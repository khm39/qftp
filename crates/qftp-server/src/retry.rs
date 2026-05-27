//! QUIC stateless retry tokens for source-address validation.
//!
//! Without this, an attacker that can spoof source IPs can force the
//! server to send up to ~3x its own Initial response per spoofed packet,
//! using the server as an amplifier. The retry handshake forces the
//! attacker to receive our Retry packet at the spoofed address before we
//! commit any further state, which they can't do.
//!
//! The token wire format we issue is:
//!
//!     "qftp1" || ip_octets || u16_be(port) || u8(dcid_len) || dcid || hmac32
//!
//! where the HMAC is SHA-256 over the rest of the token, truncated to 16
//! bytes, keyed by a process-lifetime random key. The DCID in the token
//! is the original DCID the client sent before the retry; we hand it
//! back to quiche::accept() in `odcid` so it can be incorporated into
//! the handshake transcript.

use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use hmac::{Hmac, Mac};
use ring::rand::SecureRandom;
use sha2::Sha256;

const MAGIC: &[u8; 5] = b"qftp1";
const HMAC_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Per-process secret used to sign retry tokens. A fresh secret means
/// tokens minted before a server restart become invalid, which is fine:
/// the client will just transparently retry.
pub struct RetryKey {
    key: [u8; 32],
}

impl RetryKey {
    pub fn new() -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|e| anyhow::anyhow!("system RNG failed to seed retry key: {e}"))?;
        Ok(Self { key })
    }

    /// Mint a token committing to (peer address, original DCID).
    ///
    /// Returns `None` if `odcid.len()` is outside the QUIC v1 range
    /// \[8, 20\] (RFC 9000 §7.2 mandates clients pick ≥ 8 bytes).
    /// quiche v0.24 does NOT enforce the lower bound on Initial parse,
    /// so a peer can hand us a short DCID; the caller must treat
    /// `None` as "drop this packet, do not retry, do not crash" --
    /// returning `None` here makes the validation peer-non-crashing
    /// (an earlier version asserted, giving a one-packet DoS).
    pub fn mint(&self, peer: SocketAddr, odcid: &quiche::ConnectionId) -> Option<Vec<u8>> {
        if !(8..=20).contains(&odcid.len()) {
            return None;
        }
        let mut payload = Vec::with_capacity(MAGIC.len() + 32);
        payload.extend_from_slice(MAGIC);
        match peer.ip() {
            IpAddr::V4(v4) => payload.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => payload.extend_from_slice(&v6.octets()),
        }
        payload.extend_from_slice(&peer.port().to_be_bytes());
        // The range check above guarantees odcid.len() fits in a u8;
        // `try_from` is just for the type conversion.
        let odcid_len = u8::try_from(odcid.len())
            .expect("range check above guarantees odcid.len() <= 20 <= u8::MAX");
        payload.push(odcid_len);
        payload.extend_from_slice(odcid.as_ref());

        let tag = self.sign(&payload);
        payload.extend_from_slice(&tag);
        Some(payload)
    }

    /// Validate a token. Returns the original DCID if the token is
    /// authentic for the claimed peer.
    pub fn verify<'a>(
        &self,
        peer: SocketAddr,
        token: &'a [u8],
    ) -> Option<quiche::ConnectionId<'a>> {
        if token.len() < MAGIC.len() + HMAC_LEN + 3 {
            return None;
        }
        if !token.starts_with(MAGIC) {
            return None;
        }
        let (payload, tag) = token.split_at(token.len() - HMAC_LEN);
        let expected = self.sign(payload);
        if !qftp_common::util::constant_time_eq(tag, &expected) {
            return None;
        }

        // Parse payload to verify peer match and extract odcid.
        let mut cursor = &payload[MAGIC.len()..];
        let ip_len = match peer.ip() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        if cursor.len() < ip_len + 3 {
            return None;
        }
        match peer.ip() {
            IpAddr::V4(v4) => {
                if cursor[..4] != v4.octets() {
                    return None;
                }
                cursor = &cursor[4..];
            }
            IpAddr::V6(v6) => {
                if cursor[..16] != v6.octets() {
                    return None;
                }
                cursor = &cursor[16..];
            }
        }
        let port = u16::from_be_bytes([cursor[0], cursor[1]]);
        if port != peer.port() {
            return None;
        }
        cursor = &cursor[2..];
        let dcid_len = cursor[0] as usize;
        cursor = &cursor[1..];
        if cursor.len() != dcid_len {
            return None;
        }
        // RFC 9000 §7.2: client-chosen Initial DCIDs are >= 8 bytes
        // for the connection's lifetime. Refuse a token claiming an
        // empty/short ODCID so a peer that bypassed quiche's parser
        // can't burn cap-counter / rate-limit budget by minting then
        // re-presenting a vacuous token.
        if !(8..=20).contains(&dcid_len) {
            return None;
        }
        Some(quiche::ConnectionId::from_ref(cursor))
    }

    fn sign(&self, data: &[u8]) -> [u8; HMAC_LEN] {
        // `new_from_slice` only fails when the key length is rejected
        // by the underlying HMAC; SHA-256 accepts any length, and our
        // key is a fixed 32-byte buffer, so this is provably infallible.
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC-SHA256 accepts any key length; 32-byte key is fine");
        mac.update(data);
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; HMAC_LEN];
        out.copy_from_slice(&full[..HMAC_LEN]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn round_trip_valid() {
        // RFC 9000 §7.2 mandates client-chosen Initial DCIDs are >= 8
        // bytes; mint enforces that lower bound and the test must too.
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let odcid = quiche::ConnectionId::from_ref(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let token = key.mint(peer, &odcid).expect("8-byte odcid is in range");
        let recovered = key.verify(peer, &token).expect("token should verify");
        assert_eq!(recovered.as_ref(), odcid.as_ref());
    }

    #[test]
    fn empty_odcid_token_is_rejected_on_verify() {
        // Defense-in-depth: even if a peer somehow minted a token with
        // a 0-byte ODCID (or a future change loosened the mint check),
        // verify must refuse it so cap counters can't be amplified.
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        // Hand-craft a token claiming dcid_len = 0.
        let mut payload = Vec::new();
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        payload.extend_from_slice(&4242u16.to_be_bytes());
        payload.push(0u8); // dcid_len = 0
        let tag = key.sign(&payload);
        let mut token = payload;
        token.extend_from_slice(&tag);
        assert!(
            key.verify(peer, &token).is_none(),
            "verify must reject a token with empty ODCID"
        );
    }

    #[test]
    fn short_odcid_token_is_rejected_on_verify() {
        // Token with dcid_len in [1, 7] (above empty, below RFC minimum).
        // Closes a gap between empty_odcid_token_is_rejected_on_verify
        // and the round-trip-valid happy path.
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        for short_len in 1..8u8 {
            let mut payload = Vec::new();
            payload.extend_from_slice(MAGIC);
            payload.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
            payload.extend_from_slice(&4242u16.to_be_bytes());
            payload.push(short_len);
            payload.extend(std::iter::repeat_n(0xAB, short_len as usize));
            let tag = key.sign(&payload);
            let mut token = payload;
            token.extend_from_slice(&tag);
            assert!(
                key.verify(peer, &token).is_none(),
                "verify must reject dcid_len = {short_len}"
            );
        }
    }

    #[test]
    fn mint_rejects_short_odcid() {
        // mint returns None on short DCIDs instead of panicking, so
        // a peer-controlled short DCID can't crash the server thread.
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let short = quiche::ConnectionId::from_ref(&[1, 2, 3]);
        assert!(
            key.mint(peer, &short).is_none(),
            "mint must refuse short ODCIDs without panicking"
        );
    }

    #[test]
    fn wrong_peer_is_rejected() {
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let other = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 4242));
        let odcid = quiche::ConnectionId::from_ref(&[9; 8]);
        let token = key.mint(peer, &odcid).expect("8-byte odcid is in range");
        assert!(key.verify(other, &token).is_none());
    }

    #[test]
    fn tampered_token_is_rejected() {
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let odcid = quiche::ConnectionId::from_ref(&[7; 8]);
        let mut token = key.mint(peer, &odcid).expect("8-byte odcid is in range");
        *token.last_mut().unwrap() ^= 0x01;
        assert!(key.verify(peer, &token).is_none());
    }

    #[test]
    fn random_blob_is_rejected() {
        let key = RetryKey::new().expect("test RNG should not fail");
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        assert!(key.verify(peer, &[0u8; 64]).is_none());
        assert!(key.verify(peer, &[]).is_none());
    }
}
