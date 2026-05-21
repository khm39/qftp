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
    pub fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).expect("system RNG failed");
        Self { key }
    }

    /// Mint a token committing to (peer address, original DCID).
    pub fn mint(&self, peer: SocketAddr, odcid: &quiche::ConnectionId) -> Vec<u8> {
        let mut payload = Vec::with_capacity(MAGIC.len() + 32);
        payload.extend_from_slice(MAGIC);
        match peer.ip() {
            IpAddr::V4(v4) => payload.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => payload.extend_from_slice(&v6.octets()),
        }
        payload.extend_from_slice(&peer.port().to_be_bytes());
        payload.push(odcid.len() as u8);
        payload.extend_from_slice(odcid.as_ref());

        let tag = self.sign(&payload);
        payload.extend_from_slice(&tag);
        payload
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
        Some(quiche::ConnectionId::from_ref(cursor))
    }

    fn sign(&self, data: &[u8]) -> [u8; HMAC_LEN] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac key");
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
        let key = RetryKey::new();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let odcid = quiche::ConnectionId::from_ref(&[1, 2, 3, 4, 5]);
        let token = key.mint(peer, &odcid);
        let recovered = key.verify(peer, &token).expect("token should verify");
        assert_eq!(recovered.as_ref(), odcid.as_ref());
    }

    #[test]
    fn wrong_peer_is_rejected() {
        let key = RetryKey::new();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let other = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 4242));
        let odcid = quiche::ConnectionId::from_ref(&[9; 8]);
        let token = key.mint(peer, &odcid);
        assert!(key.verify(other, &token).is_none());
    }

    #[test]
    fn tampered_token_is_rejected() {
        let key = RetryKey::new();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let odcid = quiche::ConnectionId::from_ref(&[7; 8]);
        let mut token = key.mint(peer, &odcid);
        *token.last_mut().unwrap() ^= 0x01;
        assert!(key.verify(peer, &token).is_none());
    }

    #[test]
    fn random_blob_is_rejected() {
        let key = RetryKey::new();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        assert!(key.verify(peer, &[0u8; 64]).is_none());
        assert!(key.verify(peer, &[]).is_none());
    }
}
