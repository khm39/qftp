//! Chunk-oriented zstd helpers for qftp file bodies.
//!
//! The transport loops use `quiche::Connection::stream_send` /
//! `stream_recv` byte slices, not `AsyncRead` / `AsyncWrite`. These
//! wrappers keep zstd state behind a push/drain interface and expose the
//! exact compressed input boundary where a single frame completes.

use std::io;

use thiserror::Error;
use zstd::stream::raw::{CParameter, DParameter, Decoder, Encoder, InBuffer, Operation, OutBuffer};

pub const ZSTD_DEFAULT_LEVEL: i32 = 3;
pub const ZSTD_WINDOW_LOG: u32 = 23;

const CODEC_CHUNK: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("zstd codec error: {0}")]
    Codec(#[from] io::Error),
    #[error("decoded plaintext exceeded limit of {max} bytes")]
    PlaintextLimit { max: u64 },
    #[error("zstd frame is truncated")]
    Truncated,
    #[error("zstd decoder made no progress")]
    NoProgress,
}

/// Streaming zstd encoder with drainable compressed output.
pub struct ZstdEncoder {
    inner: Encoder<'static>,
    pending: Vec<u8>,
    pending_pos: usize,
    finished: bool,
}

impl ZstdEncoder {
    pub fn new() -> Result<Self, CompressionError> {
        let mut inner = Encoder::new(ZSTD_DEFAULT_LEVEL)?;
        inner.set_parameter(CParameter::WindowLog(ZSTD_WINDOW_LOG))?;
        Ok(Self {
            inner,
            pending: Vec::new(),
            pending_pos: 0,
            finished: false,
        })
    }

    pub fn push(&mut self, plaintext: &[u8]) -> Result<(), CompressionError> {
        debug_assert!(!self.finished);
        let mut input = InBuffer::around(plaintext);
        loop {
            let before = input.pos();
            let written = self.run_encoder_step(&mut input)?;
            if input.pos() == input.src.len() && written < CODEC_CHUNK {
                break;
            }
            if input.pos() == before && written == 0 {
                return Err(CompressionError::NoProgress);
            }
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), CompressionError> {
        if self.finished {
            return Ok(());
        }
        loop {
            let mut out = Vec::with_capacity(CODEC_CHUNK);
            let remaining = {
                let mut output = OutBuffer::around(&mut out);
                self.inner.finish(&mut output, true)?
            };
            self.pending.extend_from_slice(&out);
            if remaining == 0 {
                self.finished = true;
                return Ok(());
            }
            if out.is_empty() {
                return Err(CompressionError::NoProgress);
            }
        }
    }

    pub fn pending(&self) -> &[u8] {
        &self.pending[self.pending_pos..]
    }

    pub fn consume(&mut self, len: usize) {
        let end = self.pending_pos + len;
        debug_assert!(end <= self.pending.len());
        self.pending_pos = end;
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
    }

    fn run_encoder_step(&mut self, input: &mut InBuffer<'_>) -> Result<usize, CompressionError> {
        let mut out = Vec::with_capacity(CODEC_CHUNK);
        let written = {
            let mut output = OutBuffer::around(&mut out);
            self.inner.run(input, &mut output)?;
            output.pos()
        };
        self.pending.extend_from_slice(&out);
        Ok(written)
    }
}

/// Result of pushing one compressed chunk into [`ZstdDecoder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeProgress {
    /// Bytes consumed from the input slice passed to `push`.
    pub consumed: usize,
    /// True once the single zstd frame has completed. Bytes after
    /// `consumed` in that same input slice belong to the qftp trailer.
    pub frame_complete: bool,
}

/// Streaming zstd decoder with a plaintext output cap.
pub struct ZstdDecoder {
    inner: Decoder<'static>,
    pending: Vec<u8>,
    pending_pos: usize,
    decoded: u64,
    max_plaintext: u64,
    frame_complete: bool,
}

impl ZstdDecoder {
    pub fn new(max_plaintext: u64) -> Result<Self, CompressionError> {
        let mut inner = Decoder::new()?;
        inner.set_parameter(DParameter::WindowLogMax(ZSTD_WINDOW_LOG))?;
        Ok(Self {
            inner,
            pending: Vec::new(),
            pending_pos: 0,
            decoded: 0,
            max_plaintext,
            frame_complete: false,
        })
    }

    pub fn push(&mut self, compressed: &[u8]) -> Result<DecodeProgress, CompressionError> {
        if self.frame_complete {
            return Ok(DecodeProgress {
                consumed: 0,
                frame_complete: true,
            });
        }

        let mut input = InBuffer::around(compressed);
        loop {
            let before = input.pos();
            let (remaining, written, capacity) = self.run_decoder_step(&mut input)?;
            if remaining == 0 {
                self.frame_complete = true;
                break;
            }
            if input.pos() == input.src.len() && written < capacity {
                break;
            }
            if input.pos() == before && written == 0 {
                return Err(CompressionError::NoProgress);
            }
        }

        Ok(DecodeProgress {
            consumed: input.pos(),
            frame_complete: self.frame_complete,
        })
    }

    pub fn pending(&self) -> &[u8] {
        &self.pending[self.pending_pos..]
    }

    pub fn consume(&mut self, len: usize) {
        let end = self.pending_pos + len;
        debug_assert!(end <= self.pending.len());
        self.pending_pos = end;
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
    }

    pub fn decoded_len(&self) -> u64 {
        self.decoded
    }

    pub fn frame_complete(&self) -> bool {
        self.frame_complete
    }

    pub fn finish(&self) -> Result<(), CompressionError> {
        if self.frame_complete {
            Ok(())
        } else {
            Err(CompressionError::Truncated)
        }
    }

    fn run_decoder_step(
        &mut self,
        input: &mut InBuffer<'_>,
    ) -> Result<(usize, usize, usize), CompressionError> {
        let remaining_room = self.max_plaintext.saturating_sub(self.decoded);
        let capacity = if remaining_room == 0 {
            1
        } else {
            CODEC_CHUNK.min(remaining_room as usize)
        };
        let mut out = Vec::with_capacity(capacity);
        let (remaining, written) = {
            let mut output = OutBuffer::around(&mut out);
            let remaining = self.inner.run(input, &mut output)?;
            (remaining, output.pos())
        };
        if written as u64 > remaining_room {
            return Err(CompressionError::PlaintextLimit {
                max: self.max_plaintext,
            });
        }
        self.decoded += written as u64;
        self.pending.extend_from_slice(&out);
        Ok((remaining, written, capacity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compress_all(plaintext: &[u8]) -> Vec<u8> {
        let mut encoder = ZstdEncoder::new().unwrap();
        for chunk in plaintext.chunks(17_777) {
            encoder.push(chunk).unwrap();
        }
        encoder.finish().unwrap();

        let mut out = Vec::new();
        while !encoder.pending().is_empty() {
            let n = encoder.pending().len().min(8191);
            out.extend_from_slice(&encoder.pending()[..n]);
            encoder.consume(n);
        }
        out
    }

    fn drain_decoder(decoder: &mut ZstdDecoder, out: &mut Vec<u8>) {
        while !decoder.pending().is_empty() {
            let n = decoder.pending().len().min(5003);
            out.extend_from_slice(&decoder.pending()[..n]);
            decoder.consume(n);
        }
    }

    #[test]
    fn round_trip_recovers_trailer_across_awkward_splits() {
        let plaintext: Vec<u8> = (0..300_000).map(|i| b'a' + ((i / 97) % 23) as u8).collect();
        let compressed = compress_all(&plaintext);
        let trailer = [0xA5u8; 32];
        let mut wire = compressed.clone();
        wire.extend_from_slice(&trailer);

        let split_points = [
            0usize,
            1,
            3,
            64,
            compressed.len() / 2,
            compressed.len().saturating_sub(5),
            compressed.len() + 7,
            wire.len(),
        ];
        let mut decoder = ZstdDecoder::new(plaintext.len() as u64).unwrap();
        let mut decoded = Vec::new();
        let mut recovered_trailer = Vec::new();

        for pair in split_points.windows(2) {
            let chunk = &wire[pair[0]..pair[1]];
            if decoder.frame_complete() {
                recovered_trailer.extend_from_slice(chunk);
                continue;
            }
            let progress = decoder.push(chunk).unwrap();
            drain_decoder(&mut decoder, &mut decoded);
            if progress.frame_complete {
                recovered_trailer.extend_from_slice(&chunk[progress.consumed..]);
            }
        }

        decoder.finish().unwrap();
        assert_eq!(decoded, plaintext);
        assert_eq!(recovered_trailer, trailer);
    }

    #[test]
    fn empty_plaintext_round_trips_and_recovers_trailer() {
        let compressed = compress_all(&[]);
        let trailer = [0x3Cu8; 32];
        let mut wire = compressed.clone();
        wire.extend_from_slice(&trailer);

        let mut decoder = ZstdDecoder::new(0).unwrap();
        let mut decoded = Vec::new();
        let mut recovered_trailer = Vec::new();
        for chunk in wire.chunks(3) {
            if decoder.frame_complete() {
                recovered_trailer.extend_from_slice(chunk);
                continue;
            }
            let progress = decoder.push(chunk).unwrap();
            drain_decoder(&mut decoder, &mut decoded);
            if progress.frame_complete {
                recovered_trailer.extend_from_slice(&chunk[progress.consumed..]);
            }
        }

        decoder.finish().unwrap();
        assert!(decoded.is_empty());
        assert_eq!(recovered_trailer, trailer);
    }

    #[test]
    fn decompression_bomb_exceeding_plaintext_cap_is_rejected() {
        let plaintext = vec![b'x'; 4096];
        let compressed = compress_all(&plaintext);
        let mut decoder = ZstdDecoder::new(128).unwrap();
        let err = decoder.push(&compressed).unwrap_err();
        assert!(matches!(err, CompressionError::PlaintextLimit { max: 128 }));
    }

    #[test]
    fn malformed_and_truncated_frames_are_rejected() {
        let mut malformed = ZstdDecoder::new(1024).unwrap();
        assert!(matches!(
            malformed.push(b"not a zstd frame").unwrap_err(),
            CompressionError::Codec(_)
        ));

        let compressed = compress_all(b"hello world");
        let mut truncated = ZstdDecoder::new(1024).unwrap();
        let progress = truncated.push(&compressed[..compressed.len() - 1]).unwrap();
        assert!(!progress.frame_complete);
        assert!(matches!(
            truncated.finish().unwrap_err(),
            CompressionError::Truncated
        ));
    }
}
