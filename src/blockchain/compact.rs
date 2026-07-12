//! Deterministic encoder for the block hashing/signing preimage.
//!
//! This reproduces, byte-for-byte, what `bincode::serde::encode_to_vec(_, config::legacy())`
//! produced for [`Block`](crate::blockchain::Block) and [`Transaction`](crate::blockchain::Transaction)
//! with their `serde` attributes. It replaces the (unmaintained) `bincode` dependency for the
//! one place it was used. These bytes are the consensus preimage for block hashes and
//! signatures, so the encoding MUST NOT change; `Block::compact_bytes_are_stable` pins it.
//! The bytes are never decoded — only hashed/signed — so no matching decoder is needed.
//!
//! Legacy-bincode rules reproduced here:
//! - integers: fixed-width little-endian;
//! - `String` / `str`: `u64` little-endian length prefix + raw UTF-8 bytes;
//! - `Bytes`: serialized via its `Serialize` impl, i.e. as an uppercase-hex string;
//! - `Option`: absent field (`skip_serializing_if`) emits nothing; `Some` emits a `1u8`
//!   tag followed by the value;
//! - `skip_serializing_if`: a skipped field emits nothing at all.

use crate::bytes::Bytes;
use crate::commons::to_hex;

/// Appends a bincode-legacy string: `u64` little-endian length + raw UTF-8 bytes.
pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Appends a [`Bytes`] value exactly as its `Serialize` impl does: as an uppercase-hex string.
pub(crate) fn put_bytes(out: &mut Vec<u8>, b: &Bytes) {
    put_str(out, &to_hex(b.as_slice()));
}
