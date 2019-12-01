use crate::utils;
use std::cmp::min;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use std::fmt;
use serde::de::{Error as DeError, Visitor};
use serde::ser::SerializeSeq;
use serde::export::Formatter;
use serde::export::fmt::Error;
use std::ops::Deref;

/// A hash consisting of all zeroes, used as a constant
pub const ZERO_HASH: Hash = Hash{ bytes: [0u8; 64]};

/// A hash struct
#[derive(Copy, Clone)]
pub struct Hash {
    bytes: [u8; 64]
}

impl Hash {
    /// Size of a hash in bytes.
    const LEN: usize = 64;

    pub fn new(bytes: [u8; 64]) -> Self {
        Hash{bytes}
    }

    /// Builds a Hash from a byte vector. If the vector is too short, it will be
    /// completed by zeroes. If it's too long, it will be truncated.
    pub fn from_vec(v: &[u8]) -> Hash {
        let mut h = [0; Hash::LEN];
        let copy_size = min(v.len(), Hash::LEN);
        h[..copy_size].copy_from_slice(&v[..copy_size]);
        Hash::new(h)
    }

    /// Converts the hash to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// Returns a byte slice of the hash contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert a hash to hex string format.
    pub fn to_hex(&self) -> String {
        utils::to_hex(self.to_vec().as_ref())
    }

    pub fn is_default(&self) -> bool {
        utils::same_hash(&self.bytes, &Hash::default().bytes)
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&crate::utils::to_hex(&self.bytes))
    }
}

struct HashVisitor;

impl<'de> Visitor<'de> for HashVisitor {
    type Value = Hash;

    fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str("64 bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: DeError, {
        if v.len() == Hash::LEN {
            let mut h = [0; Hash::LEN];
            let copy_size = min(v.len(), Hash::LEN);
            h[..copy_size].copy_from_slice(&v[..copy_size]);
            Ok(Hash::new(h))
        } else {
            Err(E::custom("Hash must be 64 bytes!"))
        }
    }
}

impl<'dd> Deserialize<'dd> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'dd>>::Error> where
        D: Deserializer<'dd> {
        deserializer.deserialize_bytes(HashVisitor)
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        utils::same_hash(&self.bytes, &other.bytes)
    }

    fn ne(&self, other: &Self) -> bool {
        !utils::same_hash(&self.bytes, &other.bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_hex = self.to_hex();
        const NUM_SHOW: usize = 8;

        write!(f, "{}", &hash_hex[..NUM_SHOW])
    }
}

impl Default for Hash {
    fn default() -> Hash {
        ZERO_HASH
    }
}