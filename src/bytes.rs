extern crate serde;
extern crate serde_json;

use std::cmp::Ordering;
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Formatter, Error};

use num_bigint::BigUint;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
// For deserialization
use serde::de::{Error as DeError, Visitor};
use std::ops::Deref;
use std::hash::{Hash, Hasher};

#[derive(Clone)]
pub struct Bytes {
    data: Vec<u8>
}

impl Bytes {
    pub fn new(data: Vec<u8>) -> Self {
        Bytes { data }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Bytes { data: Vec::from(data) }
    }

    pub fn length(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_zero(&self) -> bool {
        if self.data.is_empty() {
            return true;
        }
        for x in self.data.iter() {
            if *x != 0 {
                return false;
            }
        }
        return true;
    }

    /// Returns a byte slice of the hash contents.
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Returns a mutable byte slice (to fill by hasher)
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn to_string(&self) -> String {
        crate::commons::to_hex(&self.data)
    }

    pub fn get_tail_u64(&self) -> u64 {
        let index = self.data.len() - 8;
        let bytes: [u8; 8] = self.data[index..].try_into().unwrap();
        u64::from_be_bytes(bytes)
    }

    pub fn zero32() -> Self {
        Bytes { data: [0u8; 32].to_vec() }
    }

    pub fn zero64() -> Self {
        Bytes { data: [0u8; 64].to_vec() }
    }
}

impl Default for Bytes {
    fn default() -> Bytes {
        Bytes { data: Vec::new() }
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        crate::blockchain::hash_utils::same_hash(&self, &other)
    }

    fn ne(&self, other: &Self) -> bool {
        !crate::blockchain::hash_utils::same_hash(&self, &other)
    }
}

impl Eq for Bytes {}

impl PartialOrd for Bytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let self_hash_int = BigUint::from_bytes_le(&self);
        let other_hash_int = BigUint::from_bytes_le(&other);
        Some(self_hash_int.cmp(&other_hash_int))
    }
}

impl Ord for Bytes {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_hash_int = BigUint::from_bytes_le(&self);
        let other_hash_int = BigUint::from_bytes_le(&other);
        self_hash_int.cmp(&other_hash_int)
    }
}

impl Hash for Bytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.data);
    }
}

impl Deref for Bytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&crate::commons::to_hex(&self.data))
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&crate::commons::to_hex(&self.data))
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str("bytes in HEX format")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: DeError, {
        if !value.is_empty() && value.len() % 2 == 0 {
            Ok(Bytes::new(crate::from_hex(value).unwrap()))
        } else if value.is_empty() {
            Ok(Bytes::default())
        } else {
            Err(E::custom("Expected bytes in HEX format!"))
        }
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> where E: DeError, {
        if !value.is_empty() {
            Ok(Bytes::from_bytes(value))
        } else {
            Ok(Bytes::default())
        }
    }
}

impl<'dd> Deserialize<'dd> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'dd>>::Error> where D: Deserializer<'dd> {
        deserializer.deserialize_str(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::bytes::Bytes;
    use crate::blockchain::hash_utils::same_hash;

    #[test]
    pub fn test_tail_bytes() {
        let bytes = Bytes::new(vec![0, 255, 255, 255, 0, 255, 255, 255]);
        assert_eq!(bytes.get_tail_u64(), 72057589759737855u64);
    }

    #[test]
    pub fn test_deref() {
        let bytes = Bytes::zero32();
        assert!(same_hash(&bytes, &vec!(0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)));
    }
}
