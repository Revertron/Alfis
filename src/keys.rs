extern crate crypto;
extern crate serde;
use crypto::ed25519::{keypair, signature, verify};
use rand::{thread_rng, Rng};
use std::fs;
use std::fmt;
use std::path::Path;
use serde::export::fmt::Error;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
// For deserialization
use serde::de::{Error as DeError, Visitor};
use serde::export::Formatter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keystore {
    private_key: Key,
    public_key: Key,
    #[serde(skip)]
    seed: Vec<u8>
}

impl Keystore {
    pub fn new() -> Self {
        let mut buf = [0u8; 64];
        let mut rng = thread_rng();
        rng.fill(&mut buf);
        let (private, public) = keypair(&buf);
        Keystore {private_key: Key::from_bytes(&private), public_key: Key::from_bytes(&public), seed: Vec::from(&buf[..])}
    }

    pub fn from_bytes(seed: &[u8]) -> Self {
        let (private, public) = keypair(&seed);
        Keystore {private_key: Key::from_bytes(&private), public_key: Key::from_bytes(&public), seed: Vec::from(seed)}
    }

    pub fn from_file(filename: &str, _password: &str) -> Option<Self> {
        match fs::read(&Path::new(filename)) {
            Ok(key) => {
                Some(Self::from_bytes(key.as_slice()))
            },
            Err(_) => {
                None
            },
        }
    }

    pub fn get_public(&self) -> Key {
        self.public_key.clone()
    }

    pub fn get_private(&self) -> Key {
        self.private_key.clone()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        signature(message, &self.private_key.data)
    }

    pub fn check(&self, message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
        verify(message, public_key, signature)
    }
}

#[derive(Clone)]
pub struct Key {
    data: Vec<u8>
}

impl Key {
    pub fn new(data: Vec<u8>) -> Self {
        Key { data }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Key { data: Vec::from(data) }
    }

    pub fn length(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a byte slice of the hash contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn zero32() -> Self {
        Key { data: [0u8; 32].to_vec() }
    }

    pub fn zero64() -> Self {
        Key { data: [0u8; 64].to_vec() }
    }
}

impl Default for Key {
    fn default() -> Key {
        Key { data: Vec::new() }
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        crate::utils::same_hash(&self.data, &other.data)
    }

    fn ne(&self, other: &Self) -> bool {
        !crate::utils::same_hash(&self.data, &other.data)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&crate::utils::to_hex(&self.data))
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&crate::utils::to_hex(&self.data))
    }
}

struct KeyVisitor;

impl<'de> Visitor<'de> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str("32 or 64 bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: DeError, {
        if value.len() == 64 || value.len() == 128 {
            Ok(Key::new(crate::from_hex(value).unwrap()))
        } else {
            Err(E::custom("Key must be 32 or 64 bytes!"))
        }
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> where E: DeError, {
        if value.len() == 32 || value.len() == 64 {
            Ok(Key::from_bytes(value))
        } else {
            Err(E::custom("Key must be 32 or 64 bytes!"))
        }
    }
}

impl<'dd> Deserialize<'dd> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'dd>>::Error> where D: Deserializer<'dd> {
        deserializer.deserialize_str(KeyVisitor)
    }
}
