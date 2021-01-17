extern crate crypto;
extern crate serde;
extern crate serde_json;

use crypto::ed25519::{keypair, signature, verify};
use rand::{thread_rng, Rng};
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use serde::export::fmt::Error;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
// For deserialization
use serde::de::{Error as DeError, Visitor};
use serde::export::Formatter;
use crate::hash_is_good;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keystore {
    private_key: Bytes,
    public_key: Bytes,
    #[serde(skip)]
    seed: Vec<u8>
}

impl Keystore {
    pub fn new() -> Self {
        let mut buf = [0u8; 64];
        let mut rng = thread_rng();
        rng.fill(&mut buf);
        let (private, public) = keypair(&buf);
        Keystore {private_key: Bytes::from_bytes(&private), public_key: Bytes::from_bytes(&public), seed: Vec::from(&buf[..])}
    }

    pub fn from_bytes(seed: &[u8]) -> Self {
        let (private, public) = keypair(&seed);
        Keystore {private_key: Bytes::from_bytes(&private), public_key: Bytes::from_bytes(&public), seed: Vec::from(seed)}
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

    //TODO Implement error conditions
    pub fn save(&self, filename: &str, password: &str) {
        match File::create(Path::new(filename)) {
            Ok(mut f) => {
                //TODO implement key encryption
                f.write_all(&self.seed);
            }
            Err(_) => { println!("Error saving key file!"); }
        }
    }

    pub fn get_public(&self) -> Bytes {
        self.public_key.clone()
    }

    pub fn get_private(&self) -> Bytes {
        self.private_key.clone()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        signature(message, &self.private_key.data)
    }

    pub fn check(&self, message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
        verify(message, public_key, signature)
    }

    pub fn hash_is_good(&self, difficulty: usize) -> bool {
        hash_is_good(self.public_key.as_bytes(), difficulty)
    }
}

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
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
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
        crate::utils::same_hash(&self.data, &other.data)
    }

    fn ne(&self, other: &Self) -> bool {
        !crate::utils::same_hash(&self.data, &other.data)
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&crate::utils::to_hex(&self.data))
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&crate::utils::to_hex(&self.data))
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str("32 or 64 bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: DeError, {
        if value.len() == 64 || value.len() == 128 {
            Ok(Bytes::new(crate::from_hex(value).unwrap()))
        } else {
            Err(E::custom("Key must be 32 or 64 bytes!"))
        }
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> where E: DeError, {
        if value.len() == 32 || value.len() == 64 {
            Ok(Bytes::from_bytes(value))
        } else {
            Err(E::custom("Key must be 32 or 64 bytes!"))
        }
    }
}

impl<'dd> Deserialize<'dd> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'dd>>::Error> where D: Deserializer<'dd> {
        deserializer.deserialize_str(BytesVisitor)
    }
}
