extern crate crypto;
extern crate serde;
use crypto::ed25519::{keypair, signature, verify};
use rand::{thread_rng, Rng};
use std::fs;
use std::fmt;
use std::path::Path;
use std::io::Error as IoError;
use serde::export::fmt::Error;
use serde::{Serialize, Deserialize, Serializer, Deserializer};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    private_key: KeyPrivate,
    public_key: KeyPublic,
}

impl Signature {
    pub fn new() -> Self {
        let mut buf = [0u8; 64];
        let mut rng = thread_rng();
        rng.fill(&mut buf);
        let (private, public) = keypair(&buf);
        Signature {private_key: KeyPrivate::new(&private), public_key: KeyPublic::new(&public)}
    }

    pub fn from_bytes(seed: &[u8]) -> Self {
        let (private, public) = keypair(&seed);
        Signature {private_key: KeyPrivate::new(&private), public_key: KeyPublic::new(&public)}
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

    pub fn get_public(&self) -> KeyPublic {
        self.public_key.clone()
    }

    pub fn get_private(&self) -> KeyPrivate {
        self.private_key.clone()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        signature(message, &self.private_key.data)
    }

    pub fn check(&self, message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
        verify(message, &self.public_key.data, signature)
    }
}

/*impl fmt::Debug for Signature {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Signature")
            .field("pub", &&self.public_key[..])
            .field("priv", &&self.private_key[..])
            .finish()
    }
}*/

#[derive(Clone, Copy)]
pub struct KeyPublic {
    data: [u8; 32]
}

impl KeyPublic {
    pub fn new(data: &[u8]) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(data);
        KeyPublic{ data: buf }
    }

    pub fn length(&self) -> usize {
        self.data.len()
    }
}

impl PartialEq for KeyPublic {
    fn eq(&self, other: &Self) -> bool {
        crate::utils::same_hash(&self.data, &other.data)
    }

    fn ne(&self, other: &Self) -> bool {
        !crate::utils::same_hash(&self.data, &other.data)
    }
}

impl fmt::Debug for KeyPublic {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&crate::utils::to_hex(&self.data))
    }
}

impl Serialize for KeyPublic {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&crate::utils::to_hex(&self.data))
    }
}

#[derive(Clone, Copy)]
pub struct KeyPrivate {
    data: [u8; 64]
}

impl KeyPrivate {
    pub fn new(data: &[u8]) -> Self {
        let mut buf = [0u8; 64];
        buf.copy_from_slice(data);
        KeyPrivate{ data: buf }
    }

    pub fn length(&self) -> usize {
        self.data.len()
    }
}

impl PartialEq for KeyPrivate {
    fn eq(&self, other: &Self) -> bool {
        crate::utils::same_hash(&self.data, &other.data)
    }

    fn ne(&self, other: &Self) -> bool {
        !crate::utils::same_hash(&self.data, &other.data)
    }
}

impl fmt::Debug for KeyPrivate {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&crate::utils::to_hex(&self.data))
    }
}

impl Serialize for KeyPrivate {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&crate::utils::to_hex(&self.data))
    }
}

use serde::de::{Error as DeError, Visitor};
use serde::export::Formatter;

struct PublicVisitor;

impl<'de> Visitor<'de> for PublicVisitor {
    type Value = KeyPublic;

    fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str("32 bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: DeError, {
        if v.len() == 32 {
            let mut h = [0; 32];
            h[..32].copy_from_slice(&v[..32]);
            Ok(KeyPublic::new(&h))
        } else {
            Err(E::custom("KeyPublic must be 32 bytes!"))
        }
    }
}

impl<'dd> Deserialize<'dd> for KeyPublic {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'dd>>::Error> where
        D: Deserializer<'dd> {
        deserializer.deserialize_bytes(PublicVisitor)
    }
}

struct PrivateVisitor;

impl<'de> Visitor<'de> for PrivateVisitor {
    type Value = KeyPrivate;

    fn expecting(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str("32 bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: DeError, {
        if v.len() == 64 {
            let mut h = [0; 64];
            h[..64].copy_from_slice(&v[..64]);
            Ok(KeyPrivate::new(&h))
        } else {
            Err(E::custom("KeyPrivate must be 64 bytes!"))
        }
    }
}

impl<'dd> Deserialize<'dd> for KeyPrivate {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'dd>>::Error> where
        D: Deserializer<'dd> {
        deserializer.deserialize_bytes(PrivateVisitor)
    }
}
