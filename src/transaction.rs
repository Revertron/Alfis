use crate::keys::*;

extern crate serde;
extern crate serde_json;

use serde::{Serialize, Deserialize, Serializer};
use serde::ser::SerializeStruct;
use std::fmt;
use crate::transaction::Action::Genesis;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Action {
    NewDomain { hash: String, #[serde(default, skip_serializing_if = "Key::is_zero")] owner: Key },
    FillDomain { name: String, salt: String, owner: Key, #[serde(default, skip_serializing_if = "Vec::is_empty")] records: Vec<String>, #[serde(default, skip_serializing_if = "Vec::is_empty")] tags: Vec<String>, days: u16 },
    ChangeDomain { name: String, records: Vec<String>, tags: Vec<String>, #[serde(default, skip_serializing_if = "Key::is_zero")] owner: Key },
    RenewDomain { name: String, days: u16 },
    NewZone { hash: String, #[serde(default, skip_serializing_if = "Key::is_zero")] owner: Key, difficulty: u16 },
    ChangeZone { name: String, salt: String, #[serde(default, skip_serializing_if = "Key::is_zero")] owner: Key, difficulty: u16 },
    Genesis { name: String, #[serde(default, skip_serializing_if = "Key::is_zero")] owner: Key, difficulty: u16 },
}

impl Action {
    pub fn new_domain<S: Into<String>>(name: S, salt: S, owner: Key) -> Self {
        let hash = format!("{} {}", salt.into(), name.into());
        // TODO Do not use owner for now, make a field in UI and use it if filled
        Action::NewDomain { hash: Action::get_hash(&hash), owner }
    }

    pub fn fill_domain<S: Into<String>>(name: S, salt: S, owner: Key, records: Vec<String>, tags: Vec<String>, days: u16) -> Self {
        Action::FillDomain { name: name.into(), salt: salt.into(), owner, records, tags, days }
    }

    // TODO change new_owner to Key
    pub fn change_domain<S: Into<String>>(name: S, records: Vec<String>, tags: Vec<String>, new_owner: [u8; 32]) -> Self {
        Action::ChangeDomain { name: name.into(), records, tags, owner: Key::from_bytes(&new_owner) }
    }

    pub fn renew_domain<S: Into<String>>(name: S, days: u16) -> Self {
        Action::RenewDomain { name: name.into(), days }
    }

    pub fn new_zone<S: Into<String>>(name: S, salt: S, owner: Key, difficulty: u16) -> Self {
        let hash = format!("{} {}", salt.into(), name.into());
        Action::NewZone { hash, owner, difficulty }
    }

    // TODO change new_owner to Key
    pub fn change_zone<S: Into<String>>(name: S, salt: S, new_owner: [u8; 32], difficulty: u16) -> Self {
        Action::ChangeZone { name: name.into(), salt: salt.into(), owner: Key::from_bytes(&new_owner), difficulty }
    }

    pub fn genesis<S: Into<String>>(name: S, owner: Key, difficulty: u16) -> Self {
        Genesis { name: name.into(), owner, difficulty }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        // Let it panic if something is not okay
        serde_json::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        // Let it panic (for now) if something is not okay
        serde_json::from_slice(bytes.as_slice()).unwrap()
    }

    fn get_hash(data: &str) -> String {
        let mut digest = Sha256::new();
        digest.input(data.as_bytes());
        digest.result_str()
    }
}

impl fmt::Debug for Action {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Action::NewDomain { hash, owner } => {
                fmt.debug_struct("NewDomain")
                    .field("hash", hash)
                    .field("owner", owner)
                    .finish()
            }
            Action::FillDomain { name, salt, owner, records, tags, days } => {
                fmt.debug_struct("FillDomain")
                    .field("name", name)
                    .field("salt", salt)
                    .field("owner", &owner)
                    .field("records", records)
                    .field("tags", tags)
                    .field("days", days)
                    .finish()
            }
            Action::ChangeDomain { name, records, tags, owner } => {
                fmt.debug_struct("ChangeDomain")
                    .field("name", name)
                    .field("records", records)
                    .field("tags", tags)
                    .field("owner", &owner)
                    .finish()
            }
            Action::RenewDomain { name, days } => {
                fmt.debug_struct("RenewDomain")
                    .field("name", name)
                    .field("days", days)
                    .finish()
            }
            Action::NewZone { hash, owner, difficulty } => {
                fmt.debug_struct("NewZone")
                    .field("hash", hash)
                    .field("owner", &owner)
                    .field("difficulty", difficulty)
                    .finish()
            }
            Action::ChangeZone { name, salt, owner, difficulty } => {
                fmt.debug_struct("ChangeZone")
                    .field("name", name)
                    .field("salt", salt)
                    .field("owner", &owner)
                    .field("difficulty", difficulty)
                    .finish()
            }
            Action::Genesis { name, owner, difficulty } => {
                fmt.debug_struct("Genesis")
                    .field("name", name)
                    .field("owner", &owner)
                    .field("difficulty", difficulty)
                    .finish()
            }
        }
    }
}

#[derive(Clone, Deserialize, PartialEq)]
pub struct Transaction {
    pub action: Action,
    pub pub_key: Key,
    pub signature: Key,
}

impl Transaction {
    pub fn new(action: Action, pub_key: Key) -> Self {
        Transaction { action, pub_key, signature: Key::zero64() }
    }

    pub fn set_signature(&mut self, hash: Key) {
        self.signature = hash;
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        // Let it panic if something is not okay
        serde_json::to_vec(&self).unwrap()
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Transaction")
            .field("action", &self.action)
            .field("pub", &&self.pub_key)
            .field("sign", &&self.signature)
            .finish()
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let mut structure = serializer.serialize_struct("Transaction", 3).unwrap();
        structure.serialize_field("action", &self.action);
        structure.serialize_field("pub_key", &self.pub_key);
        structure.serialize_field("signature", &self.signature);
        structure.end()
    }
}