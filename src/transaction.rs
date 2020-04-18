use crate::keys::*;
extern crate serde;
extern crate serde_json;

use serde::{Serialize, Deserialize, Serializer};
use serde::ser::SerializeStruct;
use std::fmt;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Action {
    ClaimName { hash: String, owner: Key },
    NewDomain { name: String, owner: Key, #[serde(default, skip_serializing_if = "Vec::is_empty")] records: Vec<String>, #[serde(default, skip_serializing_if = "Vec::is_empty")] tags: Vec<String>, days: u16 },
    ChangeDomain { name: String, records: Vec<String>, tags: Vec<String> },
    RenewDomain { name: String, days: u16 },
    MoveDomain { name: String, new_owner: Key },
    NewZone { name: String, difficulty: u16},
    ChangeZone { name: String, difficulty: u16},
}

impl Action {
    pub fn claim_name(name: String, salt: String, signature: &Keystore) -> Self {
        let hash = format!("{} {}", salt, name);
        Action::ClaimName {hash, owner: signature.get_public()}
    }

    pub fn new_domain(name: String, signature: &Keystore, records: Vec<String>, tags: Vec<String>, days: u16) -> Self {
        Action::NewDomain {name, owner: signature.get_public(), records, tags, days}
    }

    pub fn change_domain(name: String, records: Vec<String>, tags: Vec<String>) -> Self {
        Action::ChangeDomain {name, records, tags}
    }

    pub fn renew_domain(name: String, days: u16) -> Self {
        Action::RenewDomain {name, days}
    }

    pub fn move_domain(name: String, new_owner: [u8; 32]) -> Self {
        Action::MoveDomain {name, new_owner: Key::from_bytes(&new_owner)}
    }

    pub fn new_zone(name: String, difficulty: u16) -> Self {
        Action::NewZone {name, difficulty}
    }

    pub fn change_zone(name: String, difficulty: u16) -> Self {
        Action::ChangeZone {name, difficulty}
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        // Let it panic if something is not okay
        serde_json::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        // Let it panic (for now) if something is not okay
        serde_json::from_slice(bytes.as_slice()).unwrap()
    }
}

impl fmt::Debug for Action {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Action::ClaimName { hash, owner } => {
                fmt.debug_struct("ClaimName")
                    .field("hash", hash)
                    .field("owner", owner)
                    .finish()
            },
            Action::NewDomain { name, owner, records, tags, days } => {
                fmt.debug_struct("NewDomain")
                    .field("name", name)
                    .field("owner", &owner)
                    .field("records", records)
                    .field("tags", tags)
                    .field("days", days)
                    .finish()
            },
            Action::ChangeDomain { name, records, tags } => {
                fmt.debug_struct("ChangeDomain")
                    .field("name", name)
                    .field("records", records)
                    .field("tags", tags)
                    .finish()
            },
            Action::RenewDomain { name, days } => {
                fmt.debug_struct("RenewDomain")
                    .field("name", name)
                    .field("days", days)
                    .finish()
            },
            Action::MoveDomain { name, new_owner } => {
                fmt.debug_struct("MoveDomain")
                    .field("name", name)
                    .field("new_owner", new_owner)
                    .finish()
            },
            Action::NewZone { name, difficulty } => {
                fmt.debug_struct("NewZone")
                    .field("name", name)
                    .field("difficulty", difficulty)
                    .finish()
            },
            Action::ChangeZone { name, difficulty } => {
                fmt.debug_struct("ChangeZone")
                    .field("name", name)
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
        Transaction {action, pub_key, signature: Key::zero64()}
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