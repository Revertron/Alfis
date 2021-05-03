use std::fmt;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeStruct;

use crate::blockchain::hash_utils::*;
use crate::bytes::Bytes;
use crate::dns::protocol::DnsRecord;
use crate::{CLASS_ORIGIN, CLASS_DOMAIN};

extern crate serde;
extern crate serde_json;

#[derive(Clone, Deserialize, PartialEq)]
pub struct Transaction {
    pub class: String,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub identity: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub confirmation: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub owner: Bytes,
    pub data: String,
}

impl Transaction {
    pub fn from_str(identity: String, method: String, data: String, miner: Bytes, owner: Bytes) -> Self {
        let hash = hash_identity(&identity, None);
        let key = if owner.is_empty() {
            &miner
        } else {
            &owner
        };
        let confirmation = hash_identity(&identity, Some(key));
        // If the miner doesn't change owner, we don't include owner at all
        let owner = if owner.is_empty() || owner == miner {
            miner
        } else {
            owner
        };
        return Self::new(hash, confirmation, method, data, owner);
    }

    pub fn new(identity: Bytes, confirmation: Bytes, method: String, data: String, owner: Bytes) -> Self {
        Transaction { identity, confirmation, class: method, data, owner }
    }

    pub fn origin(hash: Bytes, owner: Bytes) -> Self {
        let data = serde_json::to_string(&Origin { zones: hash }).unwrap();
        Transaction { identity: Bytes::default(), confirmation: Bytes::default(), class: String::from(CLASS_ORIGIN), data, owner }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        match serde_json::from_str(json) {
            Ok(transaction) => Some(transaction),
            Err(_) => None
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        // Let it panic if something is not okay
        serde_json::to_vec(&self).unwrap()
    }

    pub fn to_string(&self) -> String {
        // Let it panic if something is not okay
        serde_json::to_string(&self).unwrap()
    }

    pub fn check_identity(&self, domain: &str) -> bool {
        let hash = hash_identity(&domain, None);
        let confirmation = hash_identity(&domain, Some(&self.owner));
        self.identity.eq(&hash) && self.confirmation.eq(&confirmation)
    }

    /// Returns [DomainData] from this transaction if it has it
    pub fn get_domain_data(&self) -> Option<DomainData> {
        if self.class == CLASS_DOMAIN {
            if let Ok(data) = serde_json::from_str::<DomainData>(&self.data) {
                return Some(data)
            }
        }
        None
    }

    /// Gets a type of transaction
    pub fn get_type(what: &Option<Transaction>) -> TransactionType {
        match what {
            None => { TransactionType::Signing }
            Some(transaction) => {
                if transaction.class == CLASS_DOMAIN {
                    return TransactionType::Domain;
                }
                if transaction.class == CLASS_ORIGIN {
                    return TransactionType::Origin;
                }
                TransactionType::Unknown
            }
        }
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Transaction")
            .field("class", &self.class)
            .field("identity", &self.identity)
            .field("confirmation", &self.confirmation)
            .field("owner", &&self.owner)
            .field("data", &self.data)
            .finish()
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where S: Serializer {
        let mut structure = serializer.serialize_struct("Transaction", 5).unwrap();
        structure.serialize_field("class", &self.class)?;
        structure.serialize_field("identity", &self.identity)?;
        structure.serialize_field("confirmation", &self.confirmation)?;
        structure.serialize_field("owner", &self.owner)?;
        structure.serialize_field("data", &self.data)?;
        structure.end()
    }
}

pub enum TransactionType {
    Unknown,
    Signing,
    Domain,
    Origin,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DomainData {
    pub domain: Bytes,
    pub zone: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub info: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<DnsRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<ContactsData>,
}

impl DomainData {
    pub fn new(domain: Bytes, zone: String, info: String, records: Vec<DnsRecord>, contacts: Vec<ContactsData>) -> Self {
        Self { domain, zone, info, records, contacts }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Origin {
    zones: Bytes
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContactsData {
    pub name: String,
    pub value: String
}

impl Display for ContactsData {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&format!("{}: {}", self.name, self.value))
    }
}