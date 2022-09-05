use std::fmt;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::blockchain::hash_utils::*;
use crate::bytes::Bytes;
use crate::dns::protocol::DnsRecord;
use crate::{CLASS_DOMAIN, CLASS_ORIGIN};

extern crate serde;
extern crate serde_json;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub class: String,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub identity: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub confirmation: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub signing: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub encryption: Bytes,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String
}

impl Transaction {
    pub fn from_str(identity: String, method: String, data: String, signing: Bytes, encryption: Bytes) -> Self {
        let hash = hash_identity(&identity, None);
        let confirmation = hash_identity(&identity, Some(&signing));
        Self::new(hash, confirmation, method, data, signing, encryption)
    }

    pub fn new(identity: Bytes, confirmation: Bytes, method: String, data: String, signing: Bytes, encryption: Bytes) -> Self {
        Transaction { identity, confirmation, class: method, data, signing, encryption }
    }

    pub fn origin(hash: Bytes, signing: Bytes, encryption: Bytes) -> Self {
        let data = serde_json::to_string(&Origin { zones: hash }).unwrap();
        Transaction { identity: Bytes::default(), confirmation: Bytes::default(), class: String::from(CLASS_ORIGIN), data, signing, encryption }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        match serde_json::from_str(json) {
            Ok(transaction) => Some(transaction),
            Err(_) => None
        }
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        // Let it panic if something is not okay
        serde_json::to_string(&self).unwrap()
    }

    pub fn check_identity(&self, domain: &str) -> bool {
        let hash = hash_identity(domain, None);
        let confirmation = hash_identity(domain, Some(&self.signing));
        self.identity.eq(&hash) && self.confirmation.eq(&confirmation)
    }

    /// Returns [DomainData] from this transaction if it has it
    pub fn get_domain_data(&self) -> Option<DomainData> {
        if self.class == CLASS_DOMAIN {
            if let Ok(data) = serde_json::from_str::<DomainData>(&self.data) {
                return Some(data);
            }
        }
        None
    }

    /// Gets a type of transaction
    pub fn get_type(what: &Option<Transaction>) -> TransactionType {
        match what {
            None => TransactionType::Signing,
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
            .field("signing", &&self.signing)
            .field("encryption", &&self.encryption)
            .field("data", &self.data)
            .finish()
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
    pub encrypted: Bytes,
    pub zone: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub info: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<DnsRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<ContactsData>
}

impl DomainData {
    pub fn new(encrypted: Bytes, zone: String, info: String, records: Vec<DnsRecord>, contacts: Vec<ContactsData>) -> Self {
        Self { encrypted, zone, info, records, contacts }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DomainState {
    // Not in blockchain, free to mine
    NotFound,
    // Active, not expired domain
    Alive { renewed_time: i64, until: i64 },
    // Expired, but can be renewed only by owner
    Expired { renewed_time: i64, until: i64 },
    // Expired and can be recaptured by anyone
    Free { renewed_time: i64 }
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