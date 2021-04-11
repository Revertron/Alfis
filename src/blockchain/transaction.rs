use std::fmt;

use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeStruct;

use crate::blockchain::hash_utils::*;
use crate::bytes::Bytes;
use crate::dns::protocol::DnsRecord;
use std::fmt::{Display, Formatter};

extern crate serde;
extern crate serde_json;

#[derive(Clone, Deserialize, PartialEq)]
pub struct Transaction {
    pub identity: Bytes,
    pub confirmation: Bytes,
    pub class: String,
    pub data: String,
    pub pub_key: Bytes,
}

impl Transaction {
    pub fn from_str(identity: String, method: String, data: String, pub_key: Bytes) -> Self {
        let hash = hash_identity(&identity, None);
        let confirmation = hash_identity(&identity, Some(&pub_key));
        return Self::new(hash, confirmation, method, data, pub_key);
    }

    pub fn new(identity: Bytes, confirmation: Bytes, method: String, data: String, pub_key: Bytes) -> Self {
        Transaction { identity, confirmation, class: method, data, pub_key }
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
        let confirmation = hash_identity(&domain, Some(&self.pub_key));
        self.identity.eq(&hash) && self.confirmation.eq(&confirmation)
    }

    /// Returns [DomainData] from this transaction if it has it
    pub fn get_domain_data(&self) -> Option<DomainData> {
        if self.class == "domain" {
            if let Ok(data) = serde_json::from_str::<DomainData>(&self.data) {
                return Some(data)
            }
        }
        None
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Transaction")
            .field("identity", &self.identity)
            .field("confirmation", &self.confirmation)
            .field("class", &self.class)
            .field("data", &self.data)
            .field("pub_key", &&self.pub_key)
            .finish()
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where S: Serializer {
        let mut structure = serializer.serialize_struct("Transaction", 5).unwrap();
        structure.serialize_field("identity", &self.identity)?;
        structure.serialize_field("confirmation", &self.confirmation)?;
        structure.serialize_field("class", &self.class)?;
        structure.serialize_field("data", &self.data)?;
        structure.serialize_field("pub_key", &self.pub_key)?;
        structure.end()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DomainData {
    pub domain: Bytes,
    pub zone: String,
    pub records: Vec<DnsRecord>,
    pub contacts: Vec<ContactsData>,
    #[serde(default)]
    pub owners: Vec<Bytes>
}

impl DomainData {
    pub fn new(domain: Bytes, zone: String, records: Vec<DnsRecord>, contacts: Vec<ContactsData>, owners: Vec<Bytes>) -> Self {
        Self { domain, zone, records, contacts, owners }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ZoneData {
    pub name: String,
    pub difficulty: u32,
    pub yggdrasil: bool,
    #[serde(default)]
    pub owners: Vec<Bytes>
}

impl Display for ZoneData {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&format!("{} ({})", self.name, self.difficulty))
    }
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