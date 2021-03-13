use std::collections::HashSet;
use crate::blockchain::hash_utils::hash_identity;

pub struct ExternalZones {
    zones: HashSet<String>,
    hashes: HashSet<String>
}

impl ExternalZones {
    pub fn new() -> Self {
        let mut zones: HashSet<_> = include_str!("../iana-tlds.txt")
            .split("\n")
            .map(String::from)
            .collect();
        let mut hashes: HashSet<_> = include_str!("../iana-hashes.txt")
            .split("\n")
            .map(String::from)
            .collect();
        let open_nic: HashSet<_> = include_str!("../other-tlds.txt")
            .split("\n")
            .map(String::from)
            .collect();
        for zone in open_nic.iter() {
            if zone.is_empty() || zone.starts_with("#") {
                continue;
            }
            zones.insert(zone.to_string());
            hashes.insert(hash_identity(zone, None).to_string());
        }

        Self { zones, hashes }
    }

    pub fn has_zone(&self, zone: &str) -> bool {
        self.zones.contains(zone)
    }

    pub fn has_hash(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }
}