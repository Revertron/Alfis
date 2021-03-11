use std::collections::HashSet;

pub struct Iana {
    zones: HashSet<String>,
    hashes: HashSet<String>
}

impl Iana {
    pub fn new() -> Self {
        let zones: HashSet<_> = include_str!("../iana-tlds.txt")
            .split("\n")
            .map(String::from)
            .collect();
        let hashes: HashSet<_> = include_str!("../iana-hashes.txt")
            .split("\n")
            .map(String::from)
            .collect();
        Self { zones, hashes }
    }

    pub fn has_zone(&self, zone: &str) -> bool {
        self.zones.contains(zone)
    }

    pub fn has_hash(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }
}