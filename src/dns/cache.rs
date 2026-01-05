//! a threadsafe cache for DNS information

extern crate serde;
use std::clone::Clone;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

use lru::LruCache;

use chrono::*;
use derive_more::{Display, Error, From};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};

/// Estimate the memory size of a DNS record in bytes
fn estimate_dns_record_size(record: &DnsRecord) -> usize {
    match record {
        DnsRecord::A { domain, .. } => 56 + domain.len(),
        DnsRecord::AAAA { domain, .. } => 68 + domain.len(),
        DnsRecord::NS { domain, host, .. } |
        DnsRecord::CNAME { domain, host, .. } => 64 + domain.len() + host.len(),
        DnsRecord::MX { domain, host, .. } => 72 + domain.len() + host.len(),
        DnsRecord::SRV { domain, host, .. } => 80 + domain.len() + host.len(),
        DnsRecord::SOA { domain, m_name, r_name, .. } =>
            120 + domain.len() + m_name.len() + r_name.len(),
        DnsRecord::TXT { domain, data, .. } => 64 + domain.len() + data.len(),
        DnsRecord::PTR { domain, data, .. } => 64 + domain.len() + data.len(),
        DnsRecord::TLSA { domain, data, .. } => 80 + domain.len() + data.len(),
        DnsRecord::HTTPS { domain, target, params, .. } =>
            88 + domain.len() + target.len() + params.len(),
        DnsRecord::UNKNOWN { domain, .. } => 64 + domain.len(),
        DnsRecord::OPT { data, .. } => 48 + data.len(),
    }
}

/// Estimate the memory size of a domain entry in bytes
fn estimate_domain_entry_size(entry: &DomainEntry) -> usize {
    let mut size = 0;

    // Base struct sizes
    size += std::mem::size_of::<DomainEntry>();  // ~56 bytes
    size += std::mem::size_of::<Arc<DomainEntry>>();  // 16 bytes

    // Domain string: 24 byte header + actual chars
    size += 24 + entry.domain.len();

    // HashMap base overhead
    size += 24;
    size += entry.record_types.len() * 32;  // Bucket overhead per entry

    // Calculate size of each RecordSet
    for (_qtype, record_set) in &entry.record_types {
        size += std::mem::size_of::<QueryType>();  // 2 bytes

        match record_set {
            RecordSet::NoRecords { .. } => {
                size += 56;  // Enum variant + timestamp + ttl
            }
            RecordSet::Records { records, .. } => {
                size += 56;  // Base enum variant
                size += 24;  // HashSet base
                size += records.len() * 16;  // Bucket overhead per record

                // Sum up all record sizes
                for record_entry in records {
                    size += estimate_dns_record_size(&record_entry.record);
                    size += 32;  // DateTime<Local> overhead
                }
            }
        }
    }

    size
}

#[derive(Debug, Display, From, Error)]
pub enum CacheError {
    Io(std::io::Error),
    PoisonedLock
}

type Result<T> = std::result::Result<T, CacheError>;

pub enum CacheState {
    PositiveCache,
    NegativeCache,
    NotCached
}

#[derive(Clone, Eq, Debug, Serialize, Deserialize)]
pub struct RecordEntry {
    pub record: DnsRecord,
    pub timestamp: DateTime<Local>
}

impl PartialEq<RecordEntry> for RecordEntry {
    fn eq(&self, other: &RecordEntry) -> bool {
        self.record == other.record
    }
}

impl Hash for RecordEntry {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        self.record.hash(state);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RecordSet {
    NoRecords { qtype: QueryType, ttl: u32, timestamp: DateTime<Local> },
    Records { qtype: QueryType, records: HashSet<RecordEntry> }
}

#[derive(Clone, Debug)]
pub struct DomainEntry {
    pub domain: String,
    pub record_types: HashMap<QueryType, RecordSet>,
    pub hits: u32,
    pub updates: u32
}

impl DomainEntry {
    pub fn new(domain: String) -> DomainEntry {
        DomainEntry { domain, record_types: HashMap::new(), hits: 0, updates: 0 }
    }

    pub fn store_nxdomain(&mut self, qtype: QueryType, ttl: u32) {
        self.updates += 1;

        let new_set = RecordSet::NoRecords { qtype, ttl, timestamp: Local::now() };

        self.record_types.insert(qtype, new_set);
    }

    pub fn store_record(&mut self, rec: &DnsRecord) {
        self.updates += 1;

        let entry = RecordEntry { record: rec.clone(), timestamp: Local::now() };

        if let Some(&mut RecordSet::Records { ref mut records, .. }) = self.record_types.get_mut(&rec.get_querytype()) {
            if records.contains(&entry) {
                records.remove(&entry);
            }

            records.insert(entry);
            return;
        }

        let mut records = HashSet::new();
        records.insert(entry);

        let new_set = RecordSet::Records { qtype: rec.get_querytype(), records };

        self.record_types.insert(rec.get_querytype(), new_set);
    }

    pub fn get_cache_state(&self, qtype: QueryType) -> CacheState {
        match self.record_types.get(&qtype) {
            Some(&RecordSet::Records { ref records, .. }) => {
                let now = Local::now();

                let mut valid_count = 0;
                for entry in records {
                    let ttl_offset = Duration::seconds(entry.record.get_ttl() as i64);
                    let expires = entry.timestamp + ttl_offset;
                    if expires < now {
                        continue;
                    }

                    if entry.record.get_querytype() == qtype {
                        valid_count += 1;
                    }
                }

                if valid_count > 0 {
                    CacheState::PositiveCache
                } else {
                    CacheState::NotCached
                }
            }
            Some(&RecordSet::NoRecords { ttl, timestamp, .. }) => {
                let now = Local::now();
                let ttl_offset = Duration::seconds(ttl as i64);
                let expires = timestamp + ttl_offset;

                if expires < now {
                    CacheState::NotCached
                } else {
                    CacheState::NegativeCache
                }
            }
            None => CacheState::NotCached
        }
    }

    pub fn fill_queryresult(&self, qname: &str, qtype: QueryType, result_vec: &mut Vec<DnsRecord>) {
        let now = Local::now();

        let current_set = match self.record_types.get(&qtype) {
            Some(x) => x,
            None => return
        };

        if let RecordSet::Records { ref records, .. } = *current_set {
            for entry in records {
                let ttl_offset = Duration::seconds(entry.record.get_ttl() as i64);
                let expires = entry.timestamp + ttl_offset;
                if expires < now {
                    continue;
                }

                if entry.record.get_querytype() == qtype {
                    let mut record = entry.record.clone();
                    // Preserve the original query case in the response
                    record.set_domain(qname.to_string());
                    result_vec.push(record);
                }
            }
        }
    }
}

pub struct Cache {
    domain_entries: LruCache<String, Arc<DomainEntry>>,
    current_memory_bytes: usize,
    max_memory_bytes: usize
}

impl Cache {
    pub fn new() -> Cache {
        Cache::with_memory_limit(0)
    }

    pub fn with_memory_limit(limit_mb: usize) -> Cache {
        let max_memory_bytes = if limit_mb == 0 {
            usize::MAX
        } else {
            limit_mb * 1024 * 1024
        };

        // Estimate capacity: assume ~1KB per entry
        let estimated_capacity = if limit_mb == 0 {
            100_000  // Default capacity for unlimited
        } else {
            limit_mb * 1000
        };

        Cache {
            domain_entries: LruCache::new(NonZeroUsize::new(estimated_capacity).unwrap()),
            current_memory_bytes: 0,
            max_memory_bytes,
        }
    }

    fn evict_to_limit(&mut self) -> usize {
        if self.max_memory_bytes == usize::MAX {
            return 0;  // Unlimited
        }

        let mut evicted = 0;
        let target_memory = (self.max_memory_bytes * 90) / 100;  // Evict to 90%

        while self.current_memory_bytes > target_memory {
            if let Some((_, entry)) = self.domain_entries.pop_lru() {
                let size = estimate_domain_entry_size(&entry);
                self.current_memory_bytes = self.current_memory_bytes.saturating_sub(size);
                evicted += 1;
            } else {
                break;
            }
        }

        if evicted > 0 {
            info!("Evicted {} DNS cache entries (memory: {} bytes)", evicted, self.current_memory_bytes);
        }

        evicted
    }

    fn get_cache_state(&mut self, qname: &str, qtype: QueryType) -> CacheState {
        match self.domain_entries.get(qname) {
            Some(x) => x.get_cache_state(qtype),
            None => CacheState::NotCached
        }
    }

    fn fill_queryresult(&mut self, qname: &str, qtype: QueryType, result_vec: &mut Vec<DnsRecord>, increment_stats: bool) {
        // DNS is case-insensitive, so lowercase for cache lookup
        let qname_lower = qname.to_lowercase();
        if let Some(domain_entry) = self.domain_entries.get_mut(&qname_lower).and_then(Arc::get_mut) {
            if increment_stats {
                domain_entry.hits += 1
            }

            domain_entry.fill_queryresult(qname, qtype, result_vec);
        }
    }

    pub fn lookup(&mut self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        // DNS is case-insensitive, so lowercase for cache lookup
        let qname_lower = qname.to_lowercase();
        match self.get_cache_state(&qname_lower, qtype) {
            CacheState::PositiveCache => {
                let mut qr = DnsPacket::new();
                self.fill_queryresult(qname, qtype, &mut qr.answers, true);
                self.fill_queryresult(qname, QueryType::NS, &mut qr.authorities, false);

                Some(qr)
            }
            CacheState::NegativeCache => {
                let mut qr = DnsPacket::new();
                qr.header.rescode = ResultCode::NXDOMAIN;

                Some(qr)
            }
            CacheState::NotCached => None
        }
    }

    pub fn store(&mut self, records: &[DnsRecord]) {
        for rec in records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue
            };
            // Store with a lowercase key for case-insensitive lookups
            let domain_lower = domain.to_lowercase();

            // Try to update existing entry
            if let Some(ref mut rs) = self.domain_entries.get_mut(&domain_lower).and_then(Arc::get_mut) {
                let old_size = estimate_domain_entry_size(rs);
                rs.store_record(rec);
                let new_size = estimate_domain_entry_size(rs);

                self.current_memory_bytes = self.current_memory_bytes
                    .saturating_sub(old_size)
                    .saturating_add(new_size);
                continue;
            }

            // Insert new entry
            let mut rs = DomainEntry::new(domain_lower.clone());
            rs.store_record(rec);
            let entry_size = estimate_domain_entry_size(&rs);

            // Check if eviction needed
            if self.current_memory_bytes + entry_size > self.max_memory_bytes {
                self.evict_to_limit();
            }

            self.domain_entries.put(domain_lower, Arc::new(rs));
            self.current_memory_bytes = self.current_memory_bytes.saturating_add(entry_size);
        }
    }

    pub fn store_nxdomain(&mut self, qname: &str, qtype: QueryType, ttl: u32) {
        // Store with lowercase key for case-insensitive lookups
        let qname_lower = qname.to_lowercase();

        // Try to update existing entry
        if let Some(ref mut rs) = self.domain_entries.get_mut(&qname_lower).and_then(Arc::get_mut) {
            let old_size = estimate_domain_entry_size(rs);
            rs.store_nxdomain(qtype, ttl);
            let new_size = estimate_domain_entry_size(rs);

            self.current_memory_bytes = self.current_memory_bytes
                .saturating_sub(old_size)
                .saturating_add(new_size);
            return;
        }

        // Insert new entry
        let mut rs = DomainEntry::new(qname_lower.clone());
        rs.store_nxdomain(qtype, ttl);
        let entry_size = estimate_domain_entry_size(&rs);

        // Check if eviction needed
        if self.current_memory_bytes + entry_size > self.max_memory_bytes {
            self.evict_to_limit();
        }

        self.domain_entries.put(qname_lower, Arc::new(rs));
        self.current_memory_bytes = self.current_memory_bytes.saturating_add(entry_size);
    }
}

pub struct SynchronizedCache {
    pub cache: RwLock<Cache>
}

impl SynchronizedCache {
    pub fn new() -> SynchronizedCache {
        SynchronizedCache::with_memory_limit(0)
    }

    pub fn with_memory_limit(limit_mb: usize) -> SynchronizedCache {
        SynchronizedCache {
            cache: RwLock::new(Cache::with_memory_limit(limit_mb))
        }
    }

    pub fn get_memory_usage(&self) -> Result<usize> {
        let cache = self.cache.read().map_err(|_| CacheError::PoisonedLock)?;
        Ok(cache.current_memory_bytes)
    }

    pub fn get_entry_count(&self) -> Result<usize> {
        let cache = self.cache.read().map_err(|_| CacheError::PoisonedLock)?;
        Ok(cache.domain_entries.len())
    }

    pub fn list(&self) -> Result<Vec<Arc<DomainEntry>>> {
        let cache = self.cache.read().map_err(|_| CacheError::PoisonedLock)?;

        let mut list = Vec::new();

        for (_, rs) in cache.domain_entries.iter() {
            list.push(rs.clone());
        }

        Ok(list)
    }

    pub fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return None
        };

        cache.lookup(qname, qtype)
    }

    pub fn store(&self, records: &[DnsRecord]) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| CacheError::PoisonedLock)?;

        cache.store(records);

        Ok(())
    }

    pub fn store_nxdomain(&self, qname: &str, qtype: QueryType, ttl: u32) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| CacheError::PoisonedLock)?;

        cache.store_nxdomain(qname, qtype, ttl);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dns::protocol::{DnsRecord, QueryType, ResultCode, TransientTtl};

    #[test]
    fn test_cache() {
        let mut cache = Cache::new();

        // Verify that no data is returned when nothing is present
        if cache.lookup("www.google.com", QueryType::A).is_some() {
            panic!()
        }

        // Register a negative cache entry
        cache.store_nxdomain("www.google.com", QueryType::A, 3600);

        // Verify that we get a response, with the NXDOMAIN flag set
        if let Some(packet) = cache.lookup("www.google.com", QueryType::A) {
            assert_eq!(ResultCode::NXDOMAIN, packet.header.rescode);
        }

        // Register a negative cache entry with no TTL
        cache.store_nxdomain("www.yahoo.com", QueryType::A, 0);
        std::thread::sleep(core::time::Duration::from_secs(1));

        // And check that no such result is actually returned, since it's expired
        if cache.lookup("www.yahoo.com", QueryType::A).is_some() {
            panic!()
        }

        // Now add some actual records
        let mut records = Vec::new();
        records.push(DnsRecord::A {
            domain: "www.google.com".to_string(),
            addr: "127.0.0.1".parse().unwrap(),
            ttl: TransientTtl(3600)
        });
        records.push(DnsRecord::A {
            domain: "www.yahoo.com".to_string(),
            addr: "127.0.0.2".parse().unwrap(),
            ttl: TransientTtl(0)
        });
        records.push(DnsRecord::CNAME {
            domain: "www.microsoft.com".to_string(),
            host: "www.somecdn.com".to_string(),
            ttl: TransientTtl(3600)
        });

        cache.store(&records);

        // Test for successful lookup
        if let Some(packet) = cache.lookup("www.google.com", QueryType::A) {
            assert_eq!(records[0], packet.answers[0]);
        } else {
            panic!();
        }

        // Test for failed lookup, since no CNAME's are known for this domain
        if cache.lookup("www.google.com", QueryType::CNAME).is_some() {
            panic!();
        }

        // Check for successful CNAME lookup
        if let Some(packet) = cache.lookup("www.microsoft.com", QueryType::CNAME) {
            assert_eq!(records[2], packet.answers[0]);
        } else {
            panic!();
        }

        // This lookup should fail, since it has expired due to the 0 second TTL
        if cache.lookup("www.yahoo.com", QueryType::A).is_some() {
            panic!();
        }

        let mut records2 = Vec::new();
        records2.push(DnsRecord::A {
            domain: "www.yahoo.com".to_string(),
            addr: "127.0.0.2".parse().unwrap(),
            ttl: TransientTtl(3600)
        });

        cache.store(&records2);

        // And now it should succeed, since the record has been store
        if !cache.lookup("www.yahoo.com", QueryType::A).is_some() {
            panic!();
        }

        // Check stat counter behavior
        assert_eq!(3, cache.domain_entries.len());
        assert_eq!(1, cache.domain_entries.get(&"www.google.com".to_string()).unwrap().hits);
        assert_eq!(2, cache.domain_entries.get(&"www.google.com".to_string()).unwrap().updates);
        assert_eq!(1, cache.domain_entries.get(&"www.yahoo.com".to_string()).unwrap().hits);
        assert_eq!(3, cache.domain_entries.get(&"www.yahoo.com".to_string()).unwrap().updates);
        assert_eq!(1, cache.domain_entries.get(&"www.microsoft.com".to_string()).unwrap().updates);
        assert_eq!(1, cache.domain_entries.get(&"www.microsoft.com".to_string()).unwrap().hits);
    }

    #[test]
    fn test_memory_limited_cache() {
        let mut cache = Cache::with_memory_limit(1); // 1MB limit

        // Add many records until limit is hit
        for i in 0..5000 {
            let domain = format!("test{}.com", i);
            let records = vec![DnsRecord::A {
                domain: domain.clone(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600)
            }];
            cache.store(&records);
        }

        // Verify memory stayed under limit (with some tolerance)
        let limit_bytes = 1024 * 1024;
        let tolerance_bytes = limit_bytes * 110 / 100; // 110% tolerance
        assert!(
            cache.current_memory_bytes <= tolerance_bytes,
            "Cache memory {} bytes exceeds limit with tolerance {} bytes",
            cache.current_memory_bytes, tolerance_bytes
        );

        // Verify cache still works and has been evicted
        assert!(cache.domain_entries.len() < 5000, "Cache should have evicted entries");
        assert!(cache.domain_entries.len() > 0, "Cache should not be empty");

        // Most recent entries should still be present
        assert!(cache.lookup("test4999.com", QueryType::A).is_some());
    }

    #[test]
    fn test_unlimited_cache() {
        let mut cache = Cache::with_memory_limit(0); // Unlimited

        for i in 0..1000 {
            let domain = format!("test{}.com", i);
            let records = vec![DnsRecord::A {
                domain: domain.clone(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600)
            }];
            cache.store(&records);
        }

        // All entries should be present
        assert_eq!(cache.domain_entries.len(), 1000);
        assert_eq!(cache.max_memory_bytes, usize::MAX);

        // Verify lookups work for all entries
        assert!(cache.lookup("test0.com", QueryType::A).is_some());
        assert!(cache.lookup("test500.com", QueryType::A).is_some());
        assert!(cache.lookup("test999.com", QueryType::A).is_some());
    }

    #[test]
    fn test_lru_eviction_order() {
        let mut cache = Cache::with_memory_limit(1); // Small limit to trigger eviction

        // Add initial batch of records
        for i in 0..100 {
            cache.store(&[DnsRecord::A {
                domain: format!("domain{}.com", i),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600)
            }]);
        }

        // Access domain50 to make it recently used
        let _ = cache.lookup("domain50.com", QueryType::A);

        // Add more records to trigger eviction
        for i in 100..200 {
            cache.store(&[DnsRecord::A {
                domain: format!("domain{}.com", i),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600)
            }]);
        }

        // Most recently added entries should be present
        assert!(cache.lookup("domain199.com", QueryType::A).is_some());

        // Verify cache is respecting memory limit
        let limit_bytes = 1024 * 1024;
        let tolerance_bytes = limit_bytes * 110 / 100;
        assert!(cache.current_memory_bytes <= tolerance_bytes);
    }

    #[test]
    fn test_nxdomain_memory_tracking() {
        let mut cache = Cache::with_memory_limit(1); // 1MB limit

        // Store many NXDOMAIN responses
        for i in 0..1000 {
            let domain = format!("nonexistent{}.com", i);
            cache.store_nxdomain(&domain, QueryType::A, 3600);
        }

        // Verify memory tracking works for NXDOMAIN
        assert!(cache.current_memory_bytes > 0);
        assert!(cache.current_memory_bytes <= 1024 * 1024 * 110 / 100);

        // Verify NXDOMAIN responses work
        if let Some(packet) = cache.lookup("nonexistent999.com", QueryType::A) {
            assert_eq!(ResultCode::NXDOMAIN, packet.header.rescode);
        } else {
            panic!("NXDOMAIN entry should be cached");
        }
    }
}
