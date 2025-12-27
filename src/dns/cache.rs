//! a threadsafe cache for DNS information

extern crate serde;
use std::clone::Clone;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

use chrono::*;
use derive_more::{Display, Error, From};
use serde::{Deserialize, Serialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};

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

#[derive(Default)]
pub struct Cache {
    domain_entries: BTreeMap<String, Arc<DomainEntry>>
}

impl Cache {
    pub fn new() -> Cache {
        Cache { domain_entries: BTreeMap::new() }
    }

    /// Remove expired entries from cache to prevent memory leak
    fn cleanup_expired(&mut self) {
        // #region agent log
        let cache_size_before = self.domain_entries.len();
        let mut total_expired_records = 0;
        // #endregion
        let now = Local::now();
        let mut to_remove = Vec::new();
        
        for (domain, entry_arc) in &mut self.domain_entries {
            if let Some(entry) = Arc::get_mut(entry_arc) {
                let mut has_valid_records = false;
                let mut record_types_to_remove = Vec::new();
                
                // Check each record type and remove expired entries
                for (qtype, record_set) in &mut entry.record_types {
                    match record_set {
                        RecordSet::Records { ref mut records, .. } => {
                            let mut expired_entries = Vec::new();
                            for entry in records.iter() {
                                let ttl_offset = Duration::seconds(entry.record.get_ttl() as i64);
                                let expires = entry.timestamp + ttl_offset;
                                if expires < now {
                                    expired_entries.push(entry.clone());
                                } else {
                                    has_valid_records = true;
                                }
                            }
                            // Remove expired entries
                            let expired_count = expired_entries.len();
                            // #region agent log
                            total_expired_records += expired_count;
                            // #endregion
                            for expired in expired_entries {
                                records.remove(&expired);
                            }
                            // If all records expired, mark for removal
                            if records.is_empty() {
                                record_types_to_remove.push(*qtype);
                            }
                        }
                        RecordSet::NoRecords { ttl, timestamp, .. } => {
                            let ttl_offset = Duration::seconds(*ttl as i64);
                            let expires = *timestamp + ttl_offset;
                            if expires >= now {
                                has_valid_records = true;
                            } else {
                                record_types_to_remove.push(*qtype);
                            }
                        }
                    }
                }
                
                // Remove expired record types
                for qtype in record_types_to_remove {
                    entry.record_types.remove(&qtype);
                }
                
                // If domain has no valid records, mark for removal
                if !has_valid_records && entry.record_types.is_empty() {
                    to_remove.push(domain.clone());
                }
            }
        }
        
        // #region agent log
        let total_expired_domains = to_remove.len();
        // #endregion
        // Remove domains with no valid records
        for domain in to_remove {
            self.domain_entries.remove(&domain);
        }
        // #region agent log
        let cache_size_after = self.domain_entries.len();
        // Log cleanup results
        use std::fs::OpenOptions;
        use std::io::Write;
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/tmp/alfis-debug.log") {
            let _ = writeln!(file, r#"{{"id":"cache_cleanup","timestamp":{},"location":"dns/cache.rs:173","message":"DNS cache cleanup executed","data":{{"size_before":{},"size_after":{},"expired_records":{},"expired_domains":{}}},"sessionId":"debug-session","runId":"run1","hypothesisId":"A"}}"#, 
                chrono::Utc::now().timestamp_millis(), cache_size_before, cache_size_after, total_expired_records, total_expired_domains);
        }
        // #endregion
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
        // #region agent log
        let cache_size = self.domain_entries.len();
        // Log cache size periodically (every 10 lookups) to monitor growth
        use std::sync::atomic::{AtomicU64, Ordering};
        static LOOKUP_COUNTER: AtomicU64 = AtomicU64::new(0);
        let lookup_count = LOOKUP_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Log every 10 lookups or when cache size changes significantly
        if lookup_count % 10 == 0 || (cache_size > 0 && cache_size % 10 == 0) {
            use std::fs::OpenOptions;
            use std::io::Write;
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/tmp/alfis-debug.log") {
                let _ = writeln!(file, r#"{{"id":"dns_cache_size","timestamp":{},"location":"dns/cache.rs:256","message":"DNS cache size monitoring","data":{{"cache_size":{},"lookup_count":{},"qname":"{}"}},"sessionId":"debug-session","runId":"run1","hypothesisId":"A"}}"#, 
                    chrono::Utc::now().timestamp_millis(), cache_size, lookup_count, qname);
            }
        }
        // #endregion
        // Cleanup expired entries periodically to prevent memory leak
        // Cleanup every 1000 lookups to balance performance and memory usage
        if lookup_count > 0 && lookup_count % 1000 == 0 {
            self.cleanup_expired();
        }
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
            CacheState::NotCached => {
                // #region agent log
                if cache_size % 5000 == 0 {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/tmp/alfis-debug.log") {
                        let _ = writeln!(file, r#"{{"id":"cache_lookup","timestamp":{},"location":"dns/cache.rs:191","message":"DNS cache lookup - cache size","data":{{"cache_size":{}}},"sessionId":"debug-session","runId":"run1","hypothesisId":"A"}}"#, 
                            chrono::Utc::now().timestamp_millis(), cache_size);
                    }
                }
                // #endregion
                None
            }
        }
    }

    pub fn store(&mut self, records: &[DnsRecord]) {
        // #region agent log
        let cache_size_before = self.domain_entries.len();
        // #endregion
        for rec in records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue
            };
            // Store with a lowercase key for case-insensitive lookups
            let domain_lower = domain.to_lowercase();

            if let Some(ref mut rs) = self.domain_entries.get_mut(&domain_lower).and_then(Arc::get_mut) {
                rs.store_record(rec);
                continue;
            }

            let mut rs = DomainEntry::new(domain_lower.clone());
            rs.store_record(rec);
            self.domain_entries.insert(domain_lower, Arc::new(rs));
        }
        // #region agent log
        let cache_size_after = self.domain_entries.len();
        if cache_size_after > cache_size_before || cache_size_after % 1000 == 0 {
            use std::fs::OpenOptions;
            use std::io::Write;
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/tmp/alfis-debug.log") {
                let _ = writeln!(file, r#"{{"id":"cache_store","timestamp":{},"location":"dns/cache.rs:212","message":"DNS cache store","data":{{"size_before":{},"size_after":{},"records_count":{}}},"sessionId":"debug-session","runId":"run1","hypothesisId":"A"}}"#, 
                    chrono::Utc::now().timestamp_millis(), cache_size_before, cache_size_after, records.len());
            }
        }
        // #endregion
    }

    pub fn store_nxdomain(&mut self, qname: &str, qtype: QueryType, ttl: u32) {
        // Store with lowercase key for case-insensitive lookups
        let qname_lower = qname.to_lowercase();
        if let Some(ref mut rs) = self.domain_entries.get_mut(&qname_lower).and_then(Arc::get_mut) {
            rs.store_nxdomain(qtype, ttl);
            return;
        }

        let mut rs = DomainEntry::new(qname_lower.clone());
        rs.store_nxdomain(qtype, ttl);
        self.domain_entries.insert(qname_lower, Arc::new(rs));
    }
}

#[derive(Default)]
pub struct SynchronizedCache {
    pub cache: RwLock<Cache>
}

impl SynchronizedCache {
    pub fn new() -> SynchronizedCache {
        SynchronizedCache { cache: RwLock::new(Cache::new()) }
    }

    pub fn list(&self) -> Result<Vec<Arc<DomainEntry>>> {
        let cache = self.cache.read().map_err(|_| CacheError::PoisonedLock)?;

        let mut list = Vec::new();

        for rs in cache.domain_entries.values() {
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
}
