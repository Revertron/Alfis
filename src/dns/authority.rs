//! contains the data store for local zones

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{LockResult, RwLock, RwLockReadGuard, RwLockWriteGuard};

use derive_more::{Display, From, Error};

use crate::dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};

#[derive(Debug, Display, From, Error)]
pub enum AuthorityError {
    Buffer(crate::dns::buffer::BufferError),
    Protocol(crate::dns::protocol::ProtocolError),
    Io(std::io::Error),
    PoisonedLock,
}

type Result<T> = std::result::Result<T, AuthorityError>;

#[derive(Clone, Debug, Default)]
pub struct Zone {
    pub domain: String,
    pub m_name: String,
    pub r_name: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub records: BTreeSet<DnsRecord>,
}

impl Zone {
    pub fn new(domain: String, m_name: String, r_name: String) -> Zone {
        Zone {
            domain: domain,
            m_name: m_name,
            r_name: r_name,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0,
            records: BTreeSet::new(),
        }
    }

    pub fn add_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.insert(rec.clone())
    }

    pub fn delete_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.remove(rec)
    }
}

#[derive(Default)]
pub struct Zones {
    zones: BTreeMap<String, Zone>,
}

impl<'a> Zones {
    pub fn new() -> Zones {
        Zones {
            zones: BTreeMap::new(),
        }
    }

    pub fn load(&mut self) -> Result<()> {
        let zones_dir = Path::new("zones").read_dir()?;

        for wrapped_filename in zones_dir {
            let filename = match wrapped_filename {
                Ok(x) => x,
                Err(_) => continue,
            };

            let mut zone_file = match File::open(filename.path()) {
                Ok(x) => x,
                Err(_) => continue,
            };

            let mut buffer = StreamPacketBuffer::new(&mut zone_file);

            let mut zone = Zone::new(String::new(), String::new(), String::new());
            buffer.read_qname(&mut zone.domain)?;
            buffer.read_qname(&mut zone.m_name)?;
            buffer.read_qname(&mut zone.r_name)?;
            zone.serial = buffer.read_u32()?;
            zone.refresh = buffer.read_u32()?;
            zone.retry = buffer.read_u32()?;
            zone.expire = buffer.read_u32()?;
            zone.minimum = buffer.read_u32()?;

            let record_count = buffer.read_u32()?;

            for _ in 0..record_count {
                let rr = DnsRecord::read(&mut buffer)?;
                zone.add_record(&rr);
            }

            println!("Loaded zone {} with {} records", zone.domain, record_count);

            self.zones.insert(zone.domain.clone(), zone);
        }

        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        let zones_dir = Path::new("zones");
        for zone in self.zones.values() {
            let filename = zones_dir.join(Path::new(&zone.domain));
            let mut zone_file = match File::create(&filename) {
                Ok(x) => x,
                Err(_) => {
                    println!("Failed to save file {:?}", filename);
                    continue;
                }
            };

            let mut buffer = VectorPacketBuffer::new();
            let _ = buffer.write_qname(&zone.domain);
            let _ = buffer.write_qname(&zone.m_name);
            let _ = buffer.write_qname(&zone.r_name);
            let _ = buffer.write_u32(zone.serial);
            let _ = buffer.write_u32(zone.refresh);
            let _ = buffer.write_u32(zone.retry);
            let _ = buffer.write_u32(zone.expire);
            let _ = buffer.write_u32(zone.minimum);
            let _ = buffer.write_u32(zone.records.len() as u32);

            for rec in &zone.records {
                let _ = rec.write(&mut buffer);
            }

            let _ = zone_file.write(&buffer.buffer[0..buffer.pos]);
        }

        Ok(())
    }

    pub fn zones(&self) -> Vec<&Zone> {
        self.zones.values().collect()
    }

    pub fn add_zone(&mut self, zone: Zone) {
        self.zones.insert(zone.domain.clone(), zone);
    }

    pub fn get_zone(&'a self, domain: &str) -> Option<&'a Zone> {
        self.zones.get(domain)
    }

    pub fn get_zone_mut(&'a mut self, domain: &str) -> Option<&'a mut Zone> {
        self.zones.get_mut(domain)
    }
}

#[derive(Default)]
pub struct Authority {
    zones: RwLock<Zones>,
}

impl Authority {
    pub fn new() -> Authority {
        Authority {
            zones: RwLock::new(Zones::new()),
        }
    }

    pub fn load(&self) -> Result<()> {
        let mut zones = self
            .zones
            .write()
            .map_err(|_| AuthorityError::PoisonedLock)?;
        zones.load()?;

        Ok(())
    }

    pub fn query(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let zones = match self.zones.read().ok() {
            Some(x) => x,
            None => return None,
        };

        let mut best_match = None;
        for zone in zones.zones() {
            if !qname.ends_with(&zone.domain) {
                continue;
            }

            if let Some((len, _)) = best_match {
                if len < zone.domain.len() {
                    best_match = Some((zone.domain.len(), zone));
                }
            } else {
                best_match = Some((zone.domain.len(), zone));
            }
        }

        let zone = match best_match {
            Some((_, zone)) => zone,
            None => return None,
        };

        let mut packet = DnsPacket::new();
        packet.header.authoritative_answer = true;

        for rec in &zone.records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue,
            };

            if &domain != qname {
                continue;
            }

            let rtype = rec.get_querytype();
            if qtype == rtype || (qtype == QueryType::A && rtype == QueryType::CNAME) {
                packet.answers.push(rec.clone());
            }
        }

        if packet.answers.is_empty() {
            packet.header.rescode = ResultCode::NXDOMAIN;

            packet.authorities.push(DnsRecord::SOA {
                domain: zone.domain.clone(),
                m_name: zone.m_name.clone(),
                r_name: zone.r_name.clone(),
                serial: zone.serial,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum: zone.minimum,
                ttl: TransientTtl(zone.minimum),
            });
        }

        Some(packet)
    }

    pub fn read(&self) -> LockResult<RwLockReadGuard<'_, Zones>> {
        self.zones.read()
    }

    pub fn write(&self) -> LockResult<RwLockWriteGuard<'_, Zones>> {
        self.zones.write()
    }
}
