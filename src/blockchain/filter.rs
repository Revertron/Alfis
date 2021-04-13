use crate::Context;
use std::sync::{Mutex, Arc};
use crate::dns::filter::DnsFilter;
use crate::dns::protocol::{DnsPacket, QueryType, DnsRecord, DnsQuestion, ResultCode, TransientTtl};
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};
use crate::blockchain::transaction::DomainData;
use chrono::Utc;

pub struct BlockchainFilter {
    context: Arc<Mutex<Context>>
}

impl BlockchainFilter {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        BlockchainFilter { context }
    }
}

const NAME_SERVER: & str = "ns.alfis.name";
const SERVER_ADMIN: & str = "admin.alfis.name";

impl DnsFilter for BlockchainFilter {
    fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let search;
        let subdomain;
        let parts: Vec<&str> = qname.rsplitn(3, ".").collect();
        match parts.len() {
            1 => { return None; }
            2 => {
                search = format!("{}.{}", parts[1], parts[0]);
                subdomain = String::new();
            }
            _ => {
                search = format!("{}.{}", parts[1], parts[0]);
                subdomain = String::from(parts[2]);
            }
        }
        trace!("Searching record type '{:?}', name '{}' for domain '{}'", &qtype, &subdomain, &search);

        let data = self.context.lock().unwrap().chain.get_domain_info(&search);
        let zone = parts[0].to_owned();
        match data {
            None => {
                if self.context.lock().unwrap().chain.is_zone_in_blockchain(&zone) {
                    trace!("Not found data for domain {}", &search);
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    packet.header.authoritative_answer = true;
                    BlockchainFilter::add_soa_record(zone, &mut packet);
                    //trace!("Returning packet: {:?}", &packet);
                    return Some(packet);
                }
            }
            Some(data) => {
                trace!("Found data for domain {}", &search);
                let mut data: DomainData = match serde_json::from_str(&data) {
                    Err(_) => { return None; }
                    Ok(data) => { data }
                };
                let mut answers: Vec<DnsRecord> = Vec::new();
                let a_record = qtype == QueryType::A || qtype == QueryType::AAAA;
                for mut record in data.records.iter_mut() {
                    if record.get_querytype() == qtype || (a_record && record.get_querytype() == QueryType::CNAME) {
                        match &mut record {
                            DnsRecord::A { domain, .. }
                            | DnsRecord::AAAA { domain, .. }
                            | DnsRecord::NS { domain, .. }
                            | DnsRecord::CNAME { domain, .. }
                            | DnsRecord::SRV { domain, .. }
                            | DnsRecord::MX { domain, .. }
                            | DnsRecord::UNKNOWN { domain, .. }
                            | DnsRecord::SOA { domain, .. }
                            | DnsRecord::TXT { domain, .. } if domain == "@" => {
                                *domain = String::from(qname);
                            }
                            _ => ()
                        }

                        match record.get_domain() {
                            None => {}
                            Some(domain) => {
                                if domain == search {
                                    answers.push(record.clone());
                                } else if domain == subdomain {
                                    match &mut record {
                                        DnsRecord::A { domain, .. }
                                        | DnsRecord::AAAA { domain, .. }
                                        | DnsRecord::NS { domain, .. }
                                        | DnsRecord::CNAME { domain, .. }
                                        | DnsRecord::SRV { domain, .. }
                                        | DnsRecord::MX { domain, .. }
                                        | DnsRecord::UNKNOWN { domain, .. }
                                        | DnsRecord::SOA { domain, .. }
                                        | DnsRecord::TXT { domain, .. } => {
                                            *domain = String::from(qname);
                                        }
                                        _ => ()
                                    }
                                    answers.push(record.clone());
                                }
                            }
                        }
                    }
                }
                if answers.is_empty() {
                    // If there are no records found we search for *.domain.ltd record
                    for mut record in data.records {
                        if record.get_querytype() == qtype {
                            match record.get_domain() {
                                None => {}
                                Some(domain) => {
                                    if domain == search {
                                        answers.push(record.clone());
                                    } else if domain == "*" {
                                        match &mut record {
                                            DnsRecord::A { domain, .. }
                                            | DnsRecord::AAAA { domain, .. }
                                            | DnsRecord::NS { domain, .. }
                                            | DnsRecord::CNAME { domain, .. }
                                            | DnsRecord::SRV { domain, .. }
                                            | DnsRecord::MX { domain, .. }
                                            | DnsRecord::UNKNOWN { domain, .. }
                                            | DnsRecord::SOA { domain, .. }
                                            | DnsRecord::TXT { domain, .. } => {
                                                *domain = String::from(qname);
                                            }
                                            _ => ()
                                        }
                                        answers.push(record.clone());
                                    }
                                }
                            }
                        }
                    }
                }

                //debug!("Answers: {:?}", &answers);
                return if !answers.is_empty() {
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.header.authoritative_answer = true;
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    for answer in answers {
                        packet.answers.push(answer);
                    }
                    packet.authorities.push( DnsRecord::NS {
                        domain: zone,
                        host: String::from(NAME_SERVER),
                        ttl: TransientTtl(600)
                    });
                    //trace!("Returning packet: {:?}", &packet);
                    Some(packet)
                } else {
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.header.authoritative_answer = true;
                    packet.header.rescode = ResultCode::NOERROR;
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    BlockchainFilter::add_soa_record(zone, &mut packet);
                    //trace!("Returning packet: {:?}", &packet);
                    Some(packet)
                }
            }
        }

        None
    }
}

impl BlockchainFilter {
    fn add_soa_record(zone: String, packet: &mut DnsPacket) {
        packet.authorities.push(DnsRecord::SOA {
            domain: zone,
            m_name: String::from(NAME_SERVER),
            r_name: String::from(SERVER_ADMIN),
            serial: Utc::now().timestamp() as u32,
            refresh: 3600,
            retry: 300,
            expire: 604800,
            minimum: 60,
            ttl: TransientTtl(60),
        });
    }
}
