use crate::Context;
use std::sync::{Mutex, Arc};
use crate::dns::filter::DnsFilter;
use crate::dns::protocol::{DnsPacket, QueryType, DnsRecord, DnsQuestion, ResultCode};
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};
use crate::blockchain::transaction::DomainData;

pub struct BlockchainFilter {
    context: Arc<Mutex<Context>>
}

impl BlockchainFilter {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        BlockchainFilter { context }
    }
}

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
        debug!("Searching domain {} and record {}", &search, &subdomain);

        let data = self.context.lock().unwrap().chain.get_domain_info(&search);
        match data {
            None => {
                debug!("Not found data for domain {}", &search);
                if self.context.lock().unwrap().chain.is_zone_in_blockchain(parts[0]) {
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    packet.header.rescode = ResultCode::SERVFAIL;
                    trace!("Returning packet: {:?}", &packet);
                    return Some(packet);
                }
            }
            Some(data) => {
                info!("Found data for domain {}", &search);
                let mut data: DomainData = match serde_json::from_str(&data) {
                    Err(_) => { return None; }
                    Ok(data) => { data }
                };
                let mut answers: Vec<DnsRecord> = Vec::new();
                for mut record in data.records.iter_mut() {
                    if record.get_querytype() == qtype {
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

                return if !answers.is_empty() {
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    for answer in answers {
                        packet.answers.push(answer);
                    }
                    trace!("Returning packet: {:?}", &packet);
                    Some(packet)
                } else {
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    packet.header.rescode = ResultCode::SERVFAIL;
                    trace!("Returning packet: {:?}", &packet);
                    Some(packet)
                }
            }
        }

        None
    }
}