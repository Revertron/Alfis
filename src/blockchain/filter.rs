use crate::Context;
use std::sync::{Mutex, Arc};
use crate::dns::filter::DnsFilter;
use crate::dns::protocol::{DnsPacket, QueryType, DnsRecord, DnsQuestion};

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
        let data = self.context.lock().unwrap().blockchain.get_domain_info(qname);
        match data {
            None => { println!("Not found info for domain {}", &qname); }
            Some(data) => {
                let records: Vec<DnsRecord> = match serde_json::from_str(&data) {
                    Err(_) => { return None; }
                    Ok(records) => { records }
                };
                let mut answers: Vec<DnsRecord> = Vec::new();
                for mut record in records {
                    if record.get_querytype() == qtype {
                        match &mut record {
                            // TODO make it for all types of records
                            DnsRecord::A { domain, .. } | DnsRecord::AAAA { domain, .. } if domain == "@" => {
                                *domain = String::from(qname);
                            }
                            _ => ()
                        }

                        answers.push(record);
                    }
                }
                if !answers.is_empty() {
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    for answer in answers {
                        packet.answers.push(answer);
                    }
                    return Some(packet);
                }
            }
        }

        None
    }
}