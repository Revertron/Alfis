use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use crate::blockchain::transaction::DomainData;
use crate::dns::filter::DnsFilter;
use crate::dns::protocol::{DnsPacket, DnsQuestion, DnsRecord, QueryType, ResultCode, TransientTtl};
use crate::Context;
use crate::dns::client::{DnsClient, DnsNetworkClient};

const NAME_SERVER: &str = "ns.alfis.name";
const SERVER_ADMIN: &str = "admin.alfis.name";

pub struct BlockchainFilter {
    context: Arc<Mutex<Context>>
}

impl BlockchainFilter {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        BlockchainFilter { context }
    }

    fn add_soa_record(zone: String, serial: u32, packet: &mut DnsPacket) {
        packet.authorities.push(DnsRecord::SOA {
            domain: zone,
            m_name: String::from(NAME_SERVER),
            r_name: String::from(SERVER_ADMIN),
            serial,
            refresh: 3600,
            retry: 300,
            expire: 604800,
            minimum: 60,
            ttl: TransientTtl(60)
        });
    }

    fn get_zone_response(&self, zone: &str, serial: u32, packet: &mut DnsPacket) -> bool {
        let have_zone = self.context.lock().unwrap().chain.is_available_zone(zone);
        if have_zone {
            BlockchainFilter::add_soa_record(zone.to_owned(), serial, packet);
        }
        have_zone
    }

    fn lookup_from_ns(qname: &str, qtype: QueryType, servers: &Vec<IpAddr>) -> Option<DnsPacket> {
        let port = 10000 + (rand::random::<u16>() % 50000);
        let mut dns_client = DnsNetworkClient::new(port);
        dns_client.run().unwrap();

        for server in servers {
            let addr = SocketAddr::new(server.to_owned(), 53);
            if let Ok(res) = dns_client.send_udp_query(qname, qtype, addr, false) {
                dns_client.stop();
                return Some(res);
            }
        }
        dns_client.stop();
        None
    }

    fn create_packet(&self, qname: &str, qtype: QueryType, zone: String, answers: Vec<DnsRecord>) -> Option<DnsPacket> {
        if !answers.is_empty() {
            // Create DnsPacket
            let mut packet = DnsPacket::new();
            packet.header.authoritative_answer = true;
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            for answer in answers {
                packet.answers.push(answer);
            }
            packet.authorities.push(DnsRecord::NS { domain: zone, host: String::from(NAME_SERVER), ttl: TransientTtl(600) });
            //trace!("Returning packet: {:?}", &packet);
            Some(packet)
        } else {
            // Create DnsPacket
            let mut packet = DnsPacket::new();
            packet.header.authoritative_answer = true;
            packet.header.rescode = ResultCode::NOERROR;
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            let serial = self.context.lock().unwrap().chain.get_soa_serial();
            BlockchainFilter::add_soa_record(zone, serial, &mut packet);
            //trace!("Returning packet: {:?}", &packet);
            Some(packet)
        }
    }

    fn resolve_by_ns(qname: &str, qtype: QueryType, top_domain: &String, data: &DomainData) -> (bool, Option<DnsPacket>) {
        // First we search for NS records, collecting nameserver domains
        let mut hosts = Vec::new();
        for record in data.records.iter() {
            if record.get_querytype() == QueryType::NS {
                match &record {
                    DnsRecord::NS { domain, host, .. } if domain == "@" => {
                        hosts.push(host.to_owned());
                    }
                    _ => ()
                }
            }
        }

        if hosts.is_empty() {
            return (false, None);
        }

        // Searching glue records
        let mut servers = Vec::new();
        for record in data.records.iter() {
            match &record {
                DnsRecord::A { domain, addr, .. } => {
                    let domain = format!("{}.{}", &domain, &top_domain);
                    for host in &hosts {
                        if &domain == host {
                            servers.push(IpAddr::from(addr.clone()));
                        }
                    }
                }
                DnsRecord::AAAA { domain, addr, .. } => {
                    let domain = format!("{}.{}", &domain, &top_domain);
                    for host in &hosts {
                        if &domain == host {
                            servers.push(IpAddr::from(addr.clone()));
                        }
                    }
                }
                _ => ()
            }
        }

        if !servers.is_empty() {
            trace!("Found NS servers for domain {}: {:?}", &qname, &servers);
            let answer = BlockchainFilter::lookup_from_ns(qname, qtype, &servers);
            if let Some(packet) = &answer {
                trace!("Resolved {:?} from NS: {:?}", (qname, qtype), &packet.answers);
            }
            return (true, answer);
        }

        (false, None)
    }
}

impl DnsFilter for BlockchainFilter {
    fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let top_domain;
        let subdomain;
        let parts: Vec<&str> = qname.rsplitn(3, '.').collect();
        match parts.len() {
            1 => {
                let mut packet = DnsPacket::new();
                let serial = self.context.lock().unwrap().chain.get_soa_serial();
                if self.get_zone_response(parts[0], serial, &mut packet) {
                    return Some(packet);
                }
                return None;
            }
            2 => {
                top_domain = format!("{}.{}", parts[1], parts[0]);
                subdomain = String::new();
            }
            _ => {
                top_domain = format!("{}.{}", parts[1], parts[0]);
                subdomain = String::from(parts[2]);
            }
        }
        //trace!("Searching record type '{:?}', name '{}' for domain '{}'", &qtype, &subdomain, &search);

        let data = self.context.lock().unwrap().chain.get_domain_info(&top_domain);
        let zone = parts[0].to_owned();
        match data {
            None => {
                if self.context.lock().unwrap().chain.is_available_zone(&zone) {
                    trace!("Not found data for domain {}", &top_domain);
                    // Create DnsPacket
                    let mut packet = DnsPacket::new();
                    packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    packet.header.authoritative_answer = true;
                    let serial = self.context.lock().unwrap().chain.get_soa_serial();
                    BlockchainFilter::add_soa_record(zone, serial, &mut packet);
                    //trace!("Returning packet: {:?}", &packet);
                    return Some(packet);
                }
            }
            Some(data) => {
                trace!("Found data for domain {}", &top_domain);
                let mut data: DomainData = match serde_json::from_str(&data) {
                    Err(_) => {
                        return None;
                    }
                    Ok(data) => data
                };

                // Check if this domain has NS records and needs to resolve all records through them
                let (has_ns, result) = Self::resolve_by_ns(qname, qtype, &top_domain, &data);
                if has_ns {
                    return result;
                }

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
                            | DnsRecord::TLSA { domain, .. }
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
                                if domain == top_domain {
                                    answers.push(record.clone());
                                } else if domain == subdomain {
                                    match &mut record {
                                        DnsRecord::A { domain, .. }
                                        | DnsRecord::AAAA { domain, .. }
                                        | DnsRecord::NS { domain, .. }
                                        | DnsRecord::CNAME { domain, .. }
                                        | DnsRecord::SRV { domain, .. }
                                        | DnsRecord::TLSA { domain, .. }
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
                    // If there are no records found we search for *.domain.tld record
                    for mut record in data.records {
                        if record.get_querytype() == qtype {
                            match record.get_domain() {
                                None => {}
                                Some(domain) => {
                                    if domain == top_domain {
                                        answers.push(record.clone());
                                    } else if domain == "*" {
                                        match &mut record {
                                            DnsRecord::A { domain, .. }
                                            | DnsRecord::AAAA { domain, .. }
                                            | DnsRecord::NS { domain, .. }
                                            | DnsRecord::CNAME { domain, .. }
                                            | DnsRecord::SRV { domain, .. }
                                            | DnsRecord::TLSA { domain, .. }
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
                return self.create_packet(qname, qtype, zone, answers);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    // TODO write tests for this filter
}
