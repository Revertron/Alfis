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
        let timeout = std::time::Duration::from_secs(5);

        for server in servers {
            let addr = SocketAddr::new(server.to_owned(), 53);
            if let Ok(res) = dns_client.send_udp_query(qname, qtype, addr, false, timeout) {
                dns_client.stop();
                return Some(res);
            }
        }
        dns_client.stop();
        None
    }

    fn create_packet(&self, qname: &str, qtype: QueryType, zone: String, answers: Vec<DnsRecord>, ns_records: Vec<DnsRecord>, glue_records: Vec<DnsRecord>) -> Option<DnsPacket> {
        if !answers.is_empty() {
            // Create DnsPacket with answers
            let mut packet = DnsPacket::new();
            packet.header.authoritative_answer = true;
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            for answer in answers {
                packet.answers.push(answer);
            }
            // Add NS records to authority section
            for ns_record in ns_records {
                packet.authorities.push(ns_record);
            }
            // Add GLUE records to additional section (resources)
            for glue_record in glue_records {
                packet.resources.push(glue_record);
            }
            //trace!("Returning packet: {:?}", &packet);
            Some(packet)
        } else {
            // Create DnsPacket without answers
            let mut packet = DnsPacket::new();
            packet.header.authoritative_answer = true;
            packet.header.rescode = ResultCode::NXDOMAIN;
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            let serial = self.context.lock().unwrap().chain.get_soa_serial();
            BlockchainFilter::add_soa_record(zone, serial, &mut packet);
            //trace!("Returning packet: {:?}", &packet);
            Some(packet)
        }
    }

    fn resolve_by_ns(qname: &str, qtype: QueryType, top_domain: &String, data: &DomainData, recursive: bool) -> (bool, Option<DnsPacket>) {
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

        // If non-recursive, return a referral response with NS and GLUE records
        if !recursive {
            trace!("Non-recursive query for delegated domain {}, returning referral", qname);
            let ns_records = BlockchainFilter::get_ns_records(data, top_domain);
            let glue_records = BlockchainFilter::get_glue_records(data, top_domain, &hosts);

            let mut packet = DnsPacket::new();
            packet.header.authoritative_answer = false;  // Not authoritative for the answer, but for the zone
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            // Add NS records to authority section
            for ns_record in ns_records {
                packet.authorities.push(ns_record);
            }
            // Add GLUE records to additional section (resources)
            for glue_record in glue_records {
                packet.resources.push(glue_record);
            }
            return (true, Some(packet));
        }

        // For recursive queries, search for glue records to query external servers
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

    /// Extract NS records from domain data and return them
    fn get_ns_records(data: &DomainData, top_domain: &str) -> Vec<DnsRecord> {
        data.records.iter()
            .filter_map(|record| {
                if let DnsRecord::NS { domain, host, ttl } = record {
                    if domain == "@" {
                        return Some(DnsRecord::NS {
                            domain: String::from(top_domain),
                            host: host.clone(),
                            ttl: *ttl
                        });
                    }
                }
                None
            })
            .collect()
    }

    /// Extract GLUE records (A/AAAA records for NS hosts within the same domain)
    fn get_glue_records(data: &DomainData, top_domain: &str, ns_hosts: &[String]) -> Vec<DnsRecord> {
        let mut glue_records = Vec::new();

        for record in data.records.iter() {
            match record {
                DnsRecord::A { domain, addr, ttl } => {
                    let full_domain = if domain == "@" {
                        String::from(top_domain)
                    } else {
                        format!("{}.{}", domain, top_domain)
                    };

                    if ns_hosts.iter().any(|ns| ns == &full_domain) {
                        glue_records.push(DnsRecord::A {
                            domain: full_domain,
                            addr: addr.clone(),
                            ttl: *ttl
                        });
                    }
                }
                DnsRecord::AAAA { domain, addr, ttl } => {
                    let full_domain = if domain == "@" {
                        String::from(top_domain)
                    } else {
                        format!("{}.{}", domain, top_domain)
                    };

                    if ns_hosts.iter().any(|ns| ns == &full_domain) {
                        glue_records.push(DnsRecord::AAAA {
                            domain: full_domain,
                            addr: addr.clone(),
                            ttl: *ttl
                        });
                    }
                }
                _ => {}
            }
        }

        glue_records
    }
}

impl DnsFilter for BlockchainFilter {
    fn lookup(&self, qname: &str, qtype: QueryType, recursive: bool) -> Option<DnsPacket> {
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
                let (has_ns, result) = Self::resolve_by_ns(qname, qtype, &top_domain, &data, recursive);
                if has_ns {
                    return result;
                }

                let mut answers: Vec<DnsRecord> = Vec::new();
                let mut cname: Option<DnsRecord> = None;
                for mut record in data.records.iter_mut() {
                    if record.get_querytype() == qtype || record.get_querytype() == QueryType::CNAME {
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
                            | DnsRecord::TXT { domain, .. } if (domain == "@" && subdomain.is_empty()) || domain == &subdomain => {
                                *domain = String::from(qname);
                            }
                            _ => ()
                        }

                        match record.get_domain() {
                            None => {}
                            Some(domain) => {
                                if domain == qname || domain == subdomain {
                                    if record.get_querytype() == QueryType::CNAME {
                                        cname = Some(record.clone());
                                    } else {
                                        answers.push(record.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                if answers.is_empty() && cname.is_some() {
                    answers.push(cname.unwrap());
                }
                let mut domain_exists = !answers.is_empty() || subdomain.is_empty();
                if answers.is_empty() {
                    // If there are no records found we search for *.domain.tld record
                    for mut record in data.records.iter_mut() {
                        let record_domain = record.get_domain().unwrap_or(String::new());
                        if record.get_querytype() == qtype && record_domain == "*" {
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
                        if !domain_exists && (record_domain == subdomain || record_domain == "*") {
                            domain_exists = true;
                        }
                    }
                }

                // Extract NS records and GLUE records for the response
                let ns_records = BlockchainFilter::get_ns_records(&data, &top_domain);
                let ns_hosts: Vec<String> = ns_records.iter()
                    .filter_map(|record| {
                        if let DnsRecord::NS { host, .. } = record {
                            Some(host.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                let glue_records = BlockchainFilter::get_glue_records(&data, &top_domain, &ns_hosts);

                if let Some(mut packet) = self.create_packet(qname, qtype, zone, answers, ns_records, glue_records) {
                    if domain_exists && packet.answers.is_empty() {
                        packet.header.rescode = ResultCode::NOERROR;
                    }
                    return Some(packet);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    // TODO write tests for this filter
}
