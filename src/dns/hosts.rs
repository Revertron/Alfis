use std::net::IpAddr;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use crate::dns::filter::DnsFilter;
use crate::dns::protocol::{DnsPacket, QueryType, DnsRecord, TransientTtl, DnsQuestion};

const NAME_SERVER: & str = "hosts";

pub struct HostsFilter {
    hosts: HashMap<String, Vec<IpAddr>>
}

impl HostsFilter {
    pub fn new(filename: &str) -> Self {
        let hosts = match File::open(filename) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                let mut map = HashMap::new();

                let list: Vec<_> = text.split("\n").collect();
                for s in list {
                    if s.is_empty() || s.starts_with("#") {
                        continue;
                    }
                    let string = s.replace('\t', " ");
                    let parts: Vec<_> = string.splitn(2, " ").collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    let ip = parts[0].trim().to_owned();
                    let domain = parts[1].trim().to_owned();
                    if let Ok(addr) = ip.parse::<IpAddr>() {
                        if !domain.is_empty() {
                            map.entry(domain).or_insert(vec!(addr));
                        }
                    }
                }

                map
            }
            Err(..) => {
                HashMap::new()
            }
        };
        HostsFilter { hosts }
    }

    pub fn size(&self) -> usize {
        self.hosts.len()
    }
}

impl DnsFilter for HostsFilter {
    fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let mut packet = DnsPacket::new();
        if let Some(list) = self.hosts.get(qname) {
            for addr in list {
                match addr {
                    IpAddr::V4(addr) if qtype == QueryType::A => {
                        packet.answers.push(DnsRecord::A { domain: qname.to_owned(), addr: addr.clone(), ttl: TransientTtl(2) });
                    }
                    IpAddr::V6(addr) if qtype == QueryType::AAAA => {
                        packet.answers.push(DnsRecord::AAAA { domain: qname.to_owned(), addr: addr.clone(), ttl: TransientTtl(2) });
                    }
                    _ => {}
                }
            }

            packet.header.authoritative_answer = true;
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            packet.authorities.push(DnsRecord::NS { domain: String::from("hosts"), host: String::from(NAME_SERVER), ttl: TransientTtl(600) });
            return Some(packet);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::hosts::HostsFilter;
    use std::env;

    #[test]
    #[ignore]
    pub fn load_hosts() {
        let filter = if cfg!(target_os = "windows") {
            if let Ok(root) = env::var("SYSTEMROOT") {
                let filename = format!("{}{}", &root, "\\System32\\drivers\\etc\\hosts");
                HostsFilter::new(&filename)
            } else {
                unreachable!()
            }
        } else {
            let filename = "/etc/hosts";
            HostsFilter::new(filename)
        };

        assert!(filter.size() > 0);
    }
}