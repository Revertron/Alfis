use crate::codec::syllabic;
use crate::dns::filter::DnsFilter;
use crate::dns::protocol::{DnsPacket, DnsQuestion, DnsRecord, QueryType, ResultCode, TransientTtl};

const NAME_SERVER: &str = "ns.alfis.name";
const SERVER_ADMIN: &str = "admin.alfis.name";
/// Codec answers are deterministic and immutable, they can live in caches for long
const CODEC_TTL: u32 = 86400;
/// The zone content never changes, so the SOA serial is a constant
const CODEC_SOA_SERIAL: u32 = 1;

/// Answers queries in codec zones whose names are not registered on the blockchain
/// but deterministically encode an IP address: `.v6` (syllabic IPv6).
pub struct CodecFilter;

impl CodecFilter {
    pub fn new() -> Self {
        CodecFilter
    }

    fn add_soa_record(zone: &str, packet: &mut DnsPacket) {
        packet.authorities.push(DnsRecord::SOA {
            domain: String::from(zone),
            m_name: String::from(NAME_SERVER),
            r_name: String::from(SERVER_ADMIN),
            serial: CODEC_SOA_SERIAL,
            refresh: 3600,
            retry: 300,
            expire: 604800,
            minimum: 60,
            ttl: TransientTtl(60)
        });
    }
}

impl Default for CodecFilter {
    fn default() -> Self {
        CodecFilter::new()
    }
}

impl DnsFilter for CodecFilter {
    fn lookup(&self, qname: &str, qtype: QueryType, _recursive: bool) -> Option<DnsPacket> {
        let qname_lower = qname.to_lowercase();
        if qname_lower == "v6" {
            // Zone apex: authoritative NODATA with SOA
            let mut packet = DnsPacket::new();
            packet.header.authoritative_answer = true;
            packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
            CodecFilter::add_soa_record(&qname_lower, &mut packet);
            return Some(packet);
        }
        let parts: Vec<&str> = qname_lower.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }
        let (zone, name) = (parts[0], parts[1]);
        let decoded = match zone {
            "v6" => syllabic::decode(name),
            _ => return None
        };
        // From here on we always answer: falling through would leak the query upstream
        let mut packet = DnsPacket::new();
        packet.header.authoritative_answer = true;
        packet.questions.push(DnsQuestion::new(String::from(qname), qtype));
        match decoded {
            Ok(addr) if qtype == QueryType::AAAA => {
                packet.answers.push(DnsRecord::AAAA { domain: String::from(qname), addr, ttl: TransientTtl(CODEC_TTL) });
            }
            Ok(_) => {
                // The name is valid but only AAAA exists: NODATA
                CodecFilter::add_soa_record(zone, &mut packet);
            }
            Err(_) => {
                packet.header.rescode = ResultCode::NXDOMAIN;
                CodecFilter::add_soa_record(zone, &mut packet);
            }
        }
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use super::*;

    fn lookup(qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        CodecFilter::new().lookup(qname, qtype, true)
    }

    #[test]
    fn aaaa_query_is_answered() {
        let packet = lookup("ygpo-napu-ygg-pape.v6", QueryType::AAAA).unwrap();
        assert!(packet.header.authoritative_answer);
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        match &packet.answers[..] {
            [DnsRecord::AAAA { domain, addr, ttl }] => {
                assert_eq!(domain, "ygpo-napu-ygg-pape.v6");
                assert_eq!(*addr, Ipv6Addr::from_str("203:1904::1").unwrap());
                assert_eq!(ttl.0, CODEC_TTL);
            }
            answers => panic!("Expected one AAAA record, got {:?}", answers)
        }
    }

    #[test]
    fn case_is_preserved_in_answer() {
        let packet = lookup("YgPo-NaPu-YgG-PaPe.V6", QueryType::AAAA).unwrap();
        match &packet.answers[..] {
            [DnsRecord::AAAA { domain, addr, .. }] => {
                assert_eq!(domain, "YgPo-NaPu-YgG-PaPe.V6");
                assert_eq!(*addr, Ipv6Addr::from_str("203:1904::1").unwrap());
            }
            answers => panic!("Expected one AAAA record, got {:?}", answers)
        }
    }

    #[test]
    fn bad_name_is_nxdomain() {
        let packet = lookup("qqqq.v6", QueryType::AAAA).unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NXDOMAIN);
        assert!(packet.answers.is_empty());
        assert!(matches!(packet.authorities[..], [DnsRecord::SOA { .. }]));
        // Dots inside the name are not separators
        let packet = lookup("ygpo-napu.ygg-pape.v6", QueryType::AAAA).unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NXDOMAIN);
    }

    #[test]
    fn other_types_get_nodata() {
        let packet = lookup("ygpo-napu-ygg-pape.v6", QueryType::TXT).unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert!(packet.answers.is_empty());
        assert!(matches!(packet.authorities[..], [DnsRecord::SOA { .. }]));
    }

    #[test]
    fn apex_gets_soa() {
        let packet = lookup("v6", QueryType::AAAA).unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert!(packet.answers.is_empty());
        assert!(matches!(packet.authorities[..], [DnsRecord::SOA { .. }]));
    }

    #[test]
    fn other_zones_pass_through() {
        assert!(lookup("something.ygg", QueryType::AAAA).is_none());
        assert!(lookup("ygpo-napu-ygg-pape.anon", QueryType::AAAA).is_none());
        assert!(lookup("v6.example.com", QueryType::AAAA).is_none());
    }
}
