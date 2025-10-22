use crate::dns::protocol::{DnsPacket, QueryType};

pub trait DnsFilter {
    fn lookup(&self, qname: &str, qtype: QueryType, recursive: bool) -> Option<DnsPacket>;
}

pub struct DummyFilter {}

#[allow(unused_variables)]
impl DnsFilter for DummyFilter {
    fn lookup(&self, qname: &str, qtype: QueryType, recursive: bool) -> Option<DnsPacket> {
        None
    }
}