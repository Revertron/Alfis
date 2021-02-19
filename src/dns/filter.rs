use crate::dns::protocol::{QueryType, DnsPacket};

pub trait DnsFilter {
    fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket>;
}

pub struct DummyFilter {

}

#[allow(unused_variables)]
impl DnsFilter for DummyFilter {
    fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        None
    }
}