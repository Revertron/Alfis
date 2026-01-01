//! The `ServerContext in this thread holds the common state across the server

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use derive_more::{Display, Error, From};

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::{DnsClient, DnsNetworkClient};
#[cfg(feature = "doh")]
use crate::dns::client::HttpsDnsClient;
use crate::dns::filter::DnsFilter;
use crate::dns::resolve::{DnsResolver, ForwardingDnsResolver, RecursiveDnsResolver};

#[derive(Debug, Display, From, Error)]
pub enum ContextError {
    Authority(crate::dns::authority::AuthorityError),
    Client(crate::dns::client::ClientError),
    Io(std::io::Error)
}

type Result<T> = std::result::Result<T, ContextError>;

pub struct ServerStatistics {
    pub tcp_query_count: AtomicUsize,
    pub udp_query_count: AtomicUsize
}

impl ServerStatistics {
    pub fn get_tcp_query_count(&self) -> usize {
        self.tcp_query_count.load(Ordering::Acquire)
    }

    pub fn get_udp_query_count(&self) -> usize {
        self.udp_query_count.load(Ordering::Acquire)
    }
}

pub enum ResolveStrategy {
    Recursive,
    Forward { upstreams: Vec<String> }
}

pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub filters: Vec<Box<dyn DnsFilter + Sync + Send>>,
    pub old_client: Box<dyn DnsClient + Sync + Send>,
    pub doh_client: Option<Box<dyn DnsClient + Sync + Send>>,
    pub dns_listen: String,
    pub api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
    pub statistics: ServerStatistics,
    pub zones_dir: &'static str,
    pub cache_max_memory_bytes: usize,
    pub cache_cleanup_interval_sec: u64,
    pub tcp_queue_size: usize,
    pub udp_queue_size: usize,
    pub max_cname_results: usize
}

impl Default for ServerContext {
    fn default() -> Self {
        ServerContext::new(String::from("0.0.0.0:53"), Vec::new(), true)
    }
}

impl ServerContext {
    #[allow(unused_variables)]
    pub fn new(dns_listen: String, bootstraps: Vec<String>, enable_0x20: bool) -> ServerContext {
        #[cfg(not(feature = "doh"))]
        let doh_client = None;
        #[cfg(feature = "doh")]
        let doh_client: Option<Box<dyn DnsClient + Sync + Send>> = Some(Box::new(HttpsDnsClient::new(bootstraps)));

        ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            filters: Vec::new(),
            old_client: Box::new(DnsNetworkClient::new_with_0x20(enable_0x20)),
            doh_client,
            dns_listen,
            api_port: 5380,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: false,
            statistics: ServerStatistics { tcp_query_count: AtomicUsize::new(0), udp_query_count: AtomicUsize::new(0) },
            zones_dir: "zones",
            cache_max_memory_bytes: 100 * 1024 * 1024, // Default: 100 MB
            cache_cleanup_interval_sec: 300, // Default: 300 seconds
            tcp_queue_size: 1000, // Default: 1000
            udp_queue_size: 5000, // Default: 5000
            max_cname_results: 50 // Default: 50
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Start UDP client thread
        self.old_client.run()?;
        // Start DoH client
        if let Some(client) = &self.doh_client {
            client.run()?;
        }

        // Load authority data
        self.authority.load()?;

        Ok(())
    }

    pub fn create_resolver(&self, ptr: Arc<ServerContext>) -> Box<dyn DnsResolver> {
        match self.resolve_strategy {
            ResolveStrategy::Recursive => Box::new(RecursiveDnsResolver::new(ptr)),
            ResolveStrategy::Forward { ref upstreams } => {
                Box::new(ForwardingDnsResolver::new(ptr, upstreams.clone()))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use super::*;
    use crate::dns::authority::Authority;
    use crate::dns::cache::SynchronizedCache;
    use crate::dns::client::tests::{DnsStubClient, StubCallback};

    pub fn create_test_context(callback: Box<StubCallback>) -> Arc<ServerContext> {
        Arc::new(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            filters: Vec::new(),
            old_client: Box::new(DnsStubClient::new(callback)),
            doh_client: Some(Box::new(HttpsDnsClient::new(Vec::new()))),
            dns_listen: String::from("0.0.0.0:53"),
            api_port: 5380,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: false,
            statistics: ServerStatistics { tcp_query_count: AtomicUsize::new(0), udp_query_count: AtomicUsize::new(0) },
            zones_dir: "zones",
            cache_max_memory_bytes: 100 * 1024 * 1024,
            cache_cleanup_interval_sec: 300,
            tcp_queue_size: 1000,
            udp_queue_size: 5000,
            max_cname_results: 50
        })
    }
}
