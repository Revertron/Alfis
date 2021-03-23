use std::sync::{Arc, Mutex};

use crate::{Context, Settings};
use crate::blockchain::filter::BlockchainFilter;
use crate::dns::server::{DnsServer, DnsUdpServer, DnsTcpServer};
use crate::dns::context::{ServerContext, ResolveStrategy};
#[allow(unused_imports)]
use log::{debug, error, info, LevelFilter, trace, warn};

/// Starts UDP and TCP DNS-servers
pub fn start_dns_server(context: &Arc<Mutex<Context>>, settings: &Settings) {
    let server_context = create_server_context(Arc::clone(&context), &settings);

    if server_context.enable_udp {
        let udp_server = DnsUdpServer::new(Arc::clone(&server_context), settings.dns.threads);
        if let Err(e) = udp_server.run_server() {
            error!("Failed to bind UDP listener: {:?}", e);
        }
    }

    if server_context.enable_tcp {
        let tcp_server = DnsTcpServer::new(Arc::clone(&server_context), settings.dns.threads);
        if let Err(e) = tcp_server.run_server() {
            error!("Failed to bind TCP listener: {:?}", e);
        }
    }
}

/// Creates DNS-context with all needed settings
fn create_server_context(context: Arc<Mutex<Context>>, settings: &Settings) -> Arc<ServerContext> {
    let mut server_context = ServerContext::new();
    server_context.allow_recursive = true;
    server_context.dns_listen = settings.dns.listen.clone();
    server_context.resolve_strategy = match settings.dns.forwarders.is_empty() {
        true => { ResolveStrategy::Recursive }
        false => { ResolveStrategy::Forward { upstreams: settings.dns.forwarders.clone() } }
    };
    server_context.filters.push(Box::new(BlockchainFilter::new(context)));
    match server_context.initialize() {
        Ok(_) => {}
        Err(e) => { panic!("DNS server failed to initialize: {:?}", e); }
    }

    Arc::new(server_context)
}
