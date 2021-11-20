use std::env;
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use crate::blockchain::filter::BlockchainFilter;
use crate::dns::context::{ResolveStrategy, ServerContext};
use crate::dns::hosts::HostsFilter;
use crate::dns::server::{DnsServer, DnsTcpServer, DnsUdpServer};
use crate::{Context, Settings};

/// Starts UDP and TCP DNS-servers
pub fn start_dns_server(context: &Arc<Mutex<Context>>, settings: &Settings) -> bool {
    let server_context = create_server_context(Arc::clone(&context), &settings);

    let mut result = true;
    if server_context.enable_udp {
        let udp_server = DnsUdpServer::new(Arc::clone(&server_context), settings.dns.threads);
        if let Err(e) = udp_server.run_server() {
            error!("Failed to bind UDP listener on {}: {:?}", &server_context.dns_listen, e);
            result = false;
        }
    }

    if server_context.enable_tcp {
        let tcp_server = DnsTcpServer::new(Arc::clone(&server_context), settings.dns.threads);
        if let Err(e) = tcp_server.run_server() {
            error!("Failed to bind TCP listener on {}: {:?}", &server_context.dns_listen, e);
            result = false;
        }
    }
    result
}

/// Creates DNS-context with all needed settings
fn create_server_context(context: Arc<Mutex<Context>>, settings: &Settings) -> Arc<ServerContext> {
    let mut server_context = ServerContext::new(settings.dns.listen.clone(), settings.dns.bootstraps.clone());
    server_context.allow_recursive = true;
    server_context.resolve_strategy = match settings.dns.forwarders.is_empty() {
        true => ResolveStrategy::Recursive,
        false => ResolveStrategy::Forward { upstreams: settings.dns.forwarders.clone() }
    };
    // Add host filters
    for host in &settings.dns.hosts {
        if host == "system" {
            if cfg!(target_os = "windows") {
                if let Ok(root) = env::var("SYSTEMROOT") {
                    let filename = format!("{}{}", &root, "\\System32\\drivers\\etc\\hosts");
                    debug!("Loading hosts from '{}'", &filename);
                    server_context.filters.push(Box::new(HostsFilter::new(&filename)));
                }
            } else {
                let filename = "/etc/hosts";
                debug!("Loading hosts from '{}'", filename);
                server_context.filters.push(Box::new(HostsFilter::new(filename)));
            }
        } else {
            debug!("Loading hosts from '{}'", &host);
            server_context.filters.push(Box::new(HostsFilter::new(host)));
        }
    }
    server_context.filters.push(Box::new(BlockchainFilter::new(context)));
    match server_context.initialize() {
        Ok(_) => {}
        Err(e) => { panic!("DNS server failed to initialize: {:?}", e); }
    }

    Arc::new(server_context)
}
