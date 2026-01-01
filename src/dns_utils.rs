use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use crate::blockchain::filter::BlockchainFilter;
use crate::dns::context::{ResolveStrategy, ServerContext};
use crate::dns::hosts::HostsFilter;
use crate::dns::server::{DnsServer, DnsTcpServer, DnsUdpServer};
use crate::{Context, Settings};

/// Starts UDP and TCP DNS-servers
pub fn start_dns_server(context: &Arc<Mutex<Context>>, settings: &Settings) -> bool {
    let server_context = create_server_context(Arc::clone(context), settings);

    // Spawn periodic cache cleanup thread
    let cache_context = Arc::clone(&server_context);
    let cleanup_interval = server_context.cache_cleanup_interval_sec;
    let max_memory_bytes = server_context.cache_max_memory_bytes;
    info!("Starting DNS cache cleanup thread: interval={}s, max_memory={}MB", cleanup_interval, max_memory_bytes / (1024 * 1024));
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(cleanup_interval));
            info!("DNS cache cleanup: running periodic cleanup (interval: {}s)", cleanup_interval);
            
            // Cleanup expired entries
            if let Err(e) = cache_context.cache.cleanup_expired() {
                warn!("Failed to cleanup expired cache entries: {:?}", e);
            } else {
                info!("DNS cache cleanup: expired entries cleaned");
            }
            
            // Check memory and cleanup if needed
            let memory_usage = cache_context.cache.estimate_memory_usage();
            let memory_mb = memory_usage as f64 / (1024.0 * 1024.0);
            let limit_mb = max_memory_bytes as f64 / (1024.0 * 1024.0);
            info!("DNS cache cleanup: current cache memory usage: {:.2}MB, limit: {:.2}MB", memory_mb, limit_mb);
            
            // Always cleanup if we're close to limit (80% threshold for proactive cleanup)
            let cleanup_threshold = (max_memory_bytes * 80) / 100;
            if memory_usage > cleanup_threshold {
                info!("DNS cache cleanup: cache memory usage ({})MB exceeds 80% threshold ({}MB), cleaning oldest entries", memory_usage / (1024 * 1024), cleanup_threshold / (1024 * 1024));
                if let Err(e) = cache_context.cache.cleanup_oldest_by_memory(max_memory_bytes) {
                    warn!("Failed to cleanup cache by memory: {:?}", e);
                } else {
                    let memory_after = cache_context.cache.estimate_memory_usage();
                    info!("DNS cache cleanup: memory after cleanup: {}MB", memory_after / (1024 * 1024));
                }
            } else if memory_usage > max_memory_bytes {
                info!("DNS cache cleanup: memory limit exceeded ({}MB > {}MB), cleaning oldest entries", memory_usage / (1024 * 1024), max_memory_bytes / (1024 * 1024));
                if let Err(e) = cache_context.cache.cleanup_oldest_by_memory(max_memory_bytes) {
                    warn!("Failed to cleanup cache by memory: {:?}", e);
                } else {
                    let memory_after = cache_context.cache.estimate_memory_usage();
                    info!("DNS cache cleanup: memory after cleanup: {}MB", memory_after / (1024 * 1024));
                }
            }
        }
    });

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

/// Creates DNS-context with all necessary settings
fn create_server_context(context: Arc<Mutex<Context>>, settings: &Settings) -> Arc<ServerContext> {
    let mut server_context = ServerContext::new(settings.dns.listen.clone(), settings.dns.bootstraps.clone(), settings.dns.enable_0x20);
    server_context.allow_recursive = true;
    server_context.resolve_strategy = match settings.dns.forwarders.is_empty() {
        true => ResolveStrategy::Recursive,
        false => ResolveStrategy::Forward { upstreams: settings.dns.forwarders.clone() }
    };
    
    // Set cache configuration from settings
    server_context.cache_max_memory_bytes = (settings.dns.cache_max_memory_mb as usize) * 1024 * 1024;
    server_context.cache_cleanup_interval_sec = settings.dns.cache_cleanup_interval_sec;
    
    // Set queue sizes from settings
    server_context.tcp_queue_size = settings.dns.tcp_queue_size;
    server_context.udp_queue_size = settings.dns.udp_queue_size;
    
    // Set max CNAME results from settings
    server_context.max_cname_results = settings.dns.max_cname_results;
    
    // Initialize cache with memory limit
    let max_memory_bytes = server_context.cache_max_memory_bytes;
    server_context.cache = crate::dns::cache::SynchronizedCache::with_memory_limit(max_memory_bytes);
    
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
