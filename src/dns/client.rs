//! client for sending DNS queries to other servers

use std::io::Write;
#[cfg(feature = "doh")]
use std::io::Read;
use std::marker::{Send, Sync};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(feature = "doh")]
use std::net::IpAddr;
#[cfg(feature = "doh")]
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool, AtomicU16};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
#[cfg(feature = "doh")]
use std::sync::RwLock;
use std::thread::{sleep, Builder};
use std::time::Duration;

use chrono::*;
use derive_more::{Display, Error, From};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer};
#[cfg(feature = "doh")]
use crate::dns::buffer::VectorPacketBuffer;
use crate::dns::netutil::{read_packet_length, write_packet_length};
use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType};
#[cfg(feature = "doh")]
use crate::dns::protocol::DnsRecord;
#[cfg(feature = "doh")]
use lru::LruCache;
#[cfg(feature = "doh")]
use ureq::Agent;
#[cfg(feature = "doh")]
use ureq::config::Config;
#[cfg(feature = "doh")]
use ureq::http::Uri;
#[cfg(feature = "doh")]
use ureq::unversioned::resolver::{ArrayVec, ResolvedSocketAddrs, Resolver};
#[cfg(feature = "doh")]
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Display, From, Error)]
pub enum ClientError {
    Protocol(crate::dns::protocol::ProtocolError),
    Io(std::io::Error),
    PoisonedLock,
    LookupFailed,
    TimeOut
}

type Result<T> = std::result::Result<T, ClientError>;

pub trait DnsClient {
    fn get_sent_count(&self) -> usize;
    fn get_failed_count(&self) -> usize;

    fn run(&self) -> Result<()>;
    fn stop(&mut self);
    fn send_query(&self, qname: &str, qtype: QueryType, server: &str, recursive: bool) -> Result<DnsPacket>;
}

/// The UDP client
///
/// This includes a fair bit of synchronization due to the stateless nature of UDP.
/// When many queries are sent in parallel, the response packets can come back
/// in any order. For that reason, we fire off replies on the sending thread, but
/// handle replies on a single thread. A channel is created for every response,
/// and the caller will block on the channel until the a response is received.
pub struct DnsNetworkClient {
    total_sent: AtomicUsize,
    total_failed: AtomicUsize,

    /// Counter for assigning packet ids
    seq: AtomicU16,

    /// Enable DNS 0x20 encoding for additional security
    enable_0x20: bool,

    /// The requesting socket for IPv4
    socket_ipv4: UdpSocket,

    /// The requesting socket for IPv6
    socket_ipv6: UdpSocket,

    /// Queries in progress
    pending_queries: Arc<Mutex<Vec<PendingQuery>>>,

    /// Stopping handle
    stopped: Arc<AtomicBool>
}

/// A query in progress. This struct holds the `id` if the request, and a channel
/// endpoint for returning a response back to the thread from which the query
/// was posed.
struct PendingQuery {
    seq: u16,
    timestamp: DateTime<Local>,
    /// The query name with 0x20 encoding applied (for validation)
    query_name: String,
    tx: Sender<Option<DnsPacket>>
}

unsafe impl Send for DnsNetworkClient {}

unsafe impl Sync for DnsNetworkClient {}

impl DnsNetworkClient {
    pub fn new() -> DnsNetworkClient {
        Self::new_with_0x20(true)
    }

    pub fn new_with_0x20(enable_0x20: bool) -> DnsNetworkClient {
        let socket_ipv4 = UdpSocket::bind("0.0.0.0:0").expect("Error binding IPv4");
        let socket_ipv6 = UdpSocket::bind("[::]:0").expect("Error binding IPv6");

        DnsNetworkClient {
            total_sent: AtomicUsize::new(0),
            total_failed: AtomicUsize::new(0),
            seq: AtomicU16::new(rand::random::<u16>()),
            enable_0x20,
            socket_ipv4,
            socket_ipv6,
            pending_queries: Arc::new(Mutex::new(Vec::new())),
            stopped: Arc::new(AtomicBool::new(false))
        }
    }

    /// Apply DNS 0x20 encoding (random case) to domain name for additional entropy
    /// This helps prevent cache poisoning by adding ~10-15 bits of entropy per query
    fn apply_0x20_encoding(domain: &str) -> String {
        domain.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                // Randomly uppercase or lowercase each letter
                if rand::random::<bool>() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        }).collect()
    }

    /// Send a DNS query using TCP transport
    ///
    /// This is much simpler than using UDP, since the kernel will take care of
    /// packet ordering, connection state, timeouts etc.
    pub fn send_tcp_query<A: ToSocketAddrs>(&self, qname: &str, qtype: QueryType, server: A, recursive: bool) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let _ = self.seq.compare_exchange(0xFFFF, 0, Ordering::SeqCst, Ordering::SeqCst);
        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet.questions.push(DnsQuestion::new(qname.into(), qtype));

        // Send query
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 0xFFFF)?;

        let mut socket = TcpStream::connect(server)?;

        write_packet_length(&mut socket, req_buffer.pos())?;
        socket.write_all(&req_buffer.buf[0..req_buffer.pos])?;
        socket.flush()?;

        let _ = read_packet_length(&mut socket)?;

        let mut stream_buffer = StreamPacketBuffer::new(&mut socket);
        let packet = DnsPacket::from_buffer(&mut stream_buffer)?;

        Ok(packet)
    }

    /// Send a DNS query using UDP transport
    ///
    /// This will construct a query packet and fire it off to the specified server.
    /// The query is sent from the callee thread, but responses are read on a
    /// worker thread and returned to this thread through a channel. Thus, this
    /// method is thread-safe and can be used from any number of threads in
    /// parallel.
    pub fn send_udp_query<A: ToSocketAddrs>(&self, qname: &str, qtype: QueryType, server: A, recursive: bool, timeout: Duration) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Apply DNS 0x20 encoding if enabled (random case for additional entropy)
        let query_name = if self.enable_0x20 {
            Self::apply_0x20_encoding(qname)
        } else {
            qname.to_string()
        };

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let _ = self.seq.compare_exchange(0xFFFF, 0, Ordering::SeqCst, Ordering::SeqCst);
        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet.questions.push(DnsQuestion::new(query_name.clone(), qtype));

        // Create a return channel and add a `PendingQuery` to the list of lookups in progress
        let (tx, rx) = channel();
        {
            let mut pending_queries = self.pending_queries.lock().map_err(|_| ClientError::PoisonedLock)?;
            pending_queries.push(PendingQuery { seq: packet.header.id, timestamp: Local::now(), query_name, tx });
        }

        // Send a query
        let mut req_buffer = BytePacketBuffer::new();
        let len = req_buffer.buf.len();
        packet.write(&mut req_buffer, len)?;
        let addr: SocketAddr = server.to_socket_addrs()?.next().expect("Wrong resolver address");
        match addr {
            SocketAddr::V4(addr) => {
                self.socket_ipv4.send_to(&req_buffer.buf[0..req_buffer.pos], addr)?;
            }
            SocketAddr::V6(addr) => {
                self.socket_ipv6.send_to(&req_buffer.buf[0..req_buffer.pos], addr)?;
            }
        }

        // Wait for response with timeout
        match rx.recv_timeout(timeout) {
            Ok(Some(qr)) => Ok(qr),
            Ok(None) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::TimeOut)
            }
            Err(_) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::TimeOut)
            }
        }
    }
}

impl DnsClient for DnsNetworkClient {
    fn get_sent_count(&self) -> usize {
        self.total_sent.load(Ordering::Acquire)
    }

    fn get_failed_count(&self) -> usize {
        self.total_failed.load(Ordering::Acquire)
    }

    /// The run method launches a worker thread. Unless this thread is running, no
    /// responses will ever be generated, and clients will just block indefinitely.
    fn run(&self) -> Result<()> {
        // Start the thread for handling incoming responses
        {
            let socket_copy = self.socket_ipv4.try_clone()?;
            let _ = socket_copy.set_read_timeout(Some(Duration::from_millis(500)));
            let pending_queries_lock = self.pending_queries.clone();
            let stopped = Arc::clone(&self.stopped);

            let match_case = self.enable_0x20;

            Builder::new()
                .name("DnsNetworkClient-worker-thread-v4".into())
                .spawn(move || {
                    loop {
                        if stopped.load(Ordering::SeqCst) {
                            break;
                        }

                        // Read data into a buffer
                        let mut res_buffer = BytePacketBuffer::new();
                        let recv_result = socket_copy.recv_from(&mut res_buffer.buf);

                        match recv_result {
                            Ok(_) => {}
                            Err(_) => {
                                continue;
                            }
                        }

                        // Construct a DnsPacket from buffer, skipping the packet if parsing failed
                        let packet = match DnsPacket::from_buffer(&mut res_buffer) {
                            Ok(packet) => packet,
                            Err(err) => {
                                println!("DnsNetworkClient failed to parse packet with error: {:?}", err);
                                continue;
                            }
                        };

                        // Acquire a lock on the pending_queries list and search for a
                        // matching PendingQuery to which to deliver the response.
                        if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                            let mut matched_query = None;
                            for (i, pending_query) in pending_queries.iter().enumerate() {
                                if pending_query.seq == packet.header.id {
                                    // Validate 0x20 encoding - response must match query case exactly
                                    if !packet.questions.is_empty() {
                                        let response_name = &packet.questions[0].name;
                                        if (match_case && response_name != &pending_query.query_name)
                                            || (pending_query.query_name.to_lowercase() != response_name.to_lowercase()) {
                                            trace!("Rejecting response with mismatched case: expected '{}', got '{}'",
                                                pending_query.query_name, response_name);
                                            continue;
                                        }
                                    }

                                    // Matching query found with correct case, send the response
                                    let _ = pending_query.tx.send(Some(packet.clone()));

                                    // Mark this index for removal from list
                                    matched_query = Some(i);

                                    break;
                                }
                            }

                            if let Some(idx) = matched_query {
                                pending_queries.remove(idx);
                            } else {
                                trace!("Discarding unsolicited response for: {:?}", packet.questions.get(0));
                            }
                        }
                    }
                })?;
        }

        // Start the same thread for IPv6
        {
            let socket_copy = self.socket_ipv6.try_clone()?;
            let _ = socket_copy.set_read_timeout(Some(Duration::from_millis(500)));
            let pending_queries_lock = self.pending_queries.clone();
            let stopped = Arc::clone(&self.stopped);

            let match_case = self.enable_0x20;

            Builder::new()
                .name("DnsNetworkClient-worker-thread-v6".into())
                .spawn(move || {
                    loop {
                        if stopped.load(Ordering::SeqCst) {
                            break;
                        }

                        // Read data into a buffer
                        let mut res_buffer = BytePacketBuffer::new();
                        let recv_result = socket_copy.recv_from(&mut res_buffer.buf);

                        match recv_result {
                            Ok(_) => {}
                            Err(_) => {
                                continue;
                            }
                        }

                        // Construct a DnsPacket from buffer, skipping the packet if parsing failed
                        let packet = match DnsPacket::from_buffer(&mut res_buffer) {
                            Ok(packet) => packet,
                            Err(err) => {
                                println!("DnsNetworkClient failed to parse packet with error: {:?}", err);
                                continue;
                            }
                        };

                        // Acquire a lock on the pending_queries list, and search for a
                        // matching PendingQuery to which to deliver the response.
                        if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                            let mut matched_query = None;
                            for (i, pending_query) in pending_queries.iter().enumerate() {
                                if pending_query.seq == packet.header.id {
                                    // Validate 0x20 encoding - response must match query case exactly
                                    if !packet.questions.is_empty() {
                                        let response_name = &packet.questions[0].name;
                                        if (match_case && response_name != &pending_query.query_name)
                                            || (pending_query.query_name.to_lowercase() != response_name.to_lowercase()) {
                                            trace!("Rejecting response with mismatched case: expected '{}', got '{}'",
                                                pending_query.query_name, response_name);
                                            continue;
                                        }
                                    }

                                    // Matching query found with correct case, send the response
                                    let _ = pending_query.tx.send(Some(packet.clone()));

                                    // Mark this index for removal from list
                                    matched_query = Some(i);

                                    break;
                                }
                            }

                            if let Some(idx) = matched_query {
                                pending_queries.remove(idx);
                            } else {
                                trace!("Discarding unsolicited response for: {:?}", packet.questions.get(0));
                            }
                        }
                    }
                })?;
        }

        // Start the thread for timing out requests
        {
            let pending_queries_lock = self.pending_queries.clone();
            let stopped = Arc::clone(&self.stopped);

            Builder::new()
                .name("DnsNetworkClient-timeout-thread".into())
                .spawn(move || {
                    loop {
                        if stopped.load(Ordering::SeqCst) {
                            break;
                        }
                        if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                            let mut finished_queries = Vec::new();
                            for (i, pending_query) in pending_queries.iter().enumerate() {
                                let expires = pending_query.timestamp + DEFAULT_TIMEOUT;
                                if expires < Local::now() {
                                    let _ = pending_query.tx.send(None);
                                    finished_queries.push(i);
                                }
                            }

                            // Remove `PendingQuery` objects from the list, in reverse order
                            for idx in finished_queries.iter().rev() {
                                pending_queries.remove(*idx);
                            }
                        }

                        sleep(Duration::from_millis(100));
                    }
                })?;
        }

        Ok(())
    }

    fn stop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    fn send_query(&self, qname: &str, qtype: QueryType, server: &str, recursive: bool) -> Result<DnsPacket> {
        let packet = self.send_udp_query(qname, qtype, server, recursive, DEFAULT_TIMEOUT)?;
        if !packet.header.truncated_message {
            return Ok(packet);
        }

        info!("Truncated response - resending as TCP");
        self.send_tcp_query(qname, qtype, server, recursive)
    }
}

#[cfg(feature = "doh")]
pub struct HttpsDnsClient {
    agent: Agent,
    /// Counter for assigning packet ids
    seq: AtomicU16,
}

#[cfg(feature = "doh")]
impl HttpsDnsClient {
    pub fn new(bootstraps: Vec<String>) -> Self {
        let client_name = format!("ALFIS/{}", env!("CARGO_PKG_VERSION"));
        let servers = bootstraps
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect::<Vec<SocketAddr>>();
        trace!("Using bootstraps: {:?}", &servers);

        let agent_config = Agent::config_builder()
            .user_agent(&client_name)
            .timeout_global(Some(Duration::from_secs(5)))
            .max_idle_connections_per_host(8)
            .max_idle_connections(16)
            .max_idle_age(Duration::from_secs(300))
            .build();
        let agent = Agent::with_parts(agent_config, DefaultConnector::default(), BootstrapResolver::new(servers));
        Self { agent, seq: AtomicU16::new(rand::random::<u16>()) }
    }
}

#[cfg(feature = "doh")]
#[derive(Debug)]
struct BootstrapResolver {
    servers: Vec<SocketAddr>,
    cache: RwLock<LruCache<String, Vec<SocketAddr>>>
}

#[cfg(feature = "doh")]
impl BootstrapResolver {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        let cache: LruCache<String, Vec<SocketAddr>> = LruCache::new(NonZeroUsize::new(10).unwrap());
        let cache = RwLock::new(cache);
        Self { servers, cache }
    }
}

#[cfg(feature = "doh")]
impl Resolver for BootstrapResolver {
    // TODO use timeout parameter
    fn resolve(&self, uri: &Uri, _config: &Config, timeout: NextTimeout) -> std::result::Result<ResolvedSocketAddrs, ureq::Error> {
        let domain = uri.host().unwrap_or("localhost");
        let port = uri.port_u16().unwrap_or(443);
        let addr = match domain.find(':') {
            Some(index) => domain[0..index].to_string(),
            None => domain.to_string()
        };
        let timeout_duration = Duration::from_millis(timeout.after.as_millis() as u64);
        trace!("Resolving {}", addr);
        if let Some(addrs) = self.cache.write().unwrap().get(&addr) {
            trace!("Found bootstrap ip in cache");
            let mut results: ResolvedSocketAddrs = ArrayVec::from_fn(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
            for addr in addrs {
                results.push(addr.to_owned());
            }
            return Ok(results);
        }

        let mut dns_client = DnsNetworkClient::new();
        dns_client.run().unwrap();

        let mut result: Vec<IpAddr> = Vec::new();
        let mut results: ResolvedSocketAddrs = ArrayVec::from_fn(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
        for server in &self.servers {
            if let Ok(res) = dns_client.send_udp_query(&addr, QueryType::A, server, true, timeout_duration) {
                for answer in &res.answers {
                    if let DnsRecord::A { addr, .. } = answer {
                        results.push(SocketAddr::new(IpAddr::V4(*addr), port));
                        result.push(IpAddr::V4(*addr))
                    }
                }
            }
            if let Ok(res) = dns_client.send_udp_query(&addr, QueryType::AAAA, server, true, timeout_duration) {
                for answer in &res.answers {
                    if let DnsRecord::AAAA { addr, .. } = answer {
                        results.push(SocketAddr::new(IpAddr::V6(*addr), port));
                        result.push(IpAddr::V6(*addr))
                    }
                }
            }
        }
        dns_client.stop();

        result.sort();
        result.dedup();
        let addrs = result
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        trace!("Resolved addresses: {:?}", &addrs);
        self.cache.write().unwrap().put(addr, addrs.clone());
        Ok(results)
    }
}

#[cfg(feature = "doh")]
impl DnsClient for HttpsDnsClient {
    fn get_sent_count(&self) -> usize {
        // No statistics for now
        0
    }

    fn get_failed_count(&self) -> usize {
        // No statistics for now
        0
    }

    fn run(&self) -> Result<()> {
        debug!("Started DoH client");
        Ok(())
    }

    fn stop(&mut self) {
        debug!("Stopped DoH client");
    }

    fn send_query(&self, qname: &str, qtype: QueryType, doh_url: &str, recursive: bool) -> Result<DnsPacket> {
        // Create DnsPacket
        let mut packet = DnsPacket::new();
        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let _ = self.seq.compare_exchange(0xFFFF, 0, Ordering::SeqCst, Ordering::SeqCst);
        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;
        packet.questions.push(DnsQuestion::new(String::from(qname), qtype));

        let mut req_buffer = VectorPacketBuffer::new();
        packet.write(&mut req_buffer, 512 - 32).expect("Preparing DnsPacket failed!");

        let response = self.agent
            .post(doh_url)
            .header("Content-Type", "application/dns-message")
            .send(req_buffer.buffer.as_slice());

        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                match status {
                    200 => {
                        match response.headers().get("Content-Length") {
                            None => {
                                warn!("No 'Content-Length' header in DoH response for {} (status: {})", qname, status);
                                // Try to read without Content-Length
                                let mut bytes: Vec<u8> = Vec::new();
                                if let Err(e) = response.into_body().into_reader().read_to_end(&mut bytes) {
                                    warn!("Failed to read DoH response body for {}: {}", qname, e);
                                } else {
                                    debug!("Read {} bytes from DoH response for {} (no Content-Length)", bytes.len(), qname);
                                    let mut buffer = VectorPacketBuffer::new();
                                    buffer.buffer.extend_from_slice(bytes.as_slice());
                                    if let Ok(packet) = DnsPacket::from_buffer(&mut buffer) {
                                        return Ok(packet);
                                    }
                                    warn!("Error parsing DoH result for {}: invalid DNS packet format ({} bytes)", qname, bytes.len());
                                }
                            },
                            Some(str) => {
                                match str.to_str().unwrap_or("0").parse::<usize>() {
                                    Ok(size) => {
                                        if size > 65535 {
                                            warn!("DoH response for {} has suspiciously large Content-Length: {} bytes", qname, size);
                                        }
                                        let mut bytes: Vec<u8> = Vec::with_capacity(size.min(65535));
                                        let mut reader = response.into_body().into_reader();
                                        match reader.read_to_end(&mut bytes) {
                                            Ok(read_size) => {
                                                if read_size != size {
                                                    debug!("DoH response for {}: Content-Length={}, but read {} bytes", qname, size, read_size);
                                                }
                                                let mut buffer = VectorPacketBuffer::new();
                                                buffer.buffer.extend_from_slice(bytes.as_slice());
                                                match DnsPacket::from_buffer(&mut buffer) {
                                                    Ok(packet) => return Ok(packet),
                                                    Err(e) => {
                                                        warn!("Error parsing DoH result for {}: {} (response size: {} bytes)", qname, e, read_size);
                                                    }
                                                }
                                            },
                                            Err(e) => {
                                                warn!("Failed to read DoH response body for {}: {} (expected {} bytes)", qname, e, size);
                                            }
                                        }
                                    }
                                    Err(e) => warn!("Error parsing 'Content-Length' in DoH response for {}: {}", qname, e)
                                }
                            }
                        }
                    }
                    _ => warn!("DoH request for {} failed with status code: {}", qname, status)
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("timeout") {
                    debug!("DoH timeout for {}: {}", qname, error_msg);
                } else {
                    warn!("DoH error for {}: {}", qname, error_msg);
                }
            }
        }
        warn!("Lookup of {} failed", qname);
        Err(ClientError::LookupFailed)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType};

    pub type StubCallback = dyn Fn(&str, QueryType, &str, bool) -> Result<DnsPacket>;

    pub struct DnsStubClient {
        callback: Box<StubCallback>
    }

    impl<'a> DnsStubClient {
        pub fn new(callback: Box<StubCallback>) -> DnsStubClient {
            DnsStubClient { callback }
        }
    }

    unsafe impl Send for DnsStubClient {}

    unsafe impl Sync for DnsStubClient {}

    impl DnsClient for DnsStubClient {
        fn get_sent_count(&self) -> usize {
            0
        }

        fn get_failed_count(&self) -> usize {
            0
        }

        fn run(&self) -> Result<()> {
            Ok(())
        }

        fn stop(&mut self) {
            // Nothing
        }

        fn send_query(&self, qname: &str, qtype: QueryType, server: &str, recursive: bool) -> Result<DnsPacket> {
            (self.callback)(qname, qtype, server, recursive)
        }
    }

    #[test]
    pub fn test_udp_client() {
        // Disable 0x20 for testing against public DNS servers that may not preserve case
        let client = DnsNetworkClient::new_with_0x20(false);
        client.run().unwrap();

        let res = client.send_udp_query("google.com", QueryType::A, ("8.8.8.8", 53), true, DEFAULT_TIMEOUT).unwrap();

        assert_eq!(res.questions[0].name, "google.com");
        assert!(res.answers.len() > 0);

        match res.answers[0] {
            DnsRecord::A { ref domain, .. } => {
                assert_eq!("google.com", domain);
            }
            _ => panic!()
        }
    }

    #[test]
    pub fn test_tcp_client() {
        // Disable 0x20 for testing against public DNS servers
        let client = DnsNetworkClient::new_with_0x20(false);
        let res = client.send_tcp_query("google.com", QueryType::A, ("8.8.8.8", 53), true).unwrap();

        assert_eq!(res.questions[0].name, "google.com");
        assert!(res.answers.len() > 0);

        match res.answers[0] {
            DnsRecord::A { ref domain, .. } => {
                assert_eq!("google.com", domain);
            }
            _ => panic!()
        }
    }
}
