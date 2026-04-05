extern crate serde;
extern crate serde_json;

use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc, Mutex};
use std::time::{Duration, Instant};
use std::{io, thread};

use crossbeam_channel::{bounded, Receiver, Sender};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use crate::commons::rtt_tracker::RttTracker;
use crate::p2p::version::Version;
use rand::{random, Rng, RngCore};
use rand::prelude::thread_rng;
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::blockchain::types::BlockQuality;
use crate::blockchain::hash_utils::{check_block_hash, check_block_signature, hash_difficulty};
use crate::commons::*;
use crate::crypto::Chacha;
use crate::eventbus::{post, register};
use crate::p2p::{Message, Peer, Peers, State};
use crate::{Block, Bytes, Context};

const SERVER: Token = Token(0);

/// Job sent to validation worker threads
struct ValidationJob {
    token: Token,
    block: Block,
}

/// Result from validation worker threads after CPU-intensive checks
enum PreValidationResult {
    /// Block passed hash and signature checks, needs DB validation
    NeedsDbValidation(Token, Block),
    /// Block failed basic validation
    Invalid(Token, Block),
}

pub struct Network {
    context: Arc<Mutex<Context>>,
    secret_key: ReusableSecret,
    public_key: PublicKey,
    token: Token,
    // States of peer connections, and some data to send when sockets become writable
    peers: Peers,
    // Orphan blocks from future
    future_blocks: HashMap<u64, Block>,
    // Validation thread pool channels
    validation_sender: Sender<ValidationJob>,
    validation_receiver: Receiver<PreValidationResult>,
    // Track pending block requests: block_index -> (request_time, peer_token)
    pending_requests: HashMap<u64, (Instant, Token)>,
    // Track peer response times for adaptive selection
    peer_rtt: RttTracker<Token>,
}

impl Network {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        // P2P encryption primitives
        let mut thread_rng = thread_rng();
        let secret_key = ReusableSecret::random_from_rng(&mut thread_rng);
        let public_key = PublicKey::from(&secret_key);
        let peers = Peers::new();

        // Create validation thread pool
        let cpus = num_cpus::get();
        let num_workers = cpus.min((cpus / 2).max(1)); // At most half cpus
        info!("Starting {num_workers} validation threads");
        let channel_capacity = (num_workers * 4).max(100);
        let (job_sender, job_receiver) = bounded::<ValidationJob>(channel_capacity);
        let (result_sender, result_receiver) = bounded::<PreValidationResult>(channel_capacity);

        // Spawn validation worker threads
        for i in 0..num_workers {
            let job_rx = job_receiver.clone();
            let result_tx = result_sender.clone();

            thread::Builder::new()
                .name(format!("block-validator-{}", i))
                .spawn(move || {
                    Self::validation_worker(job_rx, result_tx);
                })
                .expect("Failed to spawn validation worker thread");
        }

        // Drop the extra senders/receivers we don't need
        drop(result_sender);

        Network {
            context,
            secret_key,
            public_key,
            token: Token(1),
            peers,
            future_blocks: HashMap::new(),
            validation_sender: job_sender,
            validation_receiver: result_receiver,
            pending_requests: HashMap::new(),
            peer_rtt: RttTracker::new(),
        }
    }

    /// Worker thread that performs CPU-intensive block validation
    fn validation_worker(
        job_receiver: Receiver<ValidationJob>,
        result_sender: Sender<PreValidationResult>,
    ) {
        loop {
            match job_receiver.recv() {
                Ok(job) => {
                    let ValidationJob { token, block } = job;

                    // Perform CPU-intensive validation without holding any locks
                    // These checks don't require database access

                    // Check 1: Verify block hash
                    if !check_block_hash(&block) {
                        debug!("Block {} failed hash validation", block.index);
                        let _ = result_sender.send(PreValidationResult::Invalid(token, block));
                        continue;
                    }

                    // Check 2: Verify block signature
                    if !check_block_signature(&block) {
                        debug!("Block {} failed signature validation", block.index);
                        let _ = result_sender.send(PreValidationResult::Invalid(token, block));
                        continue;
                    }

                    // Check 3: Verify hash difficulty matches claimed difficulty
                    if hash_difficulty(&block.hash) < block.difficulty {
                        debug!("Block {} hash difficulty doesn't match claimed difficulty", block.index);
                        let _ = result_sender.send(PreValidationResult::Invalid(token, block));
                        continue;
                    }

                    // Block passed CPU-intensive checks, send for DB validation
                    let _ = result_sender.send(PreValidationResult::NeedsDbValidation(token, block));
                }
                Err(_) => {
                    // Channel closed, exit worker thread
                    break;
                }
            }
        }
    }

    pub fn start(&mut self) {
        let (listen_addr, peers_addrs, yggdrasil_only) = {
            let c = self.context.lock().unwrap();
            (c.settings.net.listen.clone(), c.settings.net.peers.clone(), c.settings.net.yggdrasil_only)
        };

        let running = Arc::new(AtomicBool::new(true));
        subscribe_to_bus(Arc::clone(&running));

        // Starting server socket
        let addr = listen_addr.parse().expect("Error parsing listen address");
        let mut server = TcpListener::bind(addr).expect("Can't bind to address");
        debug!("Started node listener on {}", server.local_addr().unwrap());

        let mut buffer = vec![0u8; 65535];
        let mut events = Events::with_capacity(64);
        let mut poll = Poll::new().expect("Unable to create poll");
        poll.registry().register(&mut server, SERVER, Interest::READABLE).expect("Error registering poll");

        // Starting peer connections to bootstrap nodes
        wait_for_internet(WAIT_FOR_INTERNET);
        self.peers.connect_peers(&peers_addrs, poll.registry(), &mut self.token, yggdrasil_only);

        let mut ui_timer = Instant::now();
        let mut log_timer = Instant::now();
        let mut bootstrap_timer = Instant::now();
        let mut connect_timer = Instant::now();
        let mut last_events_time = Instant::now();
        let mut old_blocks = 0u64;
        let mut old_domains = 0i64;
        let mut old_keys = 0i64;
        let mut old_nodes = 0usize;
        let mut old_banned = 0usize;
        let mut seen_blocks = HashSet::new();

        let (debug_send, debug_receive) = mpsc::channel();
        let _debug_thread = thread::spawn(move || {
            let mut timer = Instant::now();
            let mut log = String::new();
            loop {
                if let Ok(line) = debug_receive.try_recv() {
                    timer = Instant::now();
                    log = line;
                } else {
                    if timer.elapsed().as_secs() >= 60 {
                        timer = Instant::now();
                        warn!("Stuck in '{log}'");
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
        });

        loop {
            let _ = debug_send.send(String::from("Restart swarm"));
            if self.peers.get_peers_count() == 0 && bootstrap_timer.elapsed().as_secs() > 60 {
                warn!("Restarting swarm connections...");
                wait_for_internet(WAIT_FOR_INTERNET);
                // Starting peer connections to bootstrap nodes
                self.peers.connect_peers(&peers_addrs, poll.registry(), &mut self.token, yggdrasil_only);
                bootstrap_timer = Instant::now();
                last_events_time = Instant::now();
            }
            let _ = debug_send.send(String::from("Poll events"));
            // Poll Mio for events, blocking until we get an event.
            poll.poll(&mut events, POLL_TIMEOUT)
                .unwrap_or_else(|e| warn!("Error polling sockets: {}", e));
            if !running.load(Ordering::SeqCst) {
                break;
            }

            // Process each event.
            for event in events.iter() {
                //trace!("Event for socket {} is {:?}", event.token().0, &event);
                // We can use the token we previously provided to `register` to determine for which socket the event is.
                match event.token() {
                    SERVER => {
                        let _ = debug_send.send(String::from("Server accept"));
                        //debug!("Event for server socket {} is {:?}", event.token().0, &event);
                        // If this is an event for the server, it means a connection is ready to be accepted.
                        while let Ok((mut stream, mut address)) = server.accept() {
                            // Checking if it is an ipv4-mapped ipv6 if yes convert to ipv4
                            if address.is_ipv6() {
                                if let IpAddr::V6(ipv6) = address.ip() {
                                    if let Some(ipv4) = ipv6.to_ipv4() {
                                        address = SocketAddr::V4(SocketAddrV4::new(ipv4, address.port()))
                                    }
                                }
                            }

                            if self.peers.is_ignored(&address.ip()) {
                                debug!("Ignoring connection from banned {:?}", &address.ip());
                                stream.shutdown(Shutdown::Both).unwrap_or_else(|e| {
                                    warn!("Error in shutdown, {}", e);
                                });
                                let _ = poll.registry().reregister(&mut server, SERVER, Interest::READABLE);
                                continue;
                            }

                            if yggdrasil_only && !is_yggdrasil(&address.ip()) {
                                debug!("Dropping connection from Internet");
                                stream.shutdown(Shutdown::Both).unwrap_or_else(|e| {
                                    warn!("Error in shutdown, {}", e);
                                });
                                let _ = poll.registry().reregister(&mut server, SERVER, Interest::READABLE);
                                continue;
                            }

                            //debug!("Accepted connection from: {} to local IP: {}", address, local_ip);
                            let token = self.next_token();
                            poll.registry().register(&mut stream, token, Interest::READABLE).expect("Error registering poll");
                            let peer = Peer::new(address, stream, State::Connected{ from: Instant::now() }, true);
                            self.peers.add_peer(token, peer);
                        }
                        if let Err(e) = poll.registry().reregister(&mut server, SERVER, Interest::READABLE) {
                            panic!("Error reregistering server token!\n{}", e);
                        }
                    }
                    token => {
                        let peer = match self.peers.get_peer(&token) {
                            None => "None".to_string(),
                            Some(p) => p.to_string()
                        };
                        let _ = debug_send.send(format!("Handle connection event: {:?} for peer {}", &event, &peer));
                        if !self.handle_connection_event(poll.registry(), event, &mut seen_blocks, &mut buffer) {
                            // Record failure and remove pending requests for this peer
                            self.peer_rtt.record_failure(&token);
                            self.pending_requests.retain(|_index, (_time, t)| *t != token);
                            let _ = self.peers.close_peer(poll.registry(), &token);
                            let blocks = self.context.lock().unwrap().chain.get_height();
                            let keys = self.context.lock().unwrap().chain.get_users_count();
                            let domains = self.context.lock().unwrap().chain.get_domains_count();
                            post(crate::event::Event::NetworkStatus { blocks, domains, keys, nodes: self.peers.get_peers_active_count() });
                        }
                    }
                }
            }
            let _ = debug_send.send(String::from("After events iter"));

            // Process validation results from worker threads
            let _ = debug_send.send(String::from("Process validation results"));
            self.process_validation_results();

            if last_events_time.elapsed().as_secs() > MAX_IDLE_SECONDS {
                if self.peers.get_peers_count() > 0 {
                    warn!("Something is wrong with swarm connections, closing all.");
                    self.peers.close_all_peers(poll.registry());
                    continue;
                } else {
                    thread::sleep(POLL_TIMEOUT.unwrap());
                }
            } else if !events.is_empty() {
                last_events_time = Instant::now();
            }

            let _ = debug_send.send(String::from("UI Timer"));
            if ui_timer.elapsed().as_millis() > UI_REFRESH_DELAY_MS {
                // Send pings to idle peers
                let (height, max_height, hash) = {
                    let context = self.context.lock().unwrap();
                    let blocks = context.chain.get_height();
                    let max_height = context.chain.get_max_height();
                    let nodes = self.peers.get_peers_active_count();
                    let banned = self.peers.get_peers_banned_count();

                    let keys = context.chain.get_users_count();
                    let domains = context.chain.get_domains_count();
                    let nodes_changed = old_nodes != nodes;
                    let other_changed = old_blocks != blocks || old_banned != banned || old_domains != domains || old_keys != keys;
                    if nodes_changed || other_changed {
                        // Don't log every current connection count change
                        if log_timer.elapsed().as_secs() > LOG_REFRESH_DELAY_SEC || other_changed {
                            info!("Active nodes: {}, banned: {}, blocks: {}, domains: {}, keys: {}", nodes, banned, blocks, domains, keys);
                        }
                        post(crate::event::Event::NetworkStatus { blocks, domains, keys, nodes });
                        old_nodes = nodes;
                        old_blocks = blocks;
                        old_domains = domains;
                        old_keys = keys;
                        old_banned = banned;
                    }

                    if log_timer.elapsed().as_secs() > LOG_REFRESH_DELAY_SEC {
                        let elapsed = last_events_time.elapsed().as_secs();
                        if elapsed >= 30 {
                            warn!("Last network events time {} seconds ago", elapsed);
                        }
                        log_timer = Instant::now();
                    }
                    if nodes < MAX_NODES && connect_timer.elapsed().as_secs() >= 2 {
                        self.peers.connect_new_peers(poll.registry(), &mut self.token, yggdrasil_only);
                        connect_timer = Instant::now();
                    }
                    (blocks, max_height, context.chain.get_last_hash())
                };

                // Periodic sync maintenance: gap retries and idle peer kicks
                if height < max_height {
                    self.sync_maintain(height, max_height);
                } else if height >= max_height && !self.future_blocks.is_empty() {
                    // We've caught up but have stale future_blocks — clean them up
                    self.future_blocks.clear();
                    self.pending_requests.clear();
                    post(crate::event::Event::SyncFinished);
                }

                let _ = debug_send.send(String::from("Peers update"));
                let mut have_blocks: HashSet<u64> = self.future_blocks.keys().copied().collect();
                // Also include blocks that are pending validation to avoid re-requesting them
                have_blocks.extend(self.pending_requests.keys().copied());
                self.peers.update(poll.registry(), hash, height, max_height, have_blocks);
                ui_timer = Instant::now();
            }
        }
        if !running.load(Ordering::SeqCst) {
            info!("Network loop finished");
        } else {
            panic!("Network loop has broken prematurely!");
        }
    }

    fn handle_connection_event(&mut self, registry: &Registry, event: &Event, seen_blocks: &mut HashSet<Bytes>, buf: &mut [u8]) -> bool {
        if event.is_error() || (event.is_read_closed() && event.is_write_closed()) {
            return false;
        }

        if event.is_readable() {
            if !self.process_readable(registry, event, seen_blocks, buf) {
                return false;
            }
        }

        if event.is_writable() {
            if !self.process_writable(registry, event) {
                return false;
            }
        }

        true
    }

    fn process_readable(&mut self, registry: &Registry, event: &Event, seen_blocks: &mut HashSet<Bytes>, buf: &mut [u8]) -> bool {
        let data_size = {
            let token = event.token();
            match self.peers.get_mut_peer(&token) {
                None => {
                    error!("Error getting peer for connection {}", token.0);
                    return false;
                }
                Some(peer) => {
                    if event.is_read_closed() {
                        debug!("Node from {} disconnected", peer.get_addr().ip());
                        return false;
                    }
                    match *peer.get_state() {
                        State::Connected { .. } => {
                            let stream = peer.get_stream();
                            return match read_client_handshake(stream) {
                                Ok(key) => {
                                    let mut buf = [0u8; 32];
                                    buf.copy_from_slice(key.as_slice());
                                    let public_key: PublicKey = PublicKey::from(buf);
                                    let shared = self.secret_key.diffie_hellman(&public_key);
                                    let mut nonce = [0u8; 12];
                                    let mut rng = thread_rng();
                                    rng.fill(&mut nonce);
                                    let chacha = Chacha::new(shared.as_bytes(), &nonce);
                                    registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                                    peer.set_cipher(chacha);
                                    peer.set_state(State::ServerHandshake{ from: Instant::now() });
                                    //trace!("Client hello read successfully");
                                    true
                                }
                                Err(_) => {
                                    debug!("Error reading client handshake from {}.", peer.get_addr());
                                    false
                                }
                            };
                        }
                        State::ServerHandshake { .. } => {
                            let stream = peer.get_stream();
                            return match read_server_handshake(stream) {
                                Ok(data) => {
                                    if data.len() != 32 + 12 {
                                        warn!("Server handshake of {} bytes instead of {}", data.len(), 32 + 12);
                                        return false;
                                    }
                                    let mut buf = [0u8; 32];
                                    buf.copy_from_slice(&data.as_slice()[0..32]);
                                    let public_key: PublicKey = PublicKey::from(buf);
                                    let mut nonce = [0u8; 12];
                                    nonce.copy_from_slice(&data.as_slice()[32..]);
                                    let shared = self.secret_key.diffie_hellman(&public_key);
                                    let chacha = Chacha::new(shared.as_bytes(), &nonce);
                                    registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                                    peer.set_cipher(chacha);
                                    peer.set_state(State::HandshakeFinished);
                                    //trace!("Server hello read successfully");
                                    true
                                }
                                Err(_) => {
                                    debug!("Error reading client handshake from {}", peer.get_addr());
                                    false
                                }
                            };
                        }
                        _ => {
                            let stream = peer.get_stream();
                            read_message(stream, buf)
                        }
                    }
                }
            }
        };

        if let Ok(data_size) = data_size {
            let data = {
                match self.peers.get_peer(&event.token()) {
                    Some(peer) => decode_message(&buf[0..data_size], peer.get_cipher()).unwrap_or_else(|_| vec![]),
                    None => vec![],
                }
            };
            match Message::from_bytes(data) {
                Ok(message) => {
                    //let m = format!("{:?}", &message);
                    let new_state = self.handle_message(message, &event.token(), seen_blocks);
                    let peer = self.peers.get_mut_peer(&event.token()).unwrap();
                    //debug!("Got message from {}: {:?}", &peer.get_addr(), &m);
                    match new_state {
                        State::Message { data } => {
                            let stream = peer.get_stream();
                            registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                            peer.set_state(State::Message { data });
                        }
                        State::Connecting => {}
                        State::Connected { .. } => {}
                        State::ServerHandshake { .. } => {}
                        State::HandshakeFinished => {}
                        State::Idle { .. } => {
                            peer.set_state(State::idle());
                        }
                        State::Error => {}
                        State::Banned => {
                            self.peers.ignore_peer(registry, &event.token());
                        }
                        State::Offline { .. } => {
                            peer.set_state(State::offline());
                        }
                        State::Loop => {
                            peer.set_state(State::Loop);
                            self.peers.ignore_peer(registry, &event.token());
                        }
                        State::SendLoop => {
                            let stream = peer.get_stream();
                            registry.reregister(stream, event.token(), Interest::WRITABLE | Interest::READABLE).unwrap();
                            peer.set_state(State::SendLoop);
                        }
                        State::Twin => {
                            peer.set_state(State::Twin);
                            // TODO set something in [Peers], maybe ignore this IP?
                            return false;
                        }
                    }
                }
                Err(e) => {
                    let peer = self.peers.get_peer(&event.token()).unwrap();
                    warn!("Error deserializing message from {}: {}", &peer.get_addr(), e.to_string());
                    return false;
                }
            }
        } else {
            let error = data_size.err().unwrap();
            let addr = match self.peers.get_peer(&event.token()) {
                None => String::from("unknown"),
                Some(peer) => peer.get_addr().to_string()
            };
            debug!("Error reading message from {}, error = {}", addr, error);
            return false;
        }
        true
    }

    fn process_writable(&mut self, registry: &Registry, event: &Event) -> bool {
        let my_id = self.peers.get_my_id().to_owned();
        if let Some(peer) = self.peers.get_mut_peer(&event.token()) {
            match peer.get_state().clone() {
                State::Connecting => {
                    if send_client_handshake(peer.get_stream(), self.public_key.as_bytes()).is_err() {
                        return false;
                    }
                    peer.set_state(State::ServerHandshake{ from: Instant::now() });
                    peer.set_active(true);
                }
                State::ServerHandshake { .. } => {
                    if send_server_handshake(peer, self.public_key.as_bytes()).is_err() {
                        return false;
                    }
                    peer.set_state(State::HandshakeFinished);
                    peer.set_active(true);
                    //trace!("Server handshake sent");
                }
                State::HandshakeFinished => {
                    //debug!("Connected to peer {}, sending hello...", &peer.get_addr());
                    let data: Vec<u8> = {
                        let c = self.context.lock().unwrap();
                        let message = Message::hand(&c.app_version, &c.settings.origin, CHAIN_VERSION, c.settings.net.public, &my_id);
                        //info!("Sending: {:?}", &message);
                        encode_message(&message, peer.get_cipher()).unwrap()
                    };
                    send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending hello {}", e));
                    peer.set_state(State::idle());
                    peer.set_active(true);
                    //debug!("Sent hello to {}", &peer.get_addr());
                }
                State::Connected { .. } => {}
                State::Message { data } => {
                    //debug!("Sending data to {}: {}", &peer.get_addr(), &String::from_utf8(data.clone()).unwrap());
                    if let Ok(data) = encode_bytes(&data, peer.get_cipher()) {
                        send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending message {}", e));
                    }
                    peer.set_state(State::idle());
                }
                State::Idle { from } => {
                    if peer.has_queued_messages() {
                        // Send ONE queued message at a time to avoid flooding remote peer
                        if let Some(queued_data) = peer.pop_message() {
                            if let Ok(data) = encode_bytes(&queued_data, peer.get_cipher()) {
                                send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending queued message {}", e));
                            }
                        }
                    } else {
                        debug!("Odd version of pings for {}", peer.get_addr().ip());
                        if from.elapsed().as_secs() >= 120 {
                            let data: Vec<u8> = {
                                let c = self.context.lock().unwrap();
                                let message = Message::ping(c.chain.get_height(), c.chain.get_last_hash());
                                encode_message(&message, peer.get_cipher()).unwrap()
                            };
                            send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending ping {}", e));
                        }
                    }
                }
                State::Error => {}
                State::Banned => {}
                State::Offline { .. } => {}
                State::Loop => {}
                State::SendLoop => {
                    let data = encode_message(&Message::Loop, peer.get_cipher()).unwrap();
                    send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending loop {}", e));
                    peer.set_state(State::idle());
                }
                State::Twin => {
                    let data = encode_message(&Message::Twin, peer.get_cipher()).unwrap();
                    send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending loop {}", e));
                    peer.set_state(State::idle());
                }
            }
            registry.reregister(peer.get_stream(), event.token(), Interest::READABLE).unwrap();
        }
        true
    }

    fn handle_message(&mut self, message: Message, token: &Token, seen_blocks: &mut HashSet<Bytes>) -> State {
        let (my_height, my_hash, my_origin, my_version, me_public) = {
            let context = self.context.lock().unwrap();
            // TODO cache it somewhere
            (context.chain.get_height(), context.chain.get_last_hash(), &context.settings.origin.clone(), CHAIN_VERSION, context.settings.net.public)
        };
        let my_id = self.peers.get_my_id().to_owned();
        let answer = match message {
            Message::Hand { app_version, origin, version, public, rand_id } => {
                if !version_compatible(&app_version) {
                    let peer = self.peers.get_peer(token).unwrap();
                    info!("Banning peer with version {}, at {}", &app_version, peer.get_addr().ip());
                    return State::Banned;
                }
                if self.peers.is_our_own_connect(&rand_id) {
                    warn!("Detected loop connect");
                    State::SendLoop
                } else if origin.eq(my_origin) {
                    let peer = self.peers.get_mut_peer(token).unwrap();
                    debug!("Incoming v{} on {}", &app_version, peer.get_addr().ip());
                    peer.set_version(Version::parse(&app_version));
                    let app_version = self.context.lock().unwrap().app_version.clone();
                    if version == my_version {
                        peer.set_public(public);
                        peer.set_active(true);
                    } else {
                        warn!("Handshake from unsupported version: {} (local version: {})", version, my_version);
                    }
                    State::message(Message::shake(&app_version, &origin, my_version, me_public, &my_id, my_height))
                } else {
                    warn!("Handshake from unsupported chain: {}", &origin);
                    State::Banned
                }
            }
            Message::Shake { app_version, origin, version, public, rand_id, height } => {
                if origin.ne(my_origin) {
                    return State::Banned;
                } else if version > my_version {
                    warn!("Can't work with newer blockchain version {} and ALFIS version {}, please upgrade!", version, &app_version);
                    return State::Banned;
                } else if version != my_version {
                    return State::Banned;
                }
                if self.peers.is_tween_connect(&rand_id) {
                    return State::Twin;
                }
                if !version_compatible(&app_version) {
                    let peer = self.peers.get_peer(token).unwrap();
                    info!("Banning peer with version {} at {}", &app_version, peer.get_addr().ip());
                    return State::Banned;
                }
                let nodes = self.peers.get_peers_active_count();
                let peer = self.peers.get_mut_peer(token).unwrap();
                // TODO check rand_id whether we have this peers connection already
                debug!("Outgoing v{} on {}", &app_version, peer.get_addr().ip());
                peer.set_version(Version::parse(&app_version));
                peer.set_height(height);
                peer.set_active(true);
                peer.set_public(public);
                peer.reset_reconnects();
                let mut context = self.context.lock().unwrap();
                if peer.is_higher(my_height) {
                    context.chain.update_max_height(height);
                    let event = crate::event::Event::Syncing { have: my_height, height: max(height, my_height) };
                    post(event);
                }
                if nodes < MAX_NODES && random::<bool>() {
                    debug!("Requesting more peers from {}", peer.get_addr().ip());
                    State::message(Message::GetPeers)
                } else {
                    State::idle()
                }
            }
            Message::Error => State::Error,
            Message::Ping { height, hash } => {
                let peer = self.peers.get_mut_peer(token).unwrap();
                peer.set_height(height);
                peer.set_active(true);
                if seen_blocks.contains(&hash) {
                    return State::message(Message::pong(my_height, my_hash));
                }
                if peer.is_higher(my_height) {
                    let max_height = {
                        let mut context = self.context.lock().unwrap();
                        context.chain.update_max_height(height);
                        context.chain.get_max_height()
                    };
                    // Start pipeline: queue a block request, then send pong
                    if let Some(idx) = self.next_block_to_request(my_height, max_height) {
                        let peer = self.peers.get_mut_peer(token).unwrap();
                        if peer.can_send() {
                            peer.queue_message(Message::GetBlock { index: idx });
                            self.pending_requests.insert(idx, (Instant::now(), *token));
                        }
                    }
                    State::message(Message::pong(my_height, my_hash))
                } else if my_height == height && hash.ne(&my_hash) {
                    info!("Hashes are different, requesting block {} from {}", my_height, peer.get_addr().ip());
                    info!("My hash: {:?}, their hash: {:?}", &my_hash, &hash);
                    State::message(Message::GetBlock { index: my_height })
                } else {
                    State::message(Message::pong(my_height, my_hash))
                }
            }
            Message::Pong { height, hash } => {
                let active_count = self.peers.get_peers_active_count();
                let peer = self.peers.get_mut_peer(token).unwrap();
                peer.set_height(height);
                peer.set_active(true);
                if seen_blocks.contains(&hash) {
                    return State::idle();
                }
                if peer.is_higher(my_height) {
                    let max_height = {
                        let mut context = self.context.lock().unwrap();
                        context.chain.update_max_height(height);
                        context.chain.get_max_height()
                    };
                    // Start pipeline: request next needed block from this peer
                    if let Some(idx) = self.next_block_to_request(my_height, max_height) {
                        self.pending_requests.insert(idx, (Instant::now(), *token));
                        return State::message(Message::GetBlock { index: idx });
                    }
                    State::idle()
                } else if my_height == height && hash.ne(&my_hash) {
                    info!("Hashes are different, requesting block {} from {}", my_height, peer.get_addr().ip());
                    info!("My hash: {:?}, their hash: {:?}", &my_hash, &hash);
                    State::message(Message::GetBlock { index: my_height })
                } else if active_count < MAX_NODES && random::<u8>() < 50 {
                    debug!("Requesting more peers from {}", peer.get_addr().ip());
                    State::message(Message::GetPeers)
                } else {
                    State::idle()
                }
            }
            Message::GetPeers => {
                let addr = {
                    let peer = self.peers.get_mut_peer(token).unwrap();
                    peer.set_active(true);
                    peer.get_addr()
                };
                State::message(Message::Peers { peers: self.peers.get_peers_for_exchange(&addr) })
            }
            Message::Peers { peers: new_peers } => {
                let peer = self.peers.get_mut_peer(token).unwrap();
                peer.set_active(true);
                self.peers.add_peers_from_exchange(new_peers);
                State::idle()
            }
            Message::GetBlock { index } => {
                let peer = self.peers.get_mut_peer(token).unwrap();
                peer.set_active(true);
                let context = self.context.lock().unwrap();
                match context.chain.get_block(index) {
                    Some(block) => State::message(Message::block(block.index, block.as_bytes())),
                    None => State::Error
                }
            }
            Message::Block { index, block } => {
                let peer = self.peers.get_mut_peer(token).unwrap();
                peer.set_active(true);
                let block: Block = match Block::from_bytes(block.as_slice()) {
                    Ok(block) => block,
                    Err(e) => {
                        warn!("Error deserializing block! {}", e);
                        return State::Banned;
                    }
                };
                if index != block.index {
                    return State::Banned;
                }
                let peer_addr = self.peers.get_peer(token).map_or("unknown".to_string(), |p| p.get_addr().ip().to_string());
                debug!("Received block {} with hash {:?} from {}", block.index, &block.hash, &peer_addr);
                // Record RTT but keep in pending_requests until validation completes
                // (prevents re-requesting while block is in validation channel)
                if let Some((request_time, peer_token)) = self.pending_requests.get(&block.index) {
                    let rtt_ms = request_time.elapsed().as_secs_f64() * 1000.0;
                    self.peer_rtt.record_success(peer_token, rtt_ms);
                }
                // Skip blocks we already have in the chain
                let current_height = self.context.lock().unwrap().chain.get_height();
                if block.index <= current_height {
                    let peer_addr = self.peers.get_peer(token).map_or("unknown".to_string(), |p| p.get_addr().ip().to_string());
                    debug!("Skipping stale block {} from {} (height is {})", block.index, peer_addr, current_height);
                    return State::idle();
                }
                if !seen_blocks.contains(&block.hash) {
                    seen_blocks.insert(block.hash.clone());
                    // Send block to validation worker threads for parallel processing
                    match self.validation_sender.try_send(ValidationJob {
                        token: *token,
                        block,
                    }) {
                        Ok(_) => {},
                        Err(crossbeam_channel::TrySendError::Full(job)) => {
                            debug!("Validation queue full, deferring block {}", job.block.index);
                            self.future_blocks.insert(job.block.index, job.block);
                        },
                        Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                            warn!("Validation worker threads have stopped");
                        },
                    }
                }

                // Pipeline: immediately request the next needed block from this peer
                let (my_height, max_height) = {
                    let c = self.context.lock().unwrap();
                    (c.chain.get_height(), c.chain.get_max_height())
                };
                if my_height < max_height {
                    if let Some(next_idx) = self.next_block_to_request(my_height, max_height) {
                        let peer_addr = self.peers.get_peer(token).map_or("unknown".to_string(), |p| p.get_addr().ip().to_string());
                        debug!("Requesting block {next_idx} from {}", &peer_addr);
                        self.pending_requests.insert(next_idx, (Instant::now(), *token));
                        return State::message(Message::GetBlock { index: next_idx });
                    }
                }
                State::idle()
            }
            Message::Twin => State::Twin,
            Message::Loop => State::Loop
        };
        answer
    }

    /// Find the next block that needs to be requested within the sync window.
    /// Returns None if all blocks in the window are already requested or received.
    fn next_block_to_request(&self, my_height: u64, max_height: u64) -> Option<u64> {
        const SYNC_WINDOW: u64 = 500;
        let end = max_height.min(my_height + SYNC_WINDOW);
        for idx in (my_height + 1)..=end {
            if !self.future_blocks.contains_key(&idx) && !self.pending_requests.contains_key(&idx) {
                return Some(idx);
            }
        }
        None
    }

    /// Periodic sync maintenance: retry gap blocks, kick idle peers into the pipeline.
    fn sync_maintain(&mut self, my_height: u64, max_height: u64) {
        const GAP_TIMEOUT_MSECS: u128 = 1500;

        let now = Instant::now();

        // Record failures for timed-out requests before cleanup
        let timed_out: Vec<Token> = self.pending_requests.iter()
            .filter(|(_, (t, _))| t.elapsed().as_millis() >= GAP_TIMEOUT_MSECS)
            .map(|(_, (_, tok))| *tok)
            .collect();
        for tok in &timed_out {
            self.peer_rtt.record_failure(tok);
        }

        // Clean up stale requests: timed out or peer no longer active
        self.pending_requests.retain(|_index, (request_time, token)| {
            if request_time.elapsed().as_millis() >= GAP_TIMEOUT_MSECS * 2 {
                return false;
            }
            match self.peers.get_peer(token) {
                Some(peer) => peer.active(),
                None => false,
            }
        });

        let raw_peers = self.peers.get_active_peer_tokens();
        if raw_peers.is_empty() {
            return;
        }
        let active_peers = self.peer_rtt.select_ordered(&raw_peers);

        // Retry gap blocks with shorter timeout — push to FRONT of fastest peer's queue
        let min_future_block = self.future_blocks.keys().min().copied();
        if let Some(min_future) = min_future_block {
            // active_peers is already ranked by RTT (fastest first)
            let mut gap_peer_idx = 0;
            for block_index in (my_height + 1)..min_future {
                if self.future_blocks.contains_key(&block_index) {
                    continue;
                }
                if let Some((req_time, old_token)) = self.pending_requests.get(&block_index) {
                    if req_time.elapsed().as_millis() < GAP_TIMEOUT_MSECS {
                        continue;
                    }
                    self.peer_rtt.record_failure(old_token);
                    // Skip the failed peer
                    if let Some(pos) = active_peers.iter().position(|t| t == old_token) {
                        if pos == gap_peer_idx {
                            gap_peer_idx = (gap_peer_idx + 1) % active_peers.len();
                        }
                    }
                    debug!("Gap block {} timed out, re-requesting (have future from {})", block_index, min_future);
                }

                // Find a peer that can accept a message (old nodes only allow 1 in flight)
                let mut sent = false;
                for _ in 0..active_peers.len() {
                    let peer_token = active_peers[gap_peer_idx % active_peers.len()];
                    gap_peer_idx = (gap_peer_idx + 1) % active_peers.len();
                    if let Some(peer) = self.peers.get_mut_peer(&peer_token) {
                        if !peer.can_send() {
                            continue;
                        }
                        peer.queue_priority_message(Message::GetBlock { index: block_index });
                        self.pending_requests.insert(block_index, (now, peer_token));
                        debug!("Requesting gap block {} from {} (priority)", block_index, peer.get_addr().ip());
                        sent = true;
                        break;
                    }
                }
                if !sent {
                    break; // All peers busy, try next cycle
                }
            }
        }

        // Kick idle peers into the pipeline (peers with no pending requests)
        for t in &active_peers {
            let has_pending = self.pending_requests.values().any(|(_, tk)| tk == t);
            if has_pending {
                continue;
            }
            if let Some(peer) = self.peers.get_peer(t) {
                if !peer.get_state().is_idle() || peer.has_queued_messages() {
                    continue;
                }
            }
            if let Some(idx) = self.next_block_to_request(my_height, max_height) {
                if let Some(peer) = self.peers.get_mut_peer(t) {
                    peer.queue_message(Message::GetBlock { index: idx });
                    self.pending_requests.insert(idx, (now, *t));
                    debug!("Kicking idle peer {} with block {}", peer.get_addr().ip(), idx);
                }
            }
        }
    }

    /// Process validation results from worker threads and add validated blocks to chain
    fn process_validation_results(&mut self) {
        // Process all available validation results without blocking
        while let Ok(result) = self.validation_receiver.try_recv() {
            match result {
                PreValidationResult::NeedsDbValidation(token, block) => {
                    // CPU-intensive validation passed, now do DB-dependent validation
                    let peers_count = self.peers.get_peers_active_count();

                    // Update peer state
                    if let Some(peer) = self.peers.get_mut_peer(&token) {
                        peer.set_received_block(block.index);
                        trace!("Validated block {} from {}", block.index, peer.get_addr());
                    } else {
                        // Peer disconnected, but we can still process the block
                        trace!("Validated block {} from disconnected peer", block.index);
                    }

                    // Lock context only for DB operations
                    let mut context = self.context.lock().unwrap();
                    let my_height = context.chain.get_height();
                    let max_height = context.chain.get_max_height();

                    // Skip stale blocks that are at or below current height (late pipeline responses)
                    if block.index <= my_height {
                        debug!("Ignoring stale block {} (height is {})", block.index, my_height);
                        self.pending_requests.remove(&block.index);
                        continue;
                    }

                    // Do remaining DB-dependent validation and add to chain
                    match context.chain.check_new_block(&block) {
                        BlockQuality::Good => {
                            let block_index = block.index;
                            let mut next_index = block.index + 1;
                            context.chain.add_block(block);

                            // Clean up pending request for this block
                            self.pending_requests.remove(&block_index);

                            // Process future blocks that are now ready
                            while let Some(block) = self.future_blocks.remove(&next_index) {
                                if context.chain.check_new_block(&block) == BlockQuality::Good {
                                    debug!("Added block {} from future blocks", next_index);
                                    context.chain.add_block(block);
                                    self.pending_requests.remove(&next_index);
                                } else {
                                    warn!("Block {} in future blocks is bad!", block.index);
                                    break;
                                }
                                next_index += 1;
                            }

                            let my_height = context.chain.get_height();
                            post(crate::event::Event::BlockchainChanged { index: my_height });

                            // Check if sync is finished
                            if my_height >= max_height {
                                post(crate::event::Event::SyncFinished);
                                self.future_blocks.clear();
                            } else {
                                let event = crate::event::Event::Syncing {
                                    have: my_height,
                                    height: max(max_height, my_height)
                                };
                                post(event);
                            }

                            let domains = context.chain.get_domains_count();
                            let keys = context.chain.get_users_count();
                            post(crate::event::Event::NetworkStatus {
                                blocks: my_height,
                                domains,
                                keys,
                                nodes: peers_count
                            });
                        }
                        BlockQuality::Twin => {
                            debug!("Ignoring duplicate block {}", block.index);
                        }
                        BlockQuality::Future => {
                            debug!("Got future block {}", block.index);
                            let block_index = block.index;
                            self.future_blocks.insert(block.index, block);
                            // Clean up pending request since we have this block now
                            self.pending_requests.remove(&block_index);
                        }
                        BlockQuality::Bad => {
                            debug!("Block {} failed DB validation", block.index);
                            if let Some(peer) = self.peers.get_mut_peer(&token) {
                                debug!("Banning peer {} for bad block", peer.get_addr());
                                // Mark peer for banning
                                peer.set_state(State::Banned);
                            }
                            let height = context.chain.get_height();
                            if height + 1 == block.index {
                                context.chain.update_max_height(height);
                                post(crate::event::Event::SyncFinished);
                            }
                        }
                        BlockQuality::Rewind => {
                            debug!("Got orphan block {}, requesting parent", block.index);
                            if let Some(peer) = self.peers.get_mut_peer(&token) {
                                peer.set_state(State::message(Message::GetBlock {
                                    index: block.index - 1
                                }));
                            }
                        }
                        BlockQuality::Fork => {
                            debug!("Got forked block {} with hash {:?}", block.index, block.hash);
                            let lagged = block.index == context.chain.get_height()
                                && block.index + LIMITED_CONFIDENCE_DEPTH <= max_height;

                            if let Some(our_block) = context.chain.get_block(block.index) {
                                if block.is_better_than(&our_block) || lagged {
                                    context.chain.replace_block(block)
                                        .expect("Error replacing block with fork");
                                    let index = context.chain.get_height();
                                    post(crate::event::Event::BlockchainChanged { index });
                                } else {
                                    debug!("Fork is not better than our block, dropping");
                                    if let Some(peer) = self.peers.get_mut_peer(&token) {
                                        peer.set_state(State::message(Message::block(
                                            our_block.index,
                                            our_block.as_bytes()
                                        )));
                                    }
                                }
                            }
                        }
                    }
                    // Context lock is dropped here
                }
                PreValidationResult::Invalid(token, block) => {
                    // Block failed CPU-intensive validation
                    debug!("Block {} failed pre-validation (hash/signature)", block.index);
                    if let Some(peer) = self.peers.get_mut_peer(&token) {
                        debug!("Banning peer {} for invalid block", peer.get_addr());
                        peer.set_state(State::Banned);
                    }
                }
            }
        }
    }

    /// Gets new token from old token, mutating the last
    pub fn next_token(&mut self) -> Token {
        let current = self.token.0;
        self.token.0 += 1;
        Token(current)
    }
}

fn subscribe_to_bus(running: Arc<AtomicBool>) {
    use crate::event::Event;
    register(move |_uuid, e| {
        if let Event::ActionQuit = e {
            running.store(false, Ordering::SeqCst);
            return false;
        }
        true
    });
}

fn encode_bytes(data: &[u8], cipher: &Option<Chacha>) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    match cipher {
        None => Ok(data.to_owned()),
        Some(chacha) => chacha.encrypt(data)
    }
}

fn encode_message(message: &Message, cipher: &Option<Chacha>) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    match serde_cbor::to_vec(message) {
        Ok(vec) => {
            match cipher {
                None => {
                    //info!("No cipher, not encoding message: {:?}", to_hex(&vec));
                    Ok(vec)
                }
                Some(chacha) => {
                    //info!("Encoding message: {:?}", to_hex(&vec));
                    chacha.encrypt(vec.as_slice())
                }
            }
        }
        Err(e) => {
            warn!("Could not encode message! {}", e);
            Err(chacha20poly1305::aead::Error)
        }
    }
}

fn decode_message(data: &[u8], cipher: &Option<Chacha>) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    match cipher {
        None => Ok(data.to_owned()),
        Some(chacha) => chacha.decrypt(data)
    }
}

fn read_message(stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize, Error> {
    let instant = Instant::now();
    let data_size = (stream.read_u16::<BigEndian>()? ^ 0xAAAA) as usize;
    if data_size == 0 {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }

    let mut bytes_read = 0;
    let delay = Duration::from_millis(2);
    loop {
        match stream.read(&mut buf[bytes_read..data_size]) {
            Ok(bytes) => {
                bytes_read += bytes;
                if bytes_read == data_size || bytes == 0 {
                    break;
                }
            }
            // Would block "errors" are the OS's way of saying that the connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => {
                // We give every connection no more than 100ms to read a message
                if instant.elapsed().as_millis() < MAX_READ_BLOCK_TIME {
                    // We need to sleep a bit, otherwise it can eat CPU
                    thread::sleep(delay);
                    continue;
                } else {
                    return Err(io::Error::from(ErrorKind::WouldBlock));
                }
            },
            Err(ref err) if interrupted(err) => continue,
            // Other errors we'll consider fatal.
            Err(e) => {
                debug!("Error reading message, only {}/{} bytes read", bytes_read, data_size);
                return Err(e)
            },
        }
    }
    if bytes_read == data_size {
        Ok(data_size)
    } else {
        Err(io::Error::from(ErrorKind::BrokenPipe))
    }
}

/// Sends one byte [garbage_size], [random bytes], and [public_key]
fn send_client_handshake(stream: &mut TcpStream, public_key: &[u8]) -> io::Result<()> {
    let mut rng = thread_rng();
    let packet_size: usize = rng.gen_range(64..255);
    let mut buf = vec![0u8; packet_size];
    rng.fill_bytes(&mut buf);
    let garbage_size = packet_size - 33;
    buf[0] = garbage_size as u8 ^ 0xA; // key length and 1 byte size
    for i in 0..public_key.len() {
        buf[i + garbage_size + 1] = public_key[i];
    }
    stream.write_all(buf.as_slice())?;
    stream.flush()
}

fn read_client_handshake(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    read_garbage_header(stream)?;
    // Then we have public key for ECDH
    let mut buf = vec![0u8; 32];
    match stream.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) => {
            warn!("Error reading handshake!");
            Err(e)
        }
    }
}

fn read_garbage_header(stream: &mut TcpStream) -> Result<(), Error> {
    // First, we read garbage size
    let data_size = match stream.read_u8() {
        Ok(size) => (size ^ 0xA) as usize,
        Err(e) => {
            error!("Error reading from socket! {}", e);
            return Err(e);
        }
    };
    // Read the garbage
    let mut buf = vec![0u8; data_size];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(e) => {
            return Err(e);
        }
    }
    Ok(())
}

fn send_server_handshake(peer: &mut Peer, public_key: &[u8]) -> io::Result<()> {
    let mut rng = thread_rng();
    let packet_size: usize = rng.gen_range(64..255);
    let mut buf = vec![0u8; packet_size];
    rng.fill_bytes(&mut buf);
    let nonce = peer.get_nonce();
    // We will write 1 byte size, garbage, public key, nonce
    let garbage_size = packet_size - 1 - 32 - 12;
    buf[0] = garbage_size as u8 ^ 0xA;
    for i in 0..public_key.len() {
        buf[i + garbage_size + 1] = public_key[i];
    }
    for i in 0..nonce.len() {
        buf[i + garbage_size + 32 + 1] = nonce[i];
    }
    let stream = peer.get_stream();
    stream.write_all(buf.as_slice())?;
    stream.flush()
}

fn read_server_handshake(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    read_garbage_header(stream)?;
    // Then we have public key for ECDH, plus nonce 12 bytes
    let mut buf = vec![0u8; 32 + 12];
    match stream.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) => {
            warn!("Error reading handshake!");
            Err(e)
        }
    }
}

fn send_message(connection: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let data_len = data.len() as u16;
    //debug!("Sending {} bytes", data_len);
    //debug!("Message: {:?}", to_hex(&data));
    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 2);
    buf.write_u16::<BigEndian>(data_len ^ 0xAAAA)?;
    buf.write_all(data)?;
    write_all(connection, &buf)?;
    connection.flush()
}

fn wait_for_internet(timeout: Duration) {
    let addr = "alfis.name:443";
    let start = Instant::now();
    let delay = Duration::from_millis(200);

    trace!("Waiting for internet connection...");
    while start.elapsed() < timeout {
        match addr.to_socket_addrs() {
            Ok(_) => {
                trace!("We got internet connection!");
                return;
            },
            Err(_) => {
                thread::sleep(delay);
                continue;
            }
        };
    }
    trace!("Waiting for internet connection has timed out.")
}

fn would_block(err: &Error) -> bool {
    err.kind() == ErrorKind::WouldBlock
}

fn interrupted(err: &Error) -> bool {
    err.kind() == ErrorKind::Interrupted
}

fn write_all(connection: &mut TcpStream, mut buf: &[u8]) -> io::Result<()> {
    let start = Instant::now();
    let timeout = Duration::from_secs(3);
    let delay = Duration::from_millis(2);
    while !buf.is_empty() {
        match connection.write(buf) {
            Ok(0) => {
                return Err(io::Error::from(ErrorKind::WriteZero));
            }
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == ErrorKind::Interrupted => thread::sleep(delay),
            Err(e) => return Err(e),
        }
        if start.elapsed() > timeout {
            warn!("Error writing data to {}", connection.peer_addr().unwrap());
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        } else {
            thread::sleep(delay);
        }
    }
    Ok(())
}

fn version_compatible(version: &str) -> bool {
    let my_version = env!("CARGO_PKG_VERSION");
    let parts = my_version.split('.').collect::<Vec<&str>>();
    let major = format!("{}.{}", parts[0], parts[1]);
    version.starts_with(&major)
}