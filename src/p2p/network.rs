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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use rand::{random, Rng, RngCore};
use rand::prelude::thread_rng;
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::blockchain::types::BlockQuality;
use crate::commons::*;
use crate::crypto::Chacha;
use crate::eventbus::{post, register};
use crate::p2p::{Message, Peer, Peers, State};
use crate::{Block, Bytes, Context};

const SERVER: Token = Token(0);
// Maximum number of future blocks to prevent memory leak
const MAX_FUTURE_BLOCKS: usize = 1000;

pub struct Network {
    context: Arc<Mutex<Context>>,
    secret_key: ReusableSecret,
    public_key: PublicKey,
    token: Token,
    // States of peer connections, and some data to send when sockets become writable
    peers: Peers,
    // Orphan blocks from future
    future_blocks: HashMap<u64, Block>
}

impl Network {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        // P2P encryption primitives
        let mut thread_rng = thread_rng();
        let secret_key = ReusableSecret::random_from_rng(&mut thread_rng);
        let public_key = PublicKey::from(&secret_key);
        let peers = Peers::new();
        Network { context, secret_key, public_key, token: Token(1), peers, future_blocks: HashMap::new() }
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
                        // #region agent log
                        let future_blocks_size = self.future_blocks.len();
                        let seen_blocks_size = seen_blocks.len();
                        use std::fs::OpenOptions;
                        use std::io::Write;
                        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/tmp/alfis-debug.log") {
                            let _ = writeln!(file, r#"{{"id":"p2p_memory_monitor","timestamp":{},"location":"p2p/network.rs:233","message":"P2P memory monitoring","data":{{"future_blocks":{},"seen_blocks":{},"peers":{}}},"sessionId":"debug-session","runId":"run1","hypothesisId":"B"}}"#, 
                                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64, 
                                future_blocks_size, seen_blocks_size, nodes);
                        }
                        // #endregion
                        log_timer = Instant::now();
                        seen_blocks.clear();
                    }
                    if nodes < MAX_NODES && connect_timer.elapsed().as_secs() >= 2 {
                        self.peers.connect_new_peers(poll.registry(), &mut self.token, yggdrasil_only);
                        connect_timer = Instant::now();
                    }
                    (blocks, max_height, context.chain.get_last_hash())
                };

                let _ = debug_send.send(String::from("Peers update"));
                let have_blocks: HashSet<u64> = self.future_blocks.values().map(|block| block.index).collect();
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
                    let mut context = self.context.lock().unwrap();
                    context.chain.update_max_height(height);
                    info!("Peer is higher, requesting block {} from {}", my_height + 1, peer.get_addr().ip());
                    State::message(Message::GetBlock { index: my_height + 1 })
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
                    let mut context = self.context.lock().unwrap();
                    context.chain.update_max_height(height);
                    info!("Peer is higher, requesting block {} from {}", my_height + 1, peer.get_addr().ip());
                    State::message(Message::GetBlock { index: my_height + 1 })
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
                debug!("Received block {} with hash {:?}", block.index, &block.hash);
                if !seen_blocks.contains(&block.hash) {
                    self.handle_block(token, block, seen_blocks)
                } else {
                    State::idle()
                }
            }
            Message::Twin => State::Twin,
            Message::Loop => State::Loop
        };
        answer
    }

    fn handle_block(&mut self, token: &Token, block: Block, seen_blocks: &mut HashSet<Bytes>) -> State {
        seen_blocks.insert(block.hash.clone());
        let peers_count = self.peers.get_peers_active_count();
        let peer = self.peers.get_mut_peer(token).unwrap();
        peer.set_received_block(block.index);
        trace!("New block from {}", &peer.get_addr());

        let mut context = self.context.lock().unwrap();
        let max_height = context.chain.get_max_height();
        match context.chain.check_new_block(&block) {
            BlockQuality::Good => {
                let mut next_index = block.index + 1;
                context.chain.add_block(block);
                // If we have some consequent blocks in a bucket of 'future blocks', we add them
                while let Some(block) = self.future_blocks.remove(&next_index) {
                    if context.chain.check_new_block(&block) == BlockQuality::Good {
                        debug!("Added block {} from future blocks", next_index);
                        context.chain.add_block(block);
                    } else {
                        warn!("Block {} in future blocks is bad!", block.index);
                        break;
                    }
                    next_index += 1;
                }
                let my_height = context.chain.get_height();
                post(crate::event::Event::BlockchainChanged { index: my_height });
                // If it was the last block to sync
                if my_height == max_height {
                    post(crate::event::Event::SyncFinished);
                    self.future_blocks.clear();
                } else {
                    let event = crate::event::Event::Syncing { have: my_height, height: max(max_height, my_height) };
                    post(event);
                }
                let domains = context.chain.get_domains_count();
                let keys = context.chain.get_users_count();
                post(crate::event::Event::NetworkStatus { blocks: my_height, domains, keys, nodes: peers_count });
            }
            BlockQuality::Twin => { debug!("Ignoring duplicate block {}", block.index); }
            BlockQuality::Future => {
                debug!("Got future block {}", block.index);
                // #region agent log
                let future_blocks_size_before = self.future_blocks.len();
                let block_index = block.index; // Save index before move
                // #endregion
                
                // Prevent memory leak: limit future_blocks size
                if self.future_blocks.len() >= MAX_FUTURE_BLOCKS {
                    // Remove oldest blocks (lowest index) to make room
                    let mut indices: Vec<u64> = self.future_blocks.keys().cloned().collect();
                    indices.sort();
                    // Remove 25% of oldest blocks
                    let to_remove = (MAX_FUTURE_BLOCKS / 4).max(1);
                    for i in 0..to_remove {
                        if i < indices.len() {
                            self.future_blocks.remove(&indices[i]);
                            warn!("Removed old future block {} to prevent memory leak (future_blocks limit: {})", indices[i], MAX_FUTURE_BLOCKS);
                        }
                    }
                }
                
                self.future_blocks.insert(block.index, block);
                // #region agent log
                let future_blocks_size_after = self.future_blocks.len();
                // Log if size increased or periodically (every 10 blocks)
                if future_blocks_size_after > future_blocks_size_before || future_blocks_size_after % 10 == 0 {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("/tmp/alfis-debug.log") {
                        let _ = writeln!(file, r#"{{"id":"future_blocks_insert","timestamp":{},"location":"p2p/network.rs:693","message":"Future blocks insert","data":{{"size_before":{},"size_after":{},"block_index":{}}},"sessionId":"debug-session","runId":"run1","hypothesisId":"B"}}"#, 
                            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64, 
                            future_blocks_size_before, future_blocks_size_after, block_index);
                    }
                }
                // #endregion
            }
            BlockQuality::Bad => {
                // TODO save bad public keys to banned table
                debug!("Ignoring bad block from {}:\n{:?}", peer.get_addr(), &block);
                let height = context.chain.get_height();
                if height + 1 == block.index {
                    context.chain.update_max_height(height);
                    post(crate::event::Event::SyncFinished);
                }
                return State::Banned;
            }
            BlockQuality::Rewind => {
                debug!("Got some orphan block, requesting its parent");
                return State::message(Message::GetBlock { index: block.index - 1 });
            }
            BlockQuality::Fork => {
                debug!("Got forked block {} with hash {:?}", block.index, block.hash);
                // If we are very much behind of blockchain
                let lagged = block.index == context.chain.get_height() && block.index + LIMITED_CONFIDENCE_DEPTH <= max_height;
                let our_block = context.chain.get_block(block.index).unwrap();
                if block.is_better_than(&our_block) || lagged {
                    context.chain.replace_block(block).expect("Error replacing block with fork");
                    let index = context.chain.get_height();
                    post(crate::event::Event::BlockchainChanged { index });
                } else {
                    debug!("Fork in not better than our block, dropping.");
                    return State::message(Message::block(our_block.index, our_block.as_bytes()));
                }
            }
        }
        State::idle()
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