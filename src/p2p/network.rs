extern crate serde;
extern crate serde_json;

use std::{io, thread};
use std::cmp::max;
use std::io::{Read, Write, Error};
use std::net::{IpAddr, Shutdown, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use mio::{Events, Interest, Poll, Registry, Token};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use rand::{random, RngCore, Rng};
use rand_old::prelude::thread_rng;
use x25519_dalek::{StaticSecret, PublicKey};

use crate::{Block, Context, p2p::Message, p2p::Peer, p2p::Peers, p2p::State};
use crate::blockchain::types::BlockQuality;
use crate::commons::*;
use crate::eventbus::{register, post};
use crate::crypto::Chacha;

const SERVER: Token = Token(0);

pub struct Network {
    context: Arc<Mutex<Context>>,
    secret_key: StaticSecret,
    public_key: PublicKey,
    token: Token,
    // States of peer connections, and some data to send when sockets become writable
    peers: Peers,
}

impl Network {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        // P2P encryption primitives
        let mut thread_rng = thread_rng();
        let secret_key = StaticSecret::new(&mut thread_rng);
        let public_key = PublicKey::from(&secret_key);
        let peers = Peers::new();
        Network { context, secret_key, public_key, token: Token(1), peers }
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

        let mut events = Events::with_capacity(64);
        let mut poll = Poll::new().expect("Unable to create poll");
        poll.registry().register(&mut server, SERVER, Interest::READABLE).expect("Error registering poll");

        // Starting peer connections to bootstrap nodes
        self.peers.connect_peers(&peers_addrs, &poll.registry(), &mut self.token, yggdrasil_only);

        let mut ui_timer = Instant::now();
        let mut log_timer = Instant::now();
        let mut bootstrap_timer = Instant::now();
        let mut connect_timer = Instant::now();
        let mut last_events_time = Instant::now();
        loop {
            if self.peers.get_peers_count() == 0 && bootstrap_timer.elapsed().as_secs() > 60 {
                warn!("Restarting swarm connections...");
                // Starting peer connections to bootstrap nodes
                self.peers.connect_peers(&peers_addrs, &poll.registry(), &mut self.token, yggdrasil_only);
                bootstrap_timer = Instant::now();
                last_events_time = Instant::now();
            }
            // Poll Mio for events, blocking until we get an event.
            poll.poll(&mut events, POLL_TIMEOUT).expect("Error polling sockets");
            if !running.load(Ordering::SeqCst) {
                break;
            }

            // Process each event.
            for event in events.iter() {
                //trace!("Event for socket {} is {:?}", event.token().0, &event);
                // We can use the token we previously provided to `register` to determine for which socket the event is.
                match event.token() {
                    SERVER => {
                        //debug!("Event for server socket {} is {:?}", event.token().0, &event);
                        // If this is an event for the server, it means a connection is ready to be accepted.
                        let connection = server.accept();
                        match connection {
                            Ok((mut stream, mut address)) => {
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
                                    continue;
                                }

                                if yggdrasil_only && !is_yggdrasil(&address.ip()) {
                                    debug!("Dropping connection from Internet");
                                    stream.shutdown(Shutdown::Both).unwrap_or_else(|e|{ warn!("Error in shutdown, {}", e); });
                                    let _ = poll.registry().reregister(&mut server, SERVER, Interest::READABLE);
                                    continue;
                                }

                                //debug!("Accepted connection from: {} to local IP: {}", address, local_ip);
                                let token = self.next_token();
                                poll.registry().register(&mut stream, token, Interest::READABLE).expect("Error registering poll");
                                let peer = Peer::new(address, stream, State::Connected, true);
                                self.peers.add_peer(token, peer);
                            }
                            Err(_) => {}
                        }
                        if let Err(e) = poll.registry().reregister(&mut server, SERVER, Interest::READABLE) {
                            panic!("Error reregistering server token!\n{}", e);
                        }
                    }
                    token => {
                        if !self.handle_connection_event(&poll.registry(), &event) {
                            let _ = self.peers.close_peer(poll.registry(), &token);
                            let blocks = self.context.lock().unwrap().chain.get_height();
                            let keys =  self.context.lock().unwrap().chain.get_users_count();
                            let domains =  self.context.lock().unwrap().chain.get_domains_count();
                            post(crate::event::Event::NetworkStatus { blocks, domains, keys, nodes: self.peers.get_peers_active_count() });
                        }
                    }
                }
            }
            if !events.is_empty() {
                last_events_time = Instant::now();
            } else if last_events_time.elapsed().as_secs() > MAX_IDLE_SECONDS {
                if self.peers.get_peers_count() > 0 {
                    warn!("Something is wrong with swarm connections, closing all.");
                    self.peers.close_all_peers(poll.registry());
                    continue;
                } else {
                    thread::sleep(POLL_TIMEOUT.unwrap());
                }
            }

            if ui_timer.elapsed().as_millis() > UI_REFRESH_DELAY_MS {
                // Send pings to idle peers
                let (height, hash) = {
                    let context = self.context.lock().unwrap();
                    let blocks = context.chain.get_height();
                    let nodes = self.peers.get_peers_active_count();
                    let banned = self.peers.get_peers_banned_count();

                    let keys =  context.chain.get_users_count();
                    let domains =  context.chain.get_domains_count();
                    post(crate::event::Event::NetworkStatus { blocks, domains, keys, nodes });

                    if log_timer.elapsed().as_secs() > LOG_REFRESH_DELAY_SEC {
                        info!("Active nodes count: {}, banned count: {}, blocks count: {}", nodes, banned, blocks);
                        let elapsed = last_events_time.elapsed().as_secs();
                        if elapsed >= 10 {
                            warn!("Last network events time {} seconds ago", elapsed);
                        }
                        log_timer = Instant::now();
                    }
                    if nodes < MAX_NODES && connect_timer.elapsed().as_secs() >= 5 {
                        self.peers.connect_new_peers(poll.registry(), &mut self.token, yggdrasil_only);
                        connect_timer = Instant::now();
                    }
                    (blocks, context.chain.get_last_hash())
                };
                self.peers.update(poll.registry(), height, hash);
                ui_timer = Instant::now();
            }
        }
        if !running.load(Ordering::SeqCst) {
            info!("Network loop finished");
        } else {
            panic!("Network loop has broken prematurely!");
        }
    }

    fn handle_connection_event(&mut self, registry: &Registry, event: &Event) -> bool {
        if event.is_error() || (event.is_read_closed() && event.is_write_closed()) {
            return false;
        }

        if event.is_readable() {
            let data = {
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
                        match peer.get_state().clone() {
                            State::Connected => {
                                let mut stream = peer.get_stream();
                                return match read_client_handshake(&mut stream) {
                                    Ok(key) => {
                                        let mut buf = [0u8; 32];
                                        buf.copy_from_slice(key.as_slice());
                                        let public_key: PublicKey = PublicKey::from(buf);
                                        let shared = self.secret_key.diffie_hellman(&public_key);
                                        let mut nonce = [0u8; 12];
                                        let mut rng = rand::thread_rng();
                                        rng.fill(&mut nonce);
                                        let chacha = Chacha::new(shared.as_bytes(), &nonce);
                                        registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                                        std::mem::drop(stream);
                                        peer.set_cipher(chacha);
                                        peer.set_state(State::ServerHandshake);
                                        info!("Client hello read successfully");
                                        true
                                    }
                                    Err(e) => {
                                        warn!("Error reading client handshake. {}", e);
                                        false
                                    }
                                }
                            }
                            State::ServerHandshake => {
                                let mut stream = peer.get_stream();
                                return match read_server_handshake(&mut stream) {
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
                                        std::mem::drop(stream);
                                        peer.set_cipher(chacha);
                                        peer.set_state(State::HandshakeFinished);
                                        info!("Server hello read successfully");
                                        true
                                    }
                                    Err(e) => {
                                        warn!("Error reading server handshake. {}", e);
                                        false
                                    }
                                }
                            }
                            _ => {
                                let mut stream = peer.get_stream();
                                read_message(&mut stream)
                            }
                        }
                    }
                }
            };

            if data.is_ok() {
                let data = {
                    match self.peers.get_peer(&event.token()) {
                        Some(peer) => {
                            let data = data.unwrap();
                            //info!("Decoding message {:?}", to_hex(data.as_slice()));
                            match decode_message(&data, peer.get_cipher()) {
                                Ok(data) => {
                                    data
                                }
                                Err(_) => {
                                    vec![]
                                }
                            }
                        }
                        None => {
                            vec![]
                        }
                    }
                };
                match Message::from_bytes(data) {
                    Ok(message) => {
                        let m = format!("{:?}", &message);
                        let new_state = self.handle_message(message, &event.token());
                        let peer = self.peers.get_mut_peer(&event.token()).unwrap();
                        debug!("Got message from {}: {:?}", &peer.get_addr(), &m);
                        let stream = peer.get_stream();
                        match new_state {
                            State::Message { data } => {
                                registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                                peer.set_state(State::Message { data });
                            }
                            State::Connecting => {}
                            State::Connected => {}
                            State::ServerHandshake => {}
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
                                registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                                peer.set_state(State::SendLoop);
                            }
                            State::Twin => {
                                peer.set_state(State::Twin);
                                // TODO set something in [Peers], maybe ignore this IP?
                                return false;
                            }
                        }
                    }
                    Err(_) => {
                        let peer = self.peers.get_peer(&event.token()).unwrap();
                        warn!("Error deserializing message from {}", &peer.get_addr());
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        if event.is_writable() {
            let my_id = self.peers.get_my_id().to_owned();
            match self.peers.get_mut_peer(&event.token()) {
                None => {}
                Some(peer) => {
                    match peer.get_state().clone() {
                        State::Connecting => {
                            if send_client_handshake(&mut peer.get_stream(), self.public_key.as_bytes()).is_err() {
                                return false;
                            }
                            peer.set_state(State::ServerHandshake);
                        }
                        State::ServerHandshake => {
                            if send_server_handshake(peer, self.public_key.as_bytes()).is_err() {
                                return false;
                            }
                            peer.set_state(State::HandshakeFinished);
                            info!("Server handshake sent");
                        }
                        State::HandshakeFinished => {
                            //debug!("Connected to peer {}, sending hello...", &peer.get_addr());
                            let data: Vec<u8> = {
                                let c = self.context.lock().unwrap();
                                let message = Message::hand(&c.app_version, &c.settings.origin, CHAIN_VERSION, c.settings.net.public, &my_id);
                                info!("Sending: {:?}", &message);
                                encode_message(&message, peer.get_cipher()).unwrap()
                            };
                            send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending hello {}", e));
                            //debug!("Sent hello to {}", &peer.get_addr());
                        }
                        State::Connected => {}
                        State::Message { data } => {
                            //debug!("Sending data to {}: {}", &peer.get_addr(), &String::from_utf8(data.clone()).unwrap());
                            let data = encode_bytes(&data, peer.get_cipher());
                            send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending message {}", e));
                        }
                        State::Idle { from } => {
                            debug!("Odd version of pings :)");
                            if from.elapsed().as_secs() >= 30 {
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
                        }
                        State::Twin => {
                            let data = encode_message(&Message::Twin, peer.get_cipher()).unwrap();
                            send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending loop {}", e));
                        }
                    }
                    registry.reregister(peer.get_stream(), event.token(), Interest::READABLE).unwrap();
                }
            }
        }

        true
    }

    fn handle_message(&mut self, message: Message, token: &Token) -> State {
        let (my_height, my_hash, my_origin, my_version, me_public) = {
            let context = self.context.lock().unwrap();
            // TODO cache it somewhere
            (context.chain.get_height(), context.chain.get_last_hash(), &context.settings.origin.clone(), CHAIN_VERSION, context.settings.net.public)
        };
        let my_id = self.peers.get_my_id().to_owned();
        let answer = match message {
            Message::Hand { app_version, origin, version, public, rand_id } => {
                if self.peers.is_our_own_connect(&rand_id) {
                    warn!("Detected loop connect");
                    State::SendLoop
                } else {
                    if origin.eq(my_origin) && version == my_version {
                        let peer = self.peers.get_mut_peer(token).unwrap();
                        peer.set_public(public);
                        peer.set_active(true);
                        debug!("Incoming v{} on {}", &app_version, peer.get_addr().ip());
                        let app_version = self.context.lock().unwrap().app_version.clone();
                        State::message(Message::shake(&app_version, &origin, version, me_public, &my_id, my_height))
                    } else {
                        warn!("Handshake from unsupported chain or version");
                        State::Banned
                    }
                }
            }
            Message::Shake { app_version, origin, version, public, rand_id, height } => {
                if origin.ne(my_origin) || version != my_version {
                    return State::Banned;
                }
                if self.peers.is_tween_connect(&rand_id) {
                    return State::Twin;
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
            Message::Error => { State::Error }
            Message::Ping { height, hash } => {
                let peer = self.peers.get_mut_peer(token).unwrap();
                peer.set_height(height);
                peer.set_active(true);
                if peer.is_higher(my_height) {
                    let mut context = self.context.lock().unwrap();
                    context.chain.update_max_height(height);
                    info!("Peer is higher, requesting block {} from {}", height, peer.get_addr().ip());
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
                if peer.is_higher(my_height) {
                    let mut context = self.context.lock().unwrap();
                    context.chain.update_max_height(height);
                    info!("Peer is higher, requesting block {} from {}", height, peer.get_addr().ip());
                    State::message(Message::GetBlock { index: my_height + 1 })
                } else if my_height == height && hash.ne(&my_hash) {
                    info!("Hashes are different, requesting block {} from {}", my_height, peer.get_addr().ip());
                    info!("My hash: {:?}, their hash: {:?}", &my_hash, &hash);
                    State::message(Message::GetBlock { index: my_height })
                } else {
                    if active_count < MAX_NODES && random::<u8>() < 50 {
                        debug!("Requesting more peers from {}", peer.get_addr().ip());
                        State::message(Message::GetPeers)
                    } else {
                        State::idle()
                    }
                }
            }
            Message::GetPeers => {
                let addr = {
                    let peer = self.peers.get_mut_peer(token).unwrap();
                    peer.set_active(true);
                    peer.get_addr().clone()
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
                        return State::Banned
                    }
                };
                if index != block.index {
                    return State::Banned;
                }
                info!("Received block {} with hash {:?}", block.index, &block.hash);
                self.handle_block(token, block)
            }
            Message::Twin => { State::Twin }
            Message::Loop => { State::Loop }
        };
        answer
    }

    fn handle_block(&mut self, token: &Token, block: Block) -> State {
        let peers_count = self.peers.get_peers_active_count();
        let peer = self.peers.get_mut_peer(token).unwrap();
        peer.set_received_block(block.index);

        let mut context = self.context.lock().unwrap();
        let max_height = context.chain.max_height();
        match context.chain.check_new_block(&block) {
            BlockQuality::Good => {
                context.chain.add_block(block);
                let my_height = context.chain.get_height();
                post(crate::event::Event::BlockchainChanged { index: my_height });
                // If it was the last block to sync
                if my_height == max_height {
                    post(crate::event::Event::SyncFinished);
                } else {
                    let event = crate::event::Event::Syncing { have: my_height, height: max(max_height, my_height) };
                    post(event);
                }
                let domains = context.chain.get_domains_count();
                let keys = context.chain.get_users_count();
                post(crate::event::Event::NetworkStatus { blocks: my_height, domains, keys, nodes: peers_count });
                // To load blocks from different nodes we randomize requests of new blocks
                // TODO rethink this approach
                if max_height > my_height && random::<u8>() < 200 {
                    return State::message(Message::GetBlock { index: my_height + 1 });
                }
            }
            BlockQuality::Twin => { debug!("Ignoring duplicate block {}", block.index); }
            BlockQuality::Future => { debug!("Ignoring future block {}", block.index); }
            BlockQuality::Bad => {
                // TODO save bad public keys to banned table
                debug!("Ignoring bad block from {}:\n{:?}", peer.get_addr(), &block);
                let height = context.chain.get_height();
                context.chain.update_max_height(height);
                post(crate::event::Event::SyncFinished);
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
                let last_block = context.chain.last_block().unwrap();
                if block.is_better_than(&last_block) || lagged {
                    context.chain.replace_block(block).expect("Error replacing block with fork");
                    let index = context.chain.get_height();
                    post(crate::event::Event::BlockchainChanged { index });
                } else {
                    debug!("Fork in not better than our block, dropping.");
                    if let Some(block) = context.chain.get_block(block.index) {
                        return State::message(Message::block(block.index, block.as_bytes()));
                    }
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
        match e {
            Event::ActionQuit => {
                running.store(false, Ordering::SeqCst);
                return false;
            }
            _ => {}
        }
        true
    });
}


fn encode_bytes(data: &Vec<u8>, cipher: &Option<Chacha>) -> Vec<u8> {
    match cipher {
        None => { data.clone() }
        Some(chacha) => {
            chacha.encrypt(data.as_slice())
        }
    }
}

fn encode_message(message: &Message, cipher: &Option<Chacha>) -> Result<Vec<u8>, ()> {
    match serde_cbor::to_vec(message) {
        Ok(vec) => {
            match cipher {
                None => {
                    //info!("No cipher, not encoding message: {:?}", to_hex(&vec));
                    Ok(vec)
                }
                Some(chacha) => {
                    //info!("Encoding message: {:?}", to_hex(&vec));
                    Ok(chacha.encrypt(vec.as_slice()))
                }
            }
        }
        Err(e) => {
            warn!("Could not encode message! {}", e);
            Err(())
        }
    }
}

fn decode_message(data: &Vec<u8>, cipher: &Option<Chacha>) -> Result<Vec<u8>, Error> {
    match cipher {
        None => { Ok(data.clone()) }
        Some(chacha) => {
            Ok(chacha.decrypt(data.as_slice()))
        }
    }
}

fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>, ()> {
    let instant = Instant::now();
    let data_size = match stream.read_u16::<BigEndian>() {
        Ok(size) => { (size ^ 0xAAAA) as usize }
        Err(e) => {
            error!("Error reading from socket! {}", e);
            0
        }
    };
    trace!("Payload size is {}", data_size);
    if data_size > MAX_PACKET_SIZE || data_size == 0 {
        return Err(());
    }

    let mut buf = vec![0u8; data_size];
    let mut bytes_read = 0;
    loop {
        match stream.read(&mut buf[bytes_read..]) {
            Ok(bytes) => {
                bytes_read += bytes;
                if bytes_read == data_size {
                    break;
                }
            }
            // Would block "errors" are the OS's way of saying that the connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => {
                // We give every connection no more than 200ms to read a message
                if instant.elapsed().as_millis() < MAX_READ_BLOCK_TIME {
                    // We need to sleep a bit, otherwise it can eat CPU
                    let delay = Duration::from_millis(2);
                    thread::sleep(delay);
                    continue;
                } else {
                    break;
                }
            },
            Err(ref err) if interrupted(err) => continue,
            // Other errors we'll consider fatal.
            Err(_) => {
                debug!("Error reading message, only {}/{} bytes read", bytes_read, data_size);
                return Err(())
            },
        }
    }
    if buf.len() == data_size {
        Ok(buf)
    } else {
        Err(())
    }
}

/// Sends one byte [garbage_size], [random bytes], and [public_key]
fn send_client_handshake(stream: &mut TcpStream, public_key: &[u8]) -> io::Result<()> {
    let mut rng = rand::thread_rng();
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
    // First, we read garbage size
    let data_size = match stream.read_u8() {
        Ok(size) => { (size ^ 0xA) as usize }
        Err(e) => {
            error!("Error reading from socket! {}", e);
            return Err(e)
        }
    };
    // Read the garbage
    let mut buf = vec![0u8; data_size];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(e) => { return Err(e); }
    }
    // Then we have public key for ECDH
    let mut buf = vec![0u8; 32];
    match stream.read_exact(&mut buf) {
        Ok(_) => { Ok(buf) }
        Err(e) => {
            warn!("Error reading handshake!");
            Err(e)
        }
    }
}

fn send_server_handshake(peer: &mut Peer, public_key: &[u8]) -> io::Result<()> {
    let mut rng = rand::thread_rng();
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
    // First, we read garbage size
    let data_size = match stream.read_u8() {
        Ok(size) => { (size ^ 0xA) as usize }
        Err(e) => {
            error!("Error reading from socket! {}", e);
            return Err(e)
        }
    };
    // Read the garbage
    let mut buf = vec![0u8; data_size];
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(e) => { return Err(e); }
    }
    // Then we have public key for ECDH, plus nonce 12 bytes
    let mut buf = vec![0u8; 32 + 12];
    match stream.read_exact(&mut buf) {
        Ok(_) => { Ok(buf) }
        Err(e) => {
            warn!("Error reading handshake!");
            Err(e)
        }
    }
}

fn send_message(connection: &mut TcpStream, data: &Vec<u8>) -> io::Result<()> {
    let data_len = data.len() as u16;
    //debug!("Sending {} bytes", data_len);
    //debug!("Message: {:?}", to_hex(&data));
    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 2);
    buf.write_u16::<BigEndian>(data_len ^ 0xAAAA)?;
    buf.write_all(&data)?;
    connection.write_all(&buf)?;
    connection.flush()
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}
