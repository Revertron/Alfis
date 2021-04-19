extern crate serde;
extern crate serde_json;

use std::{io, thread};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use mio::{Events, Interest, Poll, Registry, Token};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use rand::random;

use crate::{Block, Context, p2p::Message, p2p::Peer, p2p::Peers, p2p::State};
use crate::blockchain::types::BlockQuality;
use crate::commons::*;

const SERVER: Token = Token(0);
const POLL_TIMEOUT: Option<Duration> = Some(Duration::from_millis(1000));
const MAX_PACKET_SIZE: usize = 1 * 1024 * 1024; // 1 Mb
const MAX_READ_BLOCK_TIME: u128 = 500;

pub struct Network {
    context: Arc<Mutex<Context>>
}

impl Network {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        Network { context }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let (listen_addr, peers_addrs, yggdrasil_only) = {
            let c = self.context.lock().unwrap();
            (c.settings.net.listen.clone(), c.settings.net.peers.clone(), c.settings.net.yggdrasil_only)
        };

        let running = Arc::new(AtomicBool::new(true));
        subscribe_to_bus(&mut self.context, Arc::clone(&running));

        // Starting server socket
        let addr = listen_addr.parse().expect("Error parsing listen address");
        let mut server = TcpListener::bind(addr).expect("Can't bind to address");
        debug!("Started node listener on {}", server.local_addr().unwrap());

        let mut events = Events::with_capacity(1024);
        let mut poll = Poll::new().expect("Unable to create poll");
        poll.registry().register(&mut server, SERVER, Interest::READABLE).expect("Error registering poll");
        let context = Arc::clone(&self.context);
        thread::spawn(move || {
            // Give UI some time to appear :)
            thread::sleep(Duration::from_millis(2000));
            // Unique token for each incoming connection.
            let mut unique_token = Token(SERVER.0 + 1);
            // States of peer connections, and some data to send when sockets become writable
            let mut peers = Peers::new();
            // Starting peer connections to bootstrap nodes
            peers.connect_peers(&peers_addrs, &poll.registry(), &mut unique_token, yggdrasil_only);

            let mut ui_timer = Instant::now();
            let mut log_timer = Instant::now();
            let mut bootstrap_timer = Instant::now();
            let mut last_events_time = Instant::now();
            loop {
                if peers.get_peers_count() == 0 && bootstrap_timer.elapsed().as_secs() > 60 {
                    // Starting peer connections to bootstrap nodes
                    peers.connect_peers(&peers_addrs, &poll.registry(), &mut unique_token, yggdrasil_only);
                    bootstrap_timer = Instant::now();
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

                                    if yggdrasil_only && !is_yggdrasil(&address.ip()) {
                                        debug!("Dropping connection from Internet");
                                        stream.shutdown(Shutdown::Both).unwrap_or_else(|e|{ warn!("Error in shutdown, {}", e); });
                                        let _ = poll.registry().reregister(&mut server, SERVER, Interest::READABLE);
                                        continue;
                                    }

                                    // If connection is from the same IP and not from loopback we ignore it to avoid connection loops
                                    let local_ip = stream.local_addr().unwrap_or("0.0.0.0:0".parse().unwrap());
                                    if !local_ip.ip().is_loopback() && local_ip.ip() == address.ip() {
                                        peers.ignore_ip(&address.ip());
                                        stream.shutdown(Shutdown::Both).unwrap_or_else(|e|{ warn!("Error in shutdown, {}", e); });
                                        warn!("Detected connection loop, ignoring IP: {}", &address.ip());
                                    } else {
                                        //debug!("Accepted connection from: {} to local IP: {}", address, local_ip);
                                        let token = next(&mut unique_token);
                                        poll.registry().register(&mut stream, token, Interest::READABLE).expect("Error registering poll");
                                        peers.add_peer(token, Peer::new(address, stream, State::Connected, true));
                                    }
                                }
                                Err(_) => {}
                            }
                            match poll.registry().reregister(&mut server, SERVER, Interest::READABLE) {
                                Ok(_) => {}
                                Err(e) => {
                                    panic!("Error reregistering server token!\n{}", e);
                                }
                            }
                        }
                        token => {
                            if !handle_connection_event(Arc::clone(&context), &mut peers, &poll.registry(), &event) {
                                let _ = peers.close_peer(poll.registry(), &token);
                                let mut context = context.lock().unwrap();
                                let blocks_count = context.chain.height();
                                context.bus.post(crate::event::Event::NetworkStatus { nodes: peers.get_peers_active_count(), blocks: blocks_count });
                            }
                        }
                    }
                }
                if !events.is_empty() {
                    last_events_time = Instant::now();
                }
                events.clear();

                if ui_timer.elapsed().as_millis() > UI_REFRESH_DELAY_MS {
                    // Send pings to idle peers
                    let (height, hash) = {
                        let mut context = context.lock().unwrap();
                        let height = context.chain.height();
                        let nodes = peers.get_peers_active_count();
                        let banned = peers.get_peers_banned_count();
                        if nodes > 0 {
                            context.bus.post(crate::event::Event::NetworkStatus { nodes, blocks: height });
                        }
                        if log_timer.elapsed().as_secs() > LOG_REFRESH_DELAY_SEC {
                            info!("Active nodes count: {}, banned count: {}, blocks count: {}", nodes, banned, height);
                            let elapsed = last_events_time.elapsed().as_secs();
                            if elapsed >= 10 {
                                warn!("Last network events time {} seconds ago", elapsed);
                            }
                            log_timer = Instant::now();
                            let keystore = context.keystore.clone();
                            if let Some(event) = context.chain.update(&keystore) {
                                context.bus.post(event);
                            }
                        }
                        (height, context.chain.last_hash())
                    };
                    peers.update(poll.registry(), height, hash);
                    peers.connect_new_peers(poll.registry(), &mut unique_token, yggdrasil_only);
                    ui_timer = Instant::now();
                }
            }
            if !running.load(Ordering::SeqCst) {
                info!("Network loop finished");
            } else {
                panic!("Network loop has broken prematurely!");
            }
        });
        Ok(())
    }
}

fn subscribe_to_bus(context: &mut Arc<Mutex<Context>>, running: Arc<AtomicBool>) {
    use crate::event::Event;
    context.lock().unwrap().bus.register(move |_uuid, e| {
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

fn handle_connection_event(context: Arc<Mutex<Context>>, peers: &mut Peers, registry: &Registry, event: &Event) -> bool {
    if event.is_error() || (event.is_read_closed() && event.is_write_closed()) {
        return false;
    }

    if event.is_readable() {
        let data = {
            let token = event.token();
            match peers.get_mut_peer(&token) {
                None => {
                    error!("Error getting peer for connection {}", token.0);
                    return false;
                }
                Some(peer) => {
                    if event.is_read_closed() {
                        //debug!("Spurious wakeup for connection {}, ignoring", token.0);
                        if peer.spurious() >= 3 {
                            //debug!("Disconnecting socket on 3 spurious wakeups");
                            return false;
                        }
                        let interest = if let State::Message{..} = peer.get_state() {
                            Interest::WRITABLE
                        } else {
                            Interest::READABLE
                        };
                        let stream = peer.get_stream();
                        registry.reregister(stream, token, interest).unwrap();
                        peer.inc_spurious();
                        return true;
                    }
                    peer.reset_spurious();
                    let mut stream = peer.get_stream();
                    read_message(&mut stream)
                }
            }
        };

        if data.is_ok() {
            let data = data.unwrap();
            match Message::from_bytes(data) {
                Ok(message) => {
                    //let m = format!("{:?}", &message);
                    let new_state = handle_message(Arc::clone(&context), message, peers, &event.token());
                    let peer = peers.get_mut_peer(&event.token()).unwrap();
                    //debug!("Got message from {}: {:?}", &peer.get_addr(), &m);
                    let stream = peer.get_stream();
                    match new_state {
                        State::Message { data } => {
                            registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                            peer.set_state(State::Message { data });
                        }
                        State::Connecting => {}
                        State::Connected => {}
                        State::Idle { .. } => {
                            peer.set_state(State::idle());
                        }
                        State::Error => {}
                        State::Banned => {
                            peers.ignore_peer(registry, &event.token());
                        }
                        State::Offline { .. } => {
                            peer.set_state(State::offline());
                        }
                    }
                }
                Err(_) => { return false; }
            }
        } else {
            return false;
        }
    }

    if event.is_writable() {
        //trace!("Socket {} is writable", event.token().0);
        let my_id = peers.get_my_id().to_owned();
        match peers.get_mut_peer(&event.token()) {
            None => {}
            Some(peer) => {
                match peer.get_state().clone() {
                    State::Connecting => {
                        //debug!("Connected to peer {}, sending hello...", &peer.get_addr());
                        let data: String = {
                            let c = context.lock().unwrap();
                            let message = Message::hand(&c.app_version, &c.settings.origin, CHAIN_VERSION, c.settings.net.public, &my_id);
                            serde_json::to_string(&message).unwrap()
                        };
                        send_message(peer.get_stream(), &data.into_bytes()).unwrap_or_else(|e| warn!("Error sending hello {}", e));
                        //debug!("Sent hello to {}", &peer.get_addr());
                    }
                    State::Message { data } => {
                        //debug!("Sending data to {}: {}", &peer.get_addr(), &String::from_utf8(data.clone()).unwrap());
                        send_message(peer.get_stream(), &data).unwrap_or_else(|e| warn!("Error sending message {}", e));
                    }
                    State::Connected => {}
                    State::Idle { from } => {
                        debug!("Odd version of pings :)");
                        if from.elapsed().as_secs() >= 30 {
                            let data: String = {
                                let c = context.lock().unwrap();
                                let message = Message::ping(c.chain.height(), c.chain.last_hash());
                                serde_json::to_string(&message).unwrap()
                            };
                            send_message(peer.get_stream(), &data.into_bytes()).unwrap_or_else(|e| warn!("Error sending ping {}", e));
                        }
                    }
                    State::Error => {}
                    State::Banned => {}
                    State::Offline { .. } => {}
                }
                registry.reregister(peer.get_stream(), event.token(), Interest::READABLE).unwrap();
            }
        }
    }

    true
}

fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>, ()> {
    let instant = Instant::now();
    let data_size = match stream.read_u32::<BigEndian>() {
        Ok(size) => { size as usize }
        Err(e) => {
            error!("Error reading from socket! {}", e);
            0
        }
    };
    //trace!("Payload size is {}", data_size);
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
                // We give every connection no more than 500ms to read a message
                if instant.elapsed().as_millis() < MAX_READ_BLOCK_TIME {
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

fn send_message(connection: &mut TcpStream, data: &Vec<u8>) -> io::Result<()> {
    connection.write_u32::<BigEndian>(data.len() as u32)?;
    connection.write_all(&data)?;
    connection.flush()
}

fn handle_message(context: Arc<Mutex<Context>>, message: Message, peers: &mut Peers, token: &Token) -> State {
    let (my_height, my_hash, my_origin, my_version) = {
        let context = context.lock().unwrap();
        // TODO cache it somewhere
        (context.chain.height(), context.chain.last_hash(), &context.settings.origin.clone(), CHAIN_VERSION)
    };
    let answer = match message {
        Message::Hand { app_version, origin, version, public, rand} => {
            if peers.is_our_own_connect(&rand) {
                warn!("Detected loop connect");
                State::Banned
            } else {
                if origin.eq(my_origin) && version == my_version {
                    let peer = peers.get_mut_peer(token).unwrap();
                    peer.set_public(public);
                    debug!("Hello from v{} on {}", &app_version, peer.get_addr().ip());
                    State::message(Message::shake(&origin, version, true, my_height))
                } else {
                    warn!("Handshake from unsupported chain or version");
                    State::Banned
                }
            }
        }
        Message::Shake { origin, version, ok, height } => {
            if origin.ne(my_origin) || version != my_version {
                return State::Banned;
            }
            if ok {
                let active_count = peers.get_peers_active_count();
                let peer = peers.get_mut_peer(token).unwrap();
                peer.set_height(height);
                peer.set_active(true);
                peer.reset_reconnects();
                let mut context = context.lock().unwrap();
                if peer.is_higher(my_height) {
                    context.chain.update_max_height(height);
                    context.bus.post(crate::event::Event::Syncing { have: my_height, height});
                    if active_count > 3 {
                        State::idle()
                    } else {
                        State::message(Message::GetPeers)
                    }
                } else {
                    State::message(Message::GetPeers)
                }
            } else {
                State::Banned
            }
        }
        Message::Error => { State::Error }
        Message::Ping { height, hash } => {
            let peer = peers.get_mut_peer(token).unwrap();
            peer.set_height(height);
            peer.set_active(true);
            if peer.is_higher(my_height) {
                let mut context = context.lock().unwrap();
                context.chain.update_max_height(height);
            }
            if hash != my_hash {
                State::message(Message::GetBlock { index: my_height })
            } else {
                State::message(Message::pong(my_height, my_hash))
            }
        }
        Message::Pong { height, hash } => {
            let peer = peers.get_mut_peer(token).unwrap();
            peer.set_height(height);
            peer.set_active(true);
            if peer.is_higher(my_height) {
                let mut context = context.lock().unwrap();
                context.chain.update_max_height(height);
            }
            if hash != my_hash {
                State::message(Message::GetBlock { index: my_height })
            } else {
                if random::<u8>() < 10 {
                    debug!("Requesting more peers from {}", peer.get_addr().ip());
                    State::message(Message::GetPeers)
                } else {
                    State::idle()
                }
            }
        }
        Message::GetPeers => {
            let peer = peers.get_peer(token).unwrap();
            State::message(Message::Peers { peers: peers.get_peers_for_exchange(&peer.get_addr()) })
        }
        Message::Peers { peers: new_peers } => {
            peers.add_peers_from_exchange(new_peers);
            State::idle()
        }
        Message::GetBlock { index } => {
            let context = context.lock().unwrap();
            match context.chain.get_block(index) {
                Some(block) => State::message(Message::block(block.index, serde_json::to_string(&block).unwrap())),
                None => State::Error
            }
        }
        Message::Block { index, block } => {
            info!("Received block {}", index);
            let block: Block = match serde_json::from_str(&block) {
                Ok(block) => block,
                Err(_) => return State::Error
            };
            process_new_block(context, peers, token, block)
        }
    };
    answer
}

fn process_new_block(context: Arc<Mutex<Context>>, peers: &mut Peers, token: &Token, block: Block) -> State {
    let peers_count = peers.get_peers_active_count();
    let peer = peers.get_mut_peer(token).unwrap();
    peer.set_received_block(block.index);
    if let Some(transaction) = &block.transaction {
        if context.lock().unwrap().x_zones.has_hash(&transaction.identity.to_string()) {
            // This peer has mined some of the forbidden zones
            return State::Banned;
        }
    }

    let mut context = context.lock().unwrap();
    let max_height = context.chain.max_height();
    match context.chain.check_new_block(&block) {
        BlockQuality::Good => {
            context.chain.add_block(block);
            let keystore = context.keystore.clone();
            if let Some(event) = context.chain.update(&keystore) {
                context.bus.post(event);
            }
            let my_height = context.chain.height();
            context.bus.post(crate::event::Event::BlockchainChanged { index: my_height });
            // If it was the last block to sync
            if my_height == max_height {
                context.bus.post(crate::event::Event::SyncFinished);
            } else {
                context.bus.post(crate::event::Event::Syncing { have: my_height, height: max_height });
            }
            context.bus.post(crate::event::Event::NetworkStatus { nodes: peers_count, blocks: my_height });
        }
        BlockQuality::Twin => { debug!("Ignoring duplicate block {}", block.index); }
        BlockQuality::Future => { debug!("Ignoring future block {}", block.index); }
        BlockQuality::Bad => {
            // TODO save bad public keys to banned table
            debug!("Ignoring bad block {} with hash {:?} from {}", block.index, block.hash, peer.get_addr());
            let height = context.chain.height();
            context.chain.update_max_height(height);
            context.bus.post(crate::event::Event::SyncFinished);
            return State::Banned;
        }
        BlockQuality::Fork => {
            debug!("Got forked block {} with hash {:?}", block.index, block.hash);
            let last_block = context.chain.last_block().unwrap();
            if block.is_better_than(&last_block) {
                context.chain.replace_block(block.index, block).expect("Error replacing block with fork");
                let keystore = context.keystore.clone();
                if let Some(event) = context.chain.update(&keystore) {
                    context.bus.post(event);
                }
                let index = context.chain.height();
                context.bus.post(crate::event::Event::BlockchainChanged { index });
            }
            let height = context.chain.height();
            context.chain.update_max_height(height);
            context.bus.post(crate::event::Event::SyncFinished);
        }
    }
    State::idle()
}

#[allow(dead_code)]
fn deal_with_fork(context: MutexGuard<Context>, peer: &mut Peer, block: Block) {
    peer.add_fork_block(block);
    let mut vector: Vec<&Block> = peer.get_fork().values().collect();
    vector.sort_by(|a, b| a.index.cmp(&b.index));
    if vector[0].index == 0 {
        return;
    }
    if let Some(prev_block) = context.chain.get_block(vector[0].index - 1) {
        // If this block is not root of the fork (we need to go ~deeper~ more backwards)
        if vector[0].prev_block_hash != prev_block.hash {
            return;
        }
        // Okay, prev_block is the common root for our chain and the fork
        let mut check_ok = true;
        vector.insert(0, &prev_block);
        let mut prev_block = &vector[0];
        for block in &vector {
            if block == prev_block {
                continue;
            }
            if !check_block(block, prev_block) {
                check_ok = false;
                break;
            }
            prev_block = block;
        }
        match check_ok {
            true => {
                // TODO count fork chain "work" and decide which chain is "better"
            }
            false => {
                warn!("Fork chain is wrong!");
                peer.set_state(State::Banned);
            }
        }
    };
}

fn check_block(block: &Block, prev: &Block) -> bool {
    prev.index == block.index - 1 && prev.hash == block.prev_block_hash
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}
