extern crate serde;
extern crate serde_json;

use std::{io, thread};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use mio::{Events, Interest, Poll, Registry, Token};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

use crate::{Context, Block, p2p::Message, p2p::State, p2p::Peer, p2p::Peers, Bytes};
use std::net::{SocketAddr, IpAddr, SocketAddrV4, ToSocketAddrs};
use crate::blockchain::enums::BlockQuality;
use crate::blockchain::CHAIN_VERSION;
use std::collections::HashSet;

const SERVER: Token = Token(0);
const POLL_TIMEOUT: Option<Duration> = Some(Duration::from_millis(3000));
pub const LISTEN_PORT: u16 = 4244;
const MAX_PACKET_SIZE: usize = 10 * 1024 * 1024; // 10 Mb
const MAX_READ_BLOCK_TIME: u128 = 500;

pub struct Network {
    context: Arc<Mutex<Context>>
}

impl Network {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        Network { context }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let (listen_addr, peers_addrs) = {
            let c = self.context.lock().unwrap();
            (c.settings.listen.clone(), c.settings.peers.clone())
        };

        // Starting server socket
        let addr = listen_addr.parse().expect("Error parsing listen address");
        let mut server = TcpListener::bind(addr).expect("Can't bind to address");
        debug!("Started node listener on {}", server.local_addr().unwrap());

        let mut events = Events::with_capacity(64);
        let mut poll = Poll::new().expect("Unable to create poll");
        poll.registry().register(&mut server, SERVER, Interest::READABLE).expect("Error registering poll");
        let context = self.context.clone();
        thread::spawn(move || {
            // Give UI some time to appear :)
            thread::sleep(Duration::from_millis(2000));
            // Unique token for each incoming connection.
            let mut unique_token = Token(SERVER.0 + 1);
            // States of peer connections, and some data to send when sockets become writable
            let mut peers = Peers::new();
            // Starting peer connections to bootstrap nodes
            connect_peers(peers_addrs, &mut poll, &mut peers, &mut unique_token);

            loop {
                // Poll Mio for events, blocking until we get an event.
                poll.poll(&mut events, POLL_TIMEOUT).expect("Error polling sockets");

                // Process each event.
                for event in events.iter() {
                    trace!("Event for socket {} is {:?}", event.token().0, &event);
                    // We can use the token we previously provided to `register` to determine for which socket the event is.
                    match event.token() {
                        SERVER => {
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

                                    info!("Accepted connection from: {}", address);
                                    let token = next(&mut unique_token);
                                    poll.registry().register(&mut stream, token, Interest::READABLE).expect("Error registering poll");
                                    peers.add_peer(token, Peer::new(address, stream, State::Connected, true));
                                }
                                Err(_) => {}
                            }
                            poll.registry().reregister(&mut server, SERVER, Interest::READABLE).expect("Error reregistering server");
                        }
                        token => {
                            if !handle_connection_event(context.clone(), &mut peers, &poll.registry(), &event) {
                                let _ = peers.close_peer(poll.registry(), &token);
                                let mut context = context.lock().unwrap();
                                let blocks_count = context.chain.height();
                                context.bus.post(crate::event::Event::NetworkStatus { nodes: peers.get_peers_active_count(), blocks: blocks_count });
                            }
                        }
                    }
                }
                events.clear();

                // Send pings to idle peers
                let (height, hash) = {
                    let context = context.lock().unwrap();
                    (context.chain.height(), context.chain.last_hash())
                };
                mine_locker_block(context.clone());
                peers.send_pings(poll.registry(), height, hash);
                peers.connect_new_peers(poll.registry(), &mut unique_token);
            }
        });
        Ok(())
    }
}

fn handle_connection_event(context: Arc<Mutex<Context>>, peers: &mut Peers, registry: &Registry, event: &Event) -> bool {
    if event.is_error() || (event.is_read_closed() && event.is_write_closed()) {
        return false;
    }

    if event.is_readable() {
        let data = {
            let peer = peers.get_mut_peer(&event.token()).expect("Error getting peer for connection");
            let mut stream = peer.get_stream();
            read_message(&mut stream)
        };

        if data.is_ok() {
            let data = data.unwrap();
            match Message::from_bytes(data) {
                Ok(message) => {
                    let m = format!("{:?}", &message);
                    let new_state = handle_message(context.clone(), message, peers, &event.token());
                    let peer = peers.get_mut_peer(&event.token()).unwrap();
                    debug!("Got message from {}: {:?}", &peer.get_addr(), &m);
                    let stream = peer.get_stream();
                    match new_state {
                        State::Message { data } => {
                            if event.is_writable() {
                                // TODO handle all errors and buffer data to send
                                send_message(stream, &data);
                            } else {
                                registry.reregister(stream, event.token(), Interest::WRITABLE).unwrap();
                                peer.set_state(State::Message { data });
                            }
                        }
                        State::Connecting => {}
                        State::Connected => {}
                        State::Idle { .. } => {
                            peer.set_state(State::idle());
                        }
                        State::Error => {}
                        State::Banned => {}
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
        trace!("Socket {} is writable", event.token().0);
        match peers.get_mut_peer(&event.token()) {
            None => {}
            Some(peer) => {
                match peer.get_state().clone() {
                    State::Connecting => {
                        debug!("Sending hello to {}", &peer.get_addr());
                        let data: String = {
                            let c = context.lock().unwrap();
                            let message = Message::hand(&c.settings.origin, CHAIN_VERSION, c.settings.public);
                            serde_json::to_string(&message).unwrap()
                        };
                        send_message(peer.get_stream(), &data.into_bytes());
                        debug!("Sent hello to {}", &peer.get_addr());
                    }
                    State::Message { data } => {
                        debug!("Sending data to {}: {}", &peer.get_addr(), &String::from_utf8(data.clone()).unwrap());
                        send_message(peer.get_stream(), &data);
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
                            send_message(peer.get_stream(), &data.into_bytes());
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
                debug!("Error reading message, only {} bytes read", bytes_read);
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

fn send_message(connection: &mut TcpStream, data: &Vec<u8>) {
    // TODO handle errors
    connection.write_u32::<BigEndian>(data.len() as u32).expect("Error sending message");
    connection.write_all(&data).expect("Error writing to socket");
    connection.flush().expect("Error sending message");
}

fn handle_message(context: Arc<Mutex<Context>>, message: Message, peers: &mut Peers, token: &Token) -> State {
    let (my_height, my_hash, my_origin, my_version) = {
        let context = context.lock().unwrap();
        // TODO cache it somewhere
        (context.chain.height(), context.chain.last_hash(), &context.settings.origin.clone(), CHAIN_VERSION)
    };
    match message {
        Message::Hand { origin, version, public } => {
            if origin.eq(my_origin) && version == my_version {
                let peer = peers.get_mut_peer(token).unwrap();
                peer.set_public(public);
                State::message(Message::shake(&origin, version, true, my_height))
            } else {
                warn!("Handshake from unsupported chain or version");
                State::Error
            }
        }
        Message::Shake { origin, version, ok, height } => {
            if origin.ne(my_origin) || version != my_version {
                return State::Error;
            }
            if ok {
                let active_count = peers.get_peers_active_count();
                let peer = peers.get_mut_peer(token).unwrap();
                peer.set_height(height);
                peer.set_active(true);
                let mut context = context.lock().unwrap();
                let blocks_count = context.chain.height();
                context.bus.post(crate::event::Event::NetworkStatus { nodes: active_count + 1, blocks: blocks_count });
                if peer.is_higher(my_height) {
                    context.chain.update_max_height(height);
                    context.bus.post(crate::event::Event::Syncing { have: my_height, height});
                    State::message(Message::GetBlock { index: my_height + 1 })
                } else {
                    State::message(Message::GetPeers)
                }
            } else {
                State::Error
            }
        }
        Message::Error => { State::Error }
        Message::Ping { height, hash } => {
            let peer = peers.get_mut_peer(token).unwrap();
            peer.set_height(height);
            peer.set_active(true);
            if peer.is_higher(my_height) || ( height == my_height && my_hash != hash) {
                State::message(Message::GetBlock { index: my_height + 1 })
            } else {
                State::message(Message::pong(my_height, my_hash))
            }
        }
        Message::Pong { height, hash } => {
            let peer = peers.get_mut_peer(token).unwrap();
            peer.set_height(height);
            peer.set_active(true);
            let is_higher = peer.is_higher(my_height);

            let mut context = context.lock().unwrap();
            let blocks_count = context.chain.height();
            context.bus.post(crate::event::Event::NetworkStatus { nodes: peers.get_peers_active_count(), blocks: blocks_count });

            if is_higher {
                State::message(Message::GetBlock { index: my_height + 1 })
            } else if my_hash != hash {
                State::message(Message::GetBlock { index: my_height })
            } else {
                State::idle()
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
            let peer = peers.get_mut_peer(token).unwrap();
            peer.set_received_block(block.index);
            if let Some(transaction) = &block.transaction {
                if context.lock().unwrap().x_zones.has_hash(&transaction.identity.to_string()) {
                    // This peer has mined some of the forbidden zones
                    return State::Banned;
                }
            }
            let context = context.clone();
            let peers_count = peers.get_peers_active_count();
            thread::spawn(move || {
                let mut context = context.lock().unwrap();
                let max_height = context.chain.max_height();
                match context.chain.check_new_block(&block) {
                    BlockQuality::Good => {
                        context.chain.add_block(block);
                        let my_height = context.chain.height();
                        context.bus.post(crate::event::Event::BlockchainChanged);
                        // If it was the last block to sync
                        if my_height == max_height {
                            context.bus.post(crate::event::Event::SyncFinished);
                        } else {
                            context.bus.post(crate::event::Event::Syncing { have: my_height, height: max_height});
                        }
                        context.bus.post(crate::event::Event::NetworkStatus { nodes: peers_count, blocks: my_height });
                    }
                    BlockQuality::Twin => { debug!("Ignoring duplicate block {}", block.index); }
                    BlockQuality::Future => { debug!("Ignoring future block {}", block.index); }
                    BlockQuality::Bad => { debug!("Ignoring bad block {} with hash {:?}", block.index, block.hash); }
                    // TODO deal with forks
                    BlockQuality::Fork => {
                        debug!("Ignoring forked block {} with hash {:?}", block.index, block.hash);
                        //let peer = peers.get_mut_peer(token).unwrap();
                        //deal_with_fork(context, peer, block);
                    }
                }
            });
            State::idle()
        }
    }
}

/// Sends an Event to miner to start mining locker block if "locker" is our public key
fn mine_locker_block(context: Arc<Mutex<Context>>) {
    let mut context = context.lock().unwrap();
    if let Some(block) = context.chain.last_block() {
        if block.index < context.chain.max_height() {
            info!("No locker mining while syncing");
            return;
        }
        let lockers: HashSet<Bytes> = context.chain.get_block_lockers(&block).into_iter().collect();
        if lockers.contains(&context.keystore.get_public()) {
            info!("We have an honor to mine locker block!");
            context.bus.post(crate::event::Event::ActionMineLocker { index: block.index + 1, hash: block.hash });
        } else if !lockers.is_empty() {
            info!("Locker block must be mined by other nodes");
        }
    }
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

/// Connecting to configured (bootstrap) peers
fn connect_peers(peers_addrs: Vec<String>, poll: &mut Poll, peers: &mut Peers, unique_token: &mut Token) {
    for peer in peers_addrs.iter() {
        let addresses: Vec<SocketAddr> = match peer.to_socket_addrs() {
            Ok(peers) => { peers.collect() }
            Err(_) => { error!("Can't resolve address {}", &peer); continue; }
        };

        for addr in addresses {
            match TcpStream::connect(addr.clone()) {
                Ok(mut stream) => {
                    info!("Created connection to peer {}", &addr);
                    let token = next(unique_token);
                    poll.registry().register(&mut stream, token, Interest::WRITABLE).unwrap();
                    let mut peer = Peer::new(addr, stream, State::Connecting, false);
                    peer.set_public(true);
                    peers.add_peer(token, peer);
                }
                Err(e) => {
                    error!("Error connecting to peer {}: {}", &addr, e);
                }
            }
        }
    }
}

pub(crate) fn next(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}
