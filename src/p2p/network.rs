extern crate serde;
extern crate serde_json;

use std::{io, thread};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use mio::{Events, Interest, Poll, Registry, Token};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use serde::{Deserialize, Serialize};

use crate::{Context, Block};
use crate::p2p::Message;
use crate::p2p::State;
use crate::p2p::peer::Peer;

const SERVER: Token = Token(0);
const POLL_TIMEOUT: Option<Duration> = Some(Duration::from_millis(1000));

pub struct Network {
    context: Arc<Mutex<Context>>
}

impl Network {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        Network { context }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let (listen_addr, peers) = {
            let c = self.context.lock().unwrap();
            (c.settings.listen.clone(), c.settings.peers.clone())
        };

        // Starting server socket
        let addr = listen_addr.parse().expect("Error parsing listen address");
        let mut server = TcpListener::bind(addr).expect("Can't bind to address");
        println!("Started node listener on {}", server.local_addr().unwrap());

        let mut events = Events::with_capacity(64);
        let mut poll = Poll::new().expect("Unable to create poll");
        poll.registry().register(&mut server, SERVER, Interest::READABLE).expect("Error registering poll");
        let context = self.context.clone();
        thread::spawn(move || {
            // Unique token for each incoming connection.
            let mut unique_token = Token(SERVER.0 + 1);
            // Map of `Token` -> `TcpStream`.
            let mut connections = HashMap::new();
            // States of peer connections, and some data to send when sockets become writable
            let mut peer_state: HashMap<Token, Peer> = HashMap::new();
            // Starting peer connections to bootstrap nodes
            for peer in peers.iter() {
                match TcpStream::connect(peer.parse().expect("Error parsing peer address")) {
                    Ok(mut stream) => {
                        println!("Created connection to peer {}", &peer);
                        let token = next(&mut unique_token);
                        poll.registry().register(&mut stream, token, Interest::WRITABLE).unwrap();
                        peer_state.insert(token, Peer::new(peer.clone(), State::Connecting));
                        connections.insert(token, stream);
                    }
                    Err(e) => {
                        println!("Error connecting to peer {}: {}", &peer, e);
                    }
                }
            }

            loop {
                // Poll Mio for events, blocking until we get an event.
                poll.poll(&mut events, POLL_TIMEOUT).expect("Error polling sockets");
                //println!("Polling finished, got events: {}", !events.is_empty());

                // Process each event.
                for event in events.iter() {
                    println!("Event for {} is {:?}", event.token().0, &event);
                    // We can use the token we previously provided to `register` to determine for which socket the event is.
                    match event.token() {
                        SERVER => {
                            // If this is an event for the server, it means a connection is ready to be accepted.
                            let connection = server.accept();
                            match connection {
                                Ok((mut connection, address)) => {
                                    println!("Accepted connection from: {}", address);
                                    let token = next(&mut unique_token);
                                    poll.registry().register(&mut connection, token, Interest::READABLE).expect("Error registering poll");
                                    peer_state.insert(token, Peer::new(address.to_string(), State::Connected));
                                    connections.insert(token, connection);
                                }
                                Err(_) => {}
                            }
                        }
                        token => {
                            match connections.get_mut(&token) {
                                Some(connection) => {
                                    match handle_connection_event(context.clone(), &mut peer_state, &poll.registry(), connection, &event) {
                                        Ok(result) => {
                                            if !result {
                                                connections.remove(&token);
                                                peer_state.remove(&token);
                                            }
                                        }
                                        Err(err) => {}
                                    }
                                }
                                None => { println!("Odd event from poll"); }
                            }
                        }
                    }
                }
                // Send pings to idle peers
                for (token, peer) in peer_state.iter_mut() {
                    match peer.get_state() {
                        State::Idle { from } => {
                            if from.elapsed().as_secs() >= 30 {
                                let c = context.lock().unwrap();
                                peer.set_state(State::message(Message::ping(c.blockchain.height())));
                                let mut connection = connections.get_mut(&token).unwrap();
                                poll.registry().reregister(connection, token.clone(), Interest::WRITABLE).unwrap();
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(())
    }
}

fn handle_connection_event(context: Arc<Mutex<Context>>, peer_state: &mut HashMap<Token, Peer>, registry: &Registry, connection: &mut TcpStream, event: &Event) -> io::Result<bool> {
    if event.is_error() {
        return Ok(false);
    }

    if event.is_readable() {
        let data_size = match connection.read_u32::<BigEndian>() {
            Ok(size) => { size as usize }
            Err(e) => {
                println!("Error reading from socket! {}", e);
                0
            }
        };
        println!("Payload size is {}", data_size);

        // TODO check for very big buffer, make it no more 10Mb
        let mut buf = vec![0u8; data_size];
        let mut bytes_read = 0;
        loop {
            match connection.read(&mut buf[bytes_read..]) {
                Ok(bytes) => {
                    bytes_read += bytes;
                }
                // Would block "errors" are the OS's way of saying that the connection is not actually ready to perform this I/O operation.
                Err(ref err) if would_block(err) => break,
                Err(ref err) if interrupted(err) => continue,
                // Other errors we'll consider fatal.
                Err(err) => return Err(err),
            }
        }

        if bytes_read == data_size {
            match Message::from_bytes(buf) {
                Ok(message) => {
                    println!("Got message from socket {}: {:?}", &event.token().0, &message);
                    let new_state = handle_message(context.clone(), message);
                    match new_state {
                        State::Message { data } => {
                            if event.is_writable() {
                                // TODO handle all errors and buffer data to send
                                send_message(connection, &data);
                            } else {
                                registry.reregister(connection, event.token(), Interest::WRITABLE).unwrap();
                                let mut peer = peer_state.get_mut(&event.token()).unwrap();
                                peer.set_state(State::Message { data });
                            }
                        }
                        State::Connecting => {}
                        State::Connected => {}
                        State::Idle { .. } => {
                            let mut peer = peer_state.get_mut(&event.token()).unwrap();
                            peer.set_state(State::idle());
                        }
                        State::Error => {}
                        State::Banned => {}
                        State::Offline { .. } => {
                            let mut peer = peer_state.get_mut(&event.token()).unwrap();
                            peer.set_state(State::offline(1));
                        }
                    }
                }
                Err(_) => {}
            }
        } else {
            // Consider connection as unreliable
            return Ok(false);
        }
    }

    if event.is_writable() {
        println!("Socket {} is writable", event.token().0);
        match peer_state.get(&event.token()) {
            None => {}
            Some(peer) => {
                match peer.get_state() {
                    State::Connecting => {
                        println!("Hello needed for socket {}", event.token().0);
                        let data: String = {
                            let mut c = context.lock().unwrap();
                            let message = Message::Hand { chain: c.settings.chain_name.clone(), version: c.settings.version_flags };
                            serde_json::to_string(&message).unwrap()
                        };
                        send_message(connection, &data.into_bytes());
                        println!("Sent hello through socket {}", event.token().0);
                    }
                    State::Message { data } => {
                        println!("Sending data to socket {}: {}", event.token().0, &String::from_utf8(data.clone()).unwrap());
                        send_message(connection, data);
                    }
                    State::Connected => {}
                    State::Idle { from } => {
                        if from.elapsed().as_secs() >= 30 {
                            let data: String = {
                                let mut c = context.lock().unwrap();
                                let message = Message::ping(c.blockchain.height());
                                serde_json::to_string(&message).unwrap()
                            };
                            send_message(connection, &data.into_bytes());
                        }
                    }
                    State::Error => {}
                    State::Banned => {}
                    State::Offline { .. } => {}
                }
            }
        }
        registry.reregister(connection, event.token(), Interest::READABLE).unwrap();
    }

    Ok(true)
}

fn send_message(connection: &mut TcpStream, data: &Vec<u8>) {
    // TODO handle errors
    connection.write_u32::<BigEndian>(data.len() as u32);
    connection.write_all(&data).expect("Error writing to socket");
    connection.flush();
}

fn handle_message(context: Arc<Mutex<Context>>, message: Message) -> State {
    match message {
        Message::Hand { chain, version } => {
            let context = context.lock().unwrap();
            if chain == context.settings.chain_name && version == context.settings.version_flags {
                State::message(Message::shake(true, context.blockchain.height()))
            } else {
                State::Error
            }
        }
        Message::Shake { ok, height } => {
            if ok {
                let context = context.lock().unwrap();
                if height > context.blockchain.height() {
                    State::message(Message::GetBlock { index: context.blockchain.height() + 1u64 })
                } else {
                    State::idle()
                }
            } else {
                State::Error
            }
        }
        Message::Error => { State::Error }
        Message::Ping { height } => {
            let context = context.lock().unwrap();
            if height > context.blockchain.height() {
                State::message(Message::GetBlock { index: context.blockchain.height() + 1u64 })
            } else {
                State::message(Message::pong(context.blockchain.height()))
            }
        }
        Message::Pong { height } => {
            let context = context.lock().unwrap();
            if height > context.blockchain.height() {
                State::message(Message::GetBlock { index: context.blockchain.height() + 1u64 })
            } else {
                State::idle()
            }
        }
        Message::GetPeers => { State::Error }
        Message::Peers => { State::Error }
        Message::GetBlock { index } => {
            let context = context.lock().unwrap();
            match context.blockchain.get_block(index) {
                Some(block) => State::message(Message::block(block.index, serde_json::to_string(&block).unwrap())),
                None => State::Error
            }
        }
        Message::Block { index, block } => {
            let block: Block = match serde_json::from_str(&block) {
                Ok(block) => block,
                Err(_) => return State::Error
            };
            // TODO check if the block is good
            let context = context.clone();
            thread::spawn(move || {
                let mut context = context.lock().unwrap();
                context.blockchain.add_block(block);
                context.bus.post(crate::event::Event::BlockchainChanged)
            });
            State::idle()
        }
    }
}

fn next(current: &mut Token) -> Token {
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
