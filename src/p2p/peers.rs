use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, IpAddr, Shutdown, ToSocketAddrs};
use mio::{Token, Interest, Registry};
use mio::net::TcpStream;
use crate::p2p::{Peer, State, Message};
use crate::p2p::network::LISTEN_PORT;
use crate::p2p::network::next;
use rand::random;
use rand::seq::IteratorRandom;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};
use crate::Bytes;

pub struct Peers {
    peers: HashMap<Token, Peer>,
    new_peers: Vec<SocketAddr>,
    ignored: HashSet<IpAddr>
}

const PING_PERIOD: u64 = 30;

impl Peers {
    pub fn new() -> Self {
        Peers { peers: HashMap::new(), new_peers: Vec::new(), ignored: HashSet::new() }
    }

    pub fn add_peer(&mut self, token: Token, peer: Peer) {
        self.peers.insert(token, peer);
    }

    pub fn get_peer(&self, token: &Token) -> Option<&Peer> {
        self.peers.get(token)
    }

    pub fn get_mut_peer(&mut self, token: &Token) -> Option<&mut Peer> {
        self.peers.get_mut(token)
    }

    pub fn close_peer(&mut self, registry: &Registry, token: &Token) {
        let peer = self.peers.get_mut(token);
        match peer {
            Some(peer) => {
                let stream = peer.get_stream();
                let _ = stream.shutdown(Shutdown::Both);
                let _ = registry.deregister(stream);
                info!("Peer connection {:?} has shut down", &peer.get_addr());

                if !peer.disabled() && !peer.is_inbound() {
                    peer.set_state(State::offline());
                    peer.set_active(false);
                } else {
                    self.peers.remove(token);
                }
            }
            None => {}
        }
    }

    pub fn add_peers_from_exchange(&mut self, peers: Vec<String>) {
        let peers: HashSet<String> = peers
            .iter()
            .fold(HashSet::new(), |mut peers, peer| {
                peers.insert(peer.to_owned());
                peers
            });
        debug!("Got {} peers: {:?}", peers.len(), &peers);
        // TODO make it return error if these peers are wrong and seem like an attack
        for peer in peers.iter() {
            let addr: SocketAddr = match peer.parse() {
                Err(_) => {
                    warn!("Error parsing peer {}", peer);
                    continue;
                }
                Ok(addr) => addr
            };

            if self.peers
                .iter()
                .find(|(_token, peer)| peer.get_addr().ip() == addr.ip())
                .is_some() {
                //debug!("Skipping address from exchange: {}", &addr);
                continue;
            }

            if self.new_peers
                .iter()
                .find(|a| a.ip().eq(&addr.ip()))
                .is_some() {
                //debug!("Skipping address from exchange: {}", &addr);
                continue;
            }

            if skip_addr(&addr) {
                //debug!("Skipping address from exchange: {}", &addr);
                continue; // Return error in future
            }
            let mut found = false;
            for (_token, p) in self.peers.iter() {
                if p.equals(&addr) {
                    found = true;
                    break;
                }
            }
            if found {
                continue;
            }
            self.new_peers.push(addr);
        }
    }

    pub fn is_our_own_connect(&self, rand: &str) -> bool {
        match self.peers.values().find(|p| p.get_rand() == rand) {
            None => { false }
            Some(p) => {
                !p.is_inbound()
            }
        }
    }

    pub fn get_peers_for_exchange(&self, peer_address: &SocketAddr) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for (_, peer) in self.peers.iter() {
            if peer.equals(peer_address) {
                continue;
            }
            if peer.is_public() {
                result.push(SocketAddr::new(peer.get_addr().ip(), LISTEN_PORT).to_string());
            }
        }
        result
    }

    pub fn get_peers_active_count(&self) -> usize {
        let mut count = 0;
        for (_, peer) in self.peers.iter() {
            if peer.active() {
                count += 1;
            }
        }
        count
    }

    pub fn ignore_peer(&mut self, registry: &Registry, token: &Token) {
        let peer = self.peers.get_mut(token).unwrap();
        peer.set_state(State::Banned);
        let ip = peer.get_addr().ip().clone();
        self.close_peer(registry, token);
        self.ignored.insert(ip);
        match self.peers
            .iter()
            .find(|(_, p)| p.get_addr().ip() == ip)
            .map(|(t, _)| t.clone()) {
            None => {}
            Some(t) => {
                self.close_peer(registry, &t);
                self.peers.remove(&t);
            }
        }
    }

    pub fn ignore_ip(&mut self, ip: &IpAddr) {
        self.ignored.insert(ip.clone());
    }

    pub fn skip_peer_connection(&self, addr: &SocketAddr) -> bool {
        for (_, peer) in self.peers.iter() {
            if peer.equals(addr) && (!peer.is_public() || peer.active() || peer.disabled()) {
                return true;
            }
        }
        false
    }

    pub fn send_pings(&mut self, registry: &Registry, height: u64, hash: Bytes) {
        let mut ping_sent = false;
        for (token, peer) in self.peers.iter_mut() {
            match peer.get_state() {
                State::Idle { from } => {
                    let random_time = random::<u64>() % PING_PERIOD;
                    if from.elapsed().as_secs() >= PING_PERIOD + random_time {
                        // Sometimes we check for new peers instead of pinging
                        let random: u8 = random();
                        let message = if random < 16 {
                            Message::GetPeers
                        } else {
                            Message::ping(height, hash.clone())
                        };

                        peer.set_state(State::message(message));
                        let stream = peer.get_stream();
                        registry.reregister(stream, token.clone(), Interest::WRITABLE).unwrap();
                        ping_sent = true;
                    }
                }
                _ => {}
            }
        }

        // If someone has more blocks we sync
        if !ping_sent {
            let mut rng = rand::thread_rng();
            match self.peers
                .iter_mut()
                .filter_map(|(token, peer)| if peer.has_more_blocks(height) { Some((token, peer)) } else { None })
                .choose(&mut rng) {
                None => {}
                Some((token, peer)) => {
                    debug!("Found some peer higher than we are, sending block request");
                    registry.reregister(peer.get_stream(), token.clone(), Interest::WRITABLE).unwrap();
                    peer.set_state(State::message(Message::GetBlock { index: height + 1 }));
                    ping_sent = true;
                }
            }
        }

        // If someone has less blocks (we mined a new block) we send a ping with our height
        if !ping_sent {
            let mut rng = rand::thread_rng();
            match self.peers
                .iter_mut()
                .filter_map(|(token, peer)| if peer.is_lower(height) && peer.get_state().is_idle() { Some((token, peer)) } else { None })
                .choose(&mut rng) {
                None => {}
                Some((token, peer)) => {
                    debug!("Found some peer lower than we are, sending ping");
                    registry.reregister(peer.get_stream(), token.clone(), Interest::WRITABLE).unwrap();
                    peer.set_state(State::message(Message::Ping { height, hash }));
                }
            }
        }

        for (token, peer) in self.peers.iter_mut() {
            if peer.get_state().need_reconnect() {
                let addr = peer.get_addr();
                match TcpStream::connect(addr.clone()) {
                    Ok(mut stream) => {
                        info!("Created connection to peer {}, state = {:?}", &addr, peer.get_state());
                        registry.register(&mut stream, token.clone(), Interest::WRITABLE).unwrap();
                        peer.set_state(State::Connecting);
                        peer.set_stream(stream);
                    }
                    Err(e) => {
                        error!("Error connecting to peer {}: {}", &addr, e);
                    }
                }
            }
        }
    }

    pub fn connect_new_peers(&mut self, registry: &Registry, unique_token: &mut Token) {
        if self.new_peers.is_empty() {
            return;
        }
        for addr in self.new_peers.iter() {
            if self.ignored.contains(&addr.ip()) {
                continue;
            }
            match TcpStream::connect(addr.clone()) {
                Ok(mut stream) => {
                    info!("Created connection to peer {}", &addr);
                    let token = next(unique_token);
                    registry.register(&mut stream, token, Interest::WRITABLE).unwrap();
                    let mut peer = Peer::new(addr.clone(), stream, State::Connecting, false);
                    peer.set_public(true);
                    self.peers.insert(token, peer);
                }
                Err(e) => {
                    error!("Error connecting to peer {}: {}", &addr, e);
                }
            }
        }
        self.new_peers.clear();
    }

    /// Connecting to configured (bootstrap) peers
    pub fn connect_peers(&mut self, peers_addrs: Vec<String>, registry: &Registry, unique_token: &mut Token) {
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
                        registry.register(&mut stream, token, Interest::WRITABLE).unwrap();
                        let mut peer = Peer::new(addr, stream, State::Connecting, false);
                        peer.set_public(true);
                        self.add_peer(token, peer);
                    }
                    Err(e) => {
                        error!("Error connecting to peer {}: {}", &addr, e);
                    }
                }
            }
        }
    }
}

fn skip_addr(addr: &SocketAddr) -> bool {
    if addr.ip().is_loopback() {
        return true;
    }
    match addr {
        SocketAddr::V4(addr) => {
            if addr.ip().is_private() {
                return true;
            }
        }
        SocketAddr::V6(_addr) => {
            // TODO uncomment when stabilized
            // if addr.ip().is_unique_local() {
            //     return true;
            // }
        }
    }

    false
}