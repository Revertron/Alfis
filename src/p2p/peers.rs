use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs};

use chrono::Utc;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use mio::{Interest, Registry, Token};
use mio::net::TcpStream;
use rand::random;
use rand::seq::IteratorRandom;

use crate::{Bytes, commons};
use crate::commons::*;
use crate::p2p::{Message, Peer, State};
use crate::commons::next;
use std::time::Duration;
use std::io;

const PING_PERIOD: u64 = 60;
const TCP_TIMEOUT: Duration = Duration::from_millis(10000);

pub struct Peers {
    peers: HashMap<Token, Peer>,
    new_peers: Vec<SocketAddr>,
    ignored: HashSet<IpAddr>,
    my_id: String,
    asked_block: u64,
    asked_time: i64,
}

impl Peers {
    pub fn new() -> Self {
        Peers {
            peers: HashMap::new(),
            new_peers: Vec::new(),
            ignored: HashSet::new(),
            my_id: commons::random_string(6),
            asked_block: 0,
            asked_time: 0
        }
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
                match peer.get_state() {
                    State::Connecting => {
                        error!("Peer connection {} to {:?} has timed out", &token.0, &peer.get_addr());
                    }
                    State::Connected => {
                        error!("Peer connection {} to {:?} disconnected", &token.0, &peer.get_addr());
                    }
                    State::Idle { .. } | State::Message { .. } => {
                        error!("Peer connection {} to {:?} disconnected", &token.0, &peer.get_addr());
                    }
                    State::Error => {
                        error!("Peer connection {} to {:?} has shut down on error", &token.0, &peer.get_addr());
                    }
                    State::Banned => {
                        error!("Peer connection {} to {:?} has shut down, banned", &token.0, &peer.get_addr());
                        self.ignored.insert(peer.get_addr().ip().clone());
                    }
                    State::Offline { .. } => {
                        error!("Peer connection {} to {:?} is offline", &token.0, &peer.get_addr());
                    }
                }

                self.peers.remove(token);
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
        debug!("Got {} peers from exchange", peers.len());
        //debug!("Got {} peers: {:?}", peers.len(), &peers);
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

            if self.ignored.contains(&addr.ip()) {
                info!("Skipping ignored address from exchange: {}", &addr);
                continue;
            }

            if skip_private_addr(&addr) {
                //debug!("Skipping address from exchange: {}", &addr);
                continue; // Return error in future
            }
            self.new_peers.push(addr);
        }
    }

    pub fn get_my_id(&self) -> &str {
        &self.my_id
    }

    pub fn is_our_own_connect(&self, rand: &str) -> bool {
        self.my_id.eq(rand)
    }

    pub fn is_ignored(&self, addr: &IpAddr) -> bool {
        self.ignored.contains(addr)
    }

    pub fn get_peers_for_exchange(&self, peer_address: &SocketAddr) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for (_, peer) in self.peers.iter() {
            if peer.disabled() {
                continue;
            }
            if peer.equals(peer_address) {
                continue;
            }
            if peer.is_public() && peer.active() {
                result.push(SocketAddr::new(peer.get_addr().ip(), LISTEN_PORT).to_string());
            }
            if result.len() >= 10 {
                break;
            }
        }
        result
    }

    pub fn get_peers_count(&self) -> usize {
        self.peers.len()
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

    pub fn get_peers_banned_count(&self) -> usize {
        self.ignored.len()
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
        info!("Adding {} to ignored peers", &ip);
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

    pub fn update(&mut self, registry: &Registry, height: u64, hash: Bytes) {
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
        if self.need_ask_block(height + 1) {
            let mut rng = rand::thread_rng();
            let mut asked = false;
            match self.peers
                .iter_mut()
                .filter_map(|(token, peer)| if peer.has_more_blocks(height) { Some((token, peer)) } else { None })
                .choose(&mut rng) {
                None => {}
                Some((token, peer)) => {
                    debug!("Found some peer higher than we are, requesting block {}, from {}", height + 1, &peer.get_addr().ip());
                    registry.reregister(peer.get_stream(), token.clone(), Interest::WRITABLE).unwrap();
                    peer.set_state(State::message(Message::GetBlock { index: height + 1 }));
                    ping_sent = true;
                    asked = true;
                }
            }
            if asked {
                self.set_asked_block(height + 1);
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

        let mut offline_ips = Vec::new();
        // Remove all peers that are offline for a long time
        self.peers.retain(|_, p| {
            let offline = p.get_state().need_reconnect() && p.reconnects() >= MAX_RECONNECTS;
            if offline {
                offline_ips.push(p.get_addr().ip());
            }
            !offline
        });
        for ip in offline_ips {
            self.ignore_ip(&ip);
        }

        for (token, peer) in self.peers.iter_mut() {
            if peer.get_state().need_reconnect() {
                let addr = peer.get_addr();
                if let Ok(mut stream) = TcpStream::connect(addr.clone()) {
                    debug!("Trying to reconnect to peer {}, count {}", &addr, peer.reconnects());
                    registry.register(&mut stream, token.clone(), Interest::WRITABLE).unwrap();
                    peer.set_state(State::Connecting);
                    peer.inc_reconnects();
                    peer.set_stream(stream);
                }
                // We make reconnects only to one at a time
                break;
            }
        }
    }

    pub fn connect_new_peers(&mut self, registry: &Registry, unique_token: &mut Token, yggdrasil_only: bool) {
        if self.new_peers.is_empty() {
            return;
        }
        self.new_peers.dedup();
        let addr = self.new_peers.remove(0);
        match self.connect_peer(&addr, registry, unique_token, yggdrasil_only) {
            Ok(_) => {}
            Err(_) => {
                debug!("Could not connect to {}", &addr);
            }
        }
    }

    /// Connecting to configured (bootstrap) peers
    pub fn connect_peers(&mut self, peers_addrs: &Vec<String>, registry: &Registry, unique_token: &mut Token, yggdrasil_only: bool) {
        let mut set = HashSet::new();
        for peer in peers_addrs.iter() {
            let mut addresses: Vec<SocketAddr> = match peer.to_socket_addrs() {
                Ok(peers) => { peers.collect() }
                Err(_) => { error!("Can't resolve address {}", &peer); continue; }
            };

            // At first we connect to one peer address from every "peer" or domain
            let addr = addresses.remove(0);
            if !set.contains(&addr) {
                match self.connect_peer(&addr, registry, unique_token, yggdrasil_only) {
                    Ok(_) => {
                        set.insert(addr);
                    }
                    Err(_) => {
                        debug!("Could not connect to {}", &addr);
                    }
                }
            }
            // Copy others to new_peers, to connect later
            self.new_peers.append(&mut addresses);
        }
    }

    fn connect_peer(&mut self, addr: &SocketAddr, registry: &Registry, unique_token: &mut Token, yggdrasil_only: bool) -> io::Result<()> {
        if self.ignored.contains(&addr.ip()) {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        if yggdrasil_only && !is_yggdrasil(&addr.ip()) {
            debug!("Ignoring not Yggdrasil address '{}'", &addr.ip());
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if let Ok(stream) = std::net::TcpStream::connect_timeout(&addr.clone(), TCP_TIMEOUT) {
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(TCP_TIMEOUT))?;
            stream.set_write_timeout(Some(TCP_TIMEOUT))?;
            stream.set_nonblocking(true)?;

            let mut stream = TcpStream::from_std(stream);
            let token = next(unique_token);
            trace!("Created connection {}, to peer {}", &token.0, &addr);
            registry.register(&mut stream, token, Interest::WRITABLE)?;
            let mut peer = Peer::new(addr.clone(), stream, State::Connecting, false);
            peer.set_public(true);
            self.peers.insert(token, peer);
        }
        Ok(())
    }


    pub fn set_asked_block(&mut self, index: u64) {
        self.asked_block = index;
        self.asked_time = Utc::now().timestamp();
    }

    pub fn need_ask_block(&self, index: u64) -> bool {
        index > self.asked_block || self.asked_time + 3 < Utc::now().timestamp()
    }
}

fn skip_private_addr(addr: &SocketAddr) -> bool {
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