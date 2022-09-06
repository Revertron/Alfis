use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::{io, thread};
use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use chrono::Utc;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use rand::prelude::SliceRandom;
use rand::random;
use rand::seq::IteratorRandom;

use crate::commons::*;
use crate::p2p::{Message, Peer, State};
use crate::{commons, Bytes};

const PING_PERIOD: u64 = 30;

pub struct Peers {
    peers: HashMap<Token, Peer>,
    new_peers: Vec<SocketAddr>,
    ignored: HashSet<IpAddr>,
    ignore_timer: Instant,
    my_id: String,
    behind_ping_sent_time: i64
}

impl Peers {
    pub fn new() -> Self {
        Peers {
            peers: HashMap::new(),
            new_peers: Vec::new(),
            ignored: HashSet::new(),
            ignore_timer: Instant::now(),
            my_id: commons::random_string(6),
            behind_ping_sent_time: 0
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
        let peer = self.peers.remove(token);
        if let Some(mut peer) = peer {
            let stream = peer.get_stream();
            let _ = stream.shutdown(Shutdown::Both);
            let _ = registry.deregister(stream);
            let addr = peer.get_addr();
            match peer.get_state() {
                State::Connecting => {
                    debug!("Peer connection {} to {:?} has timed out", &token.0, &addr);
                }
                State::Connected => {
                    debug!("Peer connection {} to {:?} disconnected", &token.0, &addr);
                }
                State::Idle { .. } | State::Message { .. } => {
                    debug!("Peer connection {} to {:?} disconnected", &token.0, &addr);
                }
                State::Error => {
                    debug!("Peer connection {} to {:?} has shut down on error", &token.0, &addr);
                }
                State::Banned => {
                    debug!("Peer connection {} to {:?} has shut down, banned", &token.0, &addr);
                    self.ignored.insert(addr.ip());
                }
                State::Offline { .. } => {
                    debug!("Peer connection {} to {:?} is offline", &token.0, &addr);
                }
                State::SendLoop => {
                    debug!("Peer connection {} from {:?} is a loop", &token.0, &addr);
                }
                State::Loop => {
                    debug!("Peer connection {} to {:?} is a loop", &token.0, &addr);
                }
                State::Twin => {
                    debug!("Peer connection {} to {:?} is a twin", &token.0, &addr);
                }
                State::ServerHandshake => {
                    debug!("Peer connection {} from {:?} didn't shake hands", &token.0, &addr);
                }
                State::HandshakeFinished => {
                    debug!("Peer connection {} from {:?} shook hands, but then failed", &token.0, &addr);
                }
            }
        }
    }

    pub fn close_all_peers(&mut self, registry: &Registry) {
        let tokens: Vec<Token> = self.peers.keys().into_iter().cloned().collect();
        for token in tokens.iter() {
            self.close_peer(registry, token);
        }
        self.peers.clear();
    }

    pub fn add_peers_from_exchange(&mut self, peers: Vec<String>) {
        let peers: HashSet<String> = peers
            .iter()
            .fold(HashSet::new(), |mut peers, peer| {
                peers.insert(peer.to_owned());
                peers
            });
        let mut count = 0;
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
                .any(|(_token, peer)| peer.get_addr().ip() == addr.ip()) {
                //debug!("Skipping address from exchange: {}", &addr);
                continue;
            }

            if self.new_peers
                .iter()
                .any(|a| a.ip().eq(&addr.ip())) {
                //debug!("Skipping address from exchange: {}", &addr);
                continue;
            }

            if self.ignored.contains(&addr.ip()) {
                debug!("Skipping ignored address from exchange: {}", &addr);
                continue;
            }

            if skip_private_addr(&addr) {
                //debug!("Skipping address from exchange: {}", &addr);
                continue; // Return error in future
            }
            self.new_peers.push(addr);
            count += 1;
        }
        if count > 0 {
            debug!("Got {} new peer(s) from exchange", count);
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
            } else {
                if !matches!(peer.get_state(), State::Connecting) {
                    trace!("Inactive peer from {:?} in state: {:?}", peer.get_addr(), peer.get_state());
                }
            }
        }
        count
    }

    pub fn is_tween_connect(&self, id: &str) -> bool {
        for (_, peer) in self.peers.iter() {
            if peer.active() && peer.get_id() == id {
                return true;
            }
        }
        false
    }

    pub fn get_peers_banned_count(&self) -> usize {
        self.ignored.len()
    }

    pub fn ignore_peer(&mut self, registry: &Registry, token: &Token) {
        let peer = self.peers.get_mut(token).unwrap();
        if !peer.get_state().is_loop() {
            peer.set_state(State::Banned);
        }
        let ip = peer.get_addr().ip();
        self.close_peer(registry, token);
        self.ignored.insert(ip);
        match self.peers
            .iter()
            .find(|(_, p)| p.get_addr().ip() == ip)
            .map(|(t, _)| *t) {
            None => {}
            Some(t) => {
                self.close_peer(registry, &t);
            }
        }
    }

    pub fn ignore_ip(&mut self, ip: &IpAddr) {
        info!("Adding {} to ignored peers", &ip);
        self.ignored.insert(*ip);
    }

    pub fn skip_peer_connection(&self, addr: &SocketAddr) -> bool {
        for (_, peer) in self.peers.iter() {
            if peer.equals(addr) && (!peer.is_public() || peer.active() || peer.disabled()) {
                return true;
            }
        }
        false
    }

    pub fn update(&mut self, registry: &Registry, hash: Bytes, height: u64, max_height: u64, have_blocks: HashSet<u64>) {
        let nodes = self.get_peers_active_count();

        let random_time = random::<u64>() % PING_PERIOD;
        let mut stale_tokens = Vec::new();
        for (token, peer) in self.peers.iter_mut() {
            if let State::Idle { from } = peer.get_state() {
                if from.elapsed().as_secs() >= PING_PERIOD + random_time {
                    // Sometimes we check for new peers instead of pinging
                    let message = if nodes < MAX_NODES && random::<bool>() {
                        Message::GetPeers
                    } else {
                        Message::ping(height, hash.clone())
                    };

                    peer.set_state(State::message(message));
                    let stream = peer.get_stream();
                    registry.reregister(stream, *token, Interest::WRITABLE | Interest::READABLE).unwrap();
                }
            } else {
                if matches!(peer.get_state(), State::Message {..}) {
                    if !peer.active() {
                        stale_tokens.push((token.clone(), peer.get_addr()));
                        continue;
                    }
                    let stream = peer.get_stream();
                    registry.reregister(stream, *token, Interest::WRITABLE).unwrap();
                }
            }
        }
        for (token, addr) in &stale_tokens {
            info!("Closing stale peer from {}", addr);
            self.close_peer(registry, token);
        }

        // Just purging ignored/banned IPs every 10 minutes
        // TODO make it individual for every IP
        if self.ignore_timer.elapsed().as_secs() >= 600 {
            self.ignored.clear();
            self.ignore_timer = Instant::now();
        }

        // If someone has more blocks we sync
        if nodes >= MIN_CONNECTED_NODES_START_SYNC && height < max_height {
            let count = min(max_height - height, nodes as u64);
            self.ask_blocks_from_peers(registry, height, height + count, have_blocks);
        }

        // If someone has less blocks (we mined a new block) we send a ping with our height
        if self.need_behind_ping() {
            let mut rng = rand::thread_rng();
            match self.peers
                .iter_mut()
                .filter_map(|(token, peer)| if peer.is_lower(height) && peer.get_state().is_idle() && peer.get_sent_height() < height { Some((token, peer)) } else { None })
                .choose(&mut rng) {
                None => {}
                Some((token, peer)) => {
                    debug!("Peer {} is behind ({}), sending ping", &peer.get_addr().ip(), peer.get_height());
                    registry.reregister(peer.get_stream(), *token, Interest::WRITABLE).unwrap();
                    peer.set_state(State::message(Message::Ping { height, hash }));
                    peer.set_sent_height(height);
                    self.update_behind_ping_time();
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
                if let Ok(mut stream) = TcpStream::connect(addr) {
                    debug!("Trying to reconnect to peer {}, count {}", &addr, peer.reconnects());
                    registry.register(&mut stream, *token, Interest::WRITABLE).unwrap();
                    peer.set_state(State::Connecting);
                    peer.inc_reconnects();
                    peer.set_stream(stream);
                }
                // We make reconnects only to one at a time
                break;
            }
        }
    }

    #[allow(dead_code)]
    fn ask_block_from_peer(&mut self, registry: &Registry, height: u64) {
        let mut rng = rand::thread_rng();
        match self.peers
            .iter_mut()
            .filter_map(|(token, peer)| if peer.has_more_blocks(height) { Some((token, peer)) } else { None })
            .choose(&mut rng) {
            None => {}
            Some((token, peer)) => {
                debug!("Peer {} is higher than we are, requesting block {}", &peer.get_addr().ip(), height + 1);
                registry.reregister(peer.get_stream(), *token, Interest::WRITABLE | Interest::READABLE).unwrap();
                peer.set_state(State::message(Message::GetBlock { index: height + 1 }));
            }
        }
    }

    fn ask_blocks_from_peers(&mut self, registry: &Registry, height: u64, max_height: u64, have_blocks: HashSet<u64>) {
        let mut rng = rand::thread_rng();
        let mut peers = self.peers
            .iter_mut()
            .filter_map(|(token, peer)| if peer.has_more_blocks(height) { Some((token, peer)) } else { None })
            .choose_multiple(&mut rng, (max_height - height) as usize);
        peers.shuffle(&mut rng);
        let mut index = height + 1;
        for (token, peer) in peers {
            if have_blocks.contains(&index) {
                debug!("We have block {} in map, skipping request", index);
                index += 1;
                continue;
            }
            debug!("Peer {} is higher than we are, requesting block {}", &peer.get_addr().ip(), index);
            registry.reregister(peer.get_stream(), *token, Interest::WRITABLE).unwrap();
            peer.set_state(State::message(Message::GetBlock { index }));
            index += 1;
            if index > max_height {
                break;
            }
        }
    }

    pub fn connect_new_peers(&mut self, registry: &Registry, unique_token: &mut Token, yggdrasil_only: bool) {
        if self.new_peers.is_empty() {
            return;
        }
        self.new_peers.sort();
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
    pub fn connect_peers(&mut self, peers_addrs: &[String], registry: &Registry, unique_token: &mut Token, yggdrasil_only: bool) {
        let mut set = HashSet::new();
        for peer in peers_addrs.iter() {
            // At first we connect to 10 peer addresses
            if set.len() >= 10 {
                break;
            }

            let mut addresses = Self::resolve(peer);
            while !addresses.is_empty() {
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
            }

            // Copy others to new_peers, to connect later
            if !addresses.is_empty() {
                self.new_peers.append(&mut addresses);
            }
        }
    }

    /// Tries to resolve some address several times with timeout
    fn resolve(peer: &str) -> Vec<SocketAddr> {
        info!("Resolving address {}", peer);
        let start = Instant::now();
        let delay = Duration::from_millis(20);
        let timeout = Duration::from_millis(200);
        while start.elapsed() < timeout {
            let addresses: Vec<SocketAddr> = match peer.to_socket_addrs() {
                Ok(peers) => peers.collect(),
                Err(e) => {
                    trace!("Can't resolve address {}: {}", &peer, e);
                    thread::sleep(delay);
                    continue;
                }
            };
            if !addresses.is_empty() {
                info!("Got addresses: {:?}", &addresses);
                return addresses;
            }
        }
        vec![]
    }

    fn connect_peer(&mut self, addr: &SocketAddr, registry: &Registry, unique_token: &mut Token, yggdrasil_only: bool) -> io::Result<()> {
        if self.ignored.contains(&addr.ip()) {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        if yggdrasil_only && !is_yggdrasil(&addr.ip()) {
            debug!("Ignoring not Yggdrasil address '{}'", &addr.ip());
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        trace!("Connecting to peer {}", &addr);
        match TcpStream::connect(*addr) {
            Ok(mut stream) => {
                //stream.set_nodelay(true)?;
                let token = next(unique_token);
                trace!("Created connection {}, to peer {}", &token.0, &addr);
                registry.register(&mut stream, token, Interest::WRITABLE).unwrap();
                let mut peer = Peer::new(*addr, stream, State::Connecting, false);
                peer.set_public(true);
                self.peers.insert(token, peer);
                Ok(())
            }
            Err(e) => Err(e)
        }
    }

    pub fn update_behind_ping_time(&mut self) {
        self.behind_ping_sent_time = Utc::now().timestamp();
    }

    pub fn need_behind_ping(&self) -> bool {
        self.behind_ping_sent_time + 5 < Utc::now().timestamp()
    }
}

impl Default for Peers {
    fn default() -> Self {
        Self::new()
    }
}

/// Gets new token from old token, mutating the last
pub fn next(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
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
