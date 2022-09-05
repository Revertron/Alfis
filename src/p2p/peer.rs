use std::net::SocketAddr;
use std::time::Instant;

use mio::net::TcpStream;

use crate::crypto::Chacha;
use crate::p2p::State;

#[derive(Debug)]
pub struct Peer {
    addr: SocketAddr,
    stream: TcpStream,
    state: State,
    id: String,
    height: u64,
    inbound: bool,
    public: bool,
    active: bool,
    last_active: Instant,
    reconnects: u32,
    received_block: u64,
    sent_height: u64,
    cipher: Option<Chacha>
}

impl Peer {
    pub fn new(addr: SocketAddr, stream: TcpStream, state: State, inbound: bool) -> Self {
        Peer {
            addr,
            stream,
            state,
            id: String::new(),
            height: 0,
            inbound,
            public: false,
            active: false,
            last_active: Instant::now(),
            reconnects: 0,
            received_block: 0,
            sent_height: 0,
            cipher: None
        }
    }

    pub fn set_cipher(&mut self, cipher: Chacha) {
        self.cipher = Some(cipher);
    }

    pub fn get_cipher(&self) -> &Option<Chacha> {
        &self.cipher
    }

    pub fn get_nonce(&self) -> &[u8] {
        match &self.cipher {
            None => &crate::crypto::ZERO_NONCE,
            Some(chacha) => chacha.get_nonce()
        }
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn get_stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn set_stream(&mut self, stream: TcpStream) {
        self.stream = stream;
    }

    pub fn get_state(&self) -> &State {
        &self.state
    }

    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn set_sent_height(&mut self, height: u64) {
        self.sent_height = height;
    }

    pub fn get_sent_height(&self) -> u64 {
        self.sent_height
    }

    pub fn is_higher(&self, height: u64) -> bool {
        self.height > height
    }

    pub fn is_lower(&self, height: u64) -> bool {
        self.height < height
    }

    pub fn set_received_block(&mut self, index: u64) {
        self.received_block = index;
    }

    pub fn has_more_blocks(&self, height: u64) -> bool {
        if self.height <= height {
            return false;
        }
        if self.received_block > height {
            return false;
        }
        if !self.get_state().is_idle() {
            return false;
        }
        self.height > height
    }

    pub fn is_public(&self) -> bool {
        self.public
    }

    pub fn set_public(&mut self, public: bool) {
        self.public = public;
    }

    pub fn set_active(&mut self, active: bool) {
        self.active = active;
        if active {
            self.last_active = Instant::now();
        }
    }

    pub fn active(&self) -> bool {
        self.active && self.last_active.elapsed().as_secs() < 120
    }

    pub fn reconnects(&self) -> u32 {
        self.reconnects
    }

    pub fn inc_reconnects(&mut self) {
        self.reconnects += 1;
    }

    pub fn reset_reconnects(&mut self) {
        self.reconnects = 0;
    }

    pub fn disabled(&self) -> bool {
        self.state.disabled() || self.reconnects > 2
    }

    pub fn is_inbound(&self) -> bool {
        self.inbound
    }

    /// If loopback address then we care about ip and port.
    /// If regular address then we only care about the ip and ignore the port.
    pub fn equals(&self, addr: &SocketAddr) -> bool {
        if self.addr.ip().is_loopback() {
            self.addr == *addr
        } else {
            self.addr.ip() == addr.ip()
        }
    }
}