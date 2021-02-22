use crate::p2p::State;
use std::net::SocketAddr;
use mio::net::TcpStream;

#[derive(Debug)]
pub struct Peer {
    addr: SocketAddr,
    stream: TcpStream,
    state: State,
    height: u64,
    inbound: bool,
    public: bool,
}

impl Peer {
    pub fn new(addr: SocketAddr, stream: TcpStream, state: State, inbound: bool) -> Self {
        Peer { addr, stream, state, height: 0, inbound, public: false }
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr.clone()
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

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn is_higher(&self, height: u64) -> bool {
        self.height > height
    }

    pub fn is_public(&self) -> bool {
        self.public
    }

    pub fn set_public(&mut self, public: bool) {
        self.public = public;
    }

    pub fn active(&self) -> bool {
        self.state.active()
    }

    pub fn disabled(&self) -> bool {
        self.state.disabled()
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