use crate::p2p::State;

pub struct Peer {
    addr: String,
    state: State,
}

impl Peer {
    pub fn new(addr: String, state: State) -> Self {
        Peer { addr, state }
    }

    pub fn get_state(&self) -> &State {
        &self.state
    }

    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }
}