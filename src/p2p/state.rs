use std::time::Instant;
use crate::p2p::Message;

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Connecting,
    Connected,
    Idle { from: Instant },
    Message { data: Vec<u8> },
    Error,
    Banned,
    Offline { from: Instant },
}

impl State {
    pub fn idle() -> Self {
        Self::Idle { from: Instant::now() }
    }

    pub fn offline() -> Self {
        Self::Offline { from: Instant::now() }
    }

    pub fn message(message: Message) -> Self {
        let response = serde_json::to_string(&message).unwrap();
        State::Message {data: Vec::from(response.as_bytes()) }
    }

    pub fn active(&self) -> bool {
        match self {
            State::Connecting => { true }
            State::Connected => { true }
            State::Idle { .. } => { true }
            State::Message { .. } => { true }
            _ => { false }
        }
    }

    pub fn is_idle(&self) -> bool {
        match self {
            State::Idle { .. } => { true }
            _ => { false }
        }
    }

    pub fn disabled(&self) -> bool {
        match self {
            State::Error => { true }
            State::Banned => { true }
            State::Offline { from} => {
                from.elapsed().as_secs() < 60 // We check offline peers to become online every 5 minutes
            }
            _ => { false }
        }
    }

    pub fn need_reconnect(&self) -> bool {
        match self {
            State::Offline { from } => { from.elapsed().as_secs() > 60 }
            _ => { false }
        }
    }
}
