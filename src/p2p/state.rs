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
    Offline { from: Instant, attempts: usize },
}

impl State {
    pub fn idle() -> Self {
        Self::Idle { from: Instant::now() }
    }

    pub fn offline(attempts: usize) -> Self {
        Self::Offline { attempts, from: Instant::now() }
    }

    pub fn still_offline(state: Self) -> Self {
        match state {
            State::Offline { attempts, from } => {
                Self::Offline { attempts: attempts + 1, from }
            }
            _ => {
                Self::Offline { attempts: 1, from: Instant::now() }
            }
        }
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

    pub fn disabled(&self) -> bool {
        match self {
            State::Error => { true }
            State::Banned => { true }
            State::Offline { from, attempts } => {
                from.elapsed().as_secs() < 60 // We check offline peers to become online every 5 minutes
            }
            _ => { false }
        }
    }
}
