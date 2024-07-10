use std::time::Instant;

use crate::p2p::Message;

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Connecting,
    Connected { from: Instant },
    ServerHandshake { from: Instant },
    HandshakeFinished,
    Idle { from: Instant },
    Message { data: Vec<u8> },
    Error,
    Banned,
    SendLoop,
    Loop,
    Twin,
    Offline { from: Instant }
}

impl State {
    pub fn idle() -> Self {
        Self::Idle { from: Instant::now() }
    }

    pub fn offline() -> Self {
        Self::Offline { from: Instant::now() }
    }

    pub fn message(message: Message) -> Self {
        let data = serde_cbor::to_vec(&message).unwrap();
        State::Message { data }
    }

    pub fn is_idle(&self) -> bool {
        matches!(self, State::Idle { .. })
    }

    pub fn is_timed_out(&self) -> bool {
        match self {
            State::Error => true,
            State::Banned => true,
            State::Idle { from } => {
                from.elapsed().as_secs() > 60
            }
            State::Connected { from } => {
                from.elapsed().as_secs() > 10
            }
            _ => false
        }
    }

    pub fn is_loop(&self) -> bool {
        matches!(self, State::Loop { .. } | State::SendLoop { .. })
    }

    pub fn disabled(&self) -> bool {
        match self {
            State::Error => true,
            State::Banned => true,
            State::Offline { from } => {
                from.elapsed().as_secs() < 60 // We check offline peers to become online every 5 minutes
            }
            _ => false
        }
    }

    pub fn need_reconnect(&self) -> bool {
        match self {
            State::Offline { from } => from.elapsed().as_secs() > 60,
            _ => false
        }
    }
}
