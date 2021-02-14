extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Error,
    Hand { origin: String, version: u32, public: bool },
    Shake { origin: String, version: u32, ok: bool, height: u64 },
    Ping { height: u64 },
    Pong { height: u64 },
    GetPeers,
    Peers { peers: Vec<String> },
    GetBlock { index: u64 },
    Block { index: u64, block: String },
}

impl Message {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ()> {
        let text = String::from_utf8(bytes).unwrap_or(String::from("Error{}"));
        match serde_json::from_str(&text) {
            Ok(cmd) => Ok(cmd),
            Err(_) => Err(())
        }
    }

    pub fn hand(origin: &str, version: u32, public: bool) -> Self {
        Message::Hand { origin: origin.to_owned(), version, public }
    }

    pub fn shake(origin: &str, version: u32, ok: bool, height: u64) -> Self {
        Message::Shake { origin: origin.to_owned(), version, ok, height }
    }

    pub fn ping(height: u64) -> Self {
        Message::Ping { height }
    }

    pub fn pong(height: u64) -> Self {
        Message::Pong { height }
    }

    pub fn block(height: u64, str: String) -> Self {
        Message::Block { index: height, block: str }
    }
}
