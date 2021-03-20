extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use crate::Bytes;

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Error,
    Hand { origin: String, version: u32, public: bool, #[serde(default)] rand: String },
    Shake { origin: String, version: u32, ok: bool, height: u64 },
    Ping { height: u64, hash: Bytes },
    Pong { height: u64, hash: Bytes },
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

    pub fn hand(origin: &str, version: u32, public: bool, rand: &str) -> Self {
        Message::Hand { origin: origin.to_owned(), version, public, rand: rand.to_owned() }
    }

    pub fn shake(origin: &str, version: u32, ok: bool, height: u64) -> Self {
        Message::Shake { origin: origin.to_owned(), version, ok, height }
    }

    pub fn ping(height: u64, hash: Bytes) -> Self {
        Message::Ping { height, hash }
    }

    pub fn pong(height: u64, hash: Bytes) -> Self {
        Message::Pong { height, hash }
    }

    pub fn block(height: u64, str: String) -> Self {
        Message::Block { index: height, block: str }
    }
}

#[cfg(test)]
mod tests {
    use crate::p2p::Message;

    #[test]
    pub fn test_hand() {
        assert!(serde_json::from_str::<Message>("\"Error\"").is_ok());
        assert!(serde_json::from_str::<Message>("{\"Hand\":{\"origin\":\"\",\"version\":1,\"public\":false,\"rand\":\"123\"}}").is_ok());
        assert!(serde_json::from_str::<Message>("{\"Hand\":{\"origin\":\"\",\"version\":1,\"public\":false}}").is_ok());
    }

}