extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use crate::Bytes;

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Error,
    Hand { app_version: String, origin: String, version: u32, public: bool, rand_id: String, },
    Shake { app_version: String, origin: String, version: u32, public: bool, rand_id: String, height: u64 },
    Ping { height: u64, hash: Bytes },
    Pong { height: u64, hash: Bytes },
    Twin,
    Loop,
    GetPeers,
    Peers { peers: Vec<String> },
    GetBlock { index: u64 },
    Block { index: u64, block: Vec<u8> },
}

impl Message {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ()> {
        match serde_cbor::from_slice(bytes.as_slice()) {
            Ok(cmd) => Ok(cmd),
            Err(_) => Err(())
        }
    }

    pub fn hand(app_version: &str, origin: &str, version: u32, public: bool, rand_id: &str) -> Self {
        Message::Hand { app_version: app_version.to_owned(), origin: origin.to_owned(), version, public, rand_id: rand_id.to_owned() }
    }

    pub fn shake(app_version: &str, origin: &str, version: u32, public: bool, rand_id: &str, height: u64) -> Self {
        Message::Shake { app_version: app_version.to_owned(), origin: origin.to_owned(), version, public, rand_id: rand_id.to_owned(), height }
    }

    pub fn ping(height: u64, hash: Bytes) -> Self {
        Message::Ping { height, hash }
    }

    pub fn pong(height: u64, hash: Bytes) -> Self {
        Message::Pong { height, hash }
    }

    pub fn block(height: u64, block: Vec<u8>) -> Self {
        Message::Block { index: height, block }
    }
}