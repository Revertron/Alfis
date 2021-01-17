extern crate serde;
extern crate serde_json;
extern crate num_bigint;
extern crate num_traits;

use super::*;
use std::fmt::Debug;
use chrono::Utc;
use serde::{Serialize, Deserialize};
use num_bigint::BigUint;
use num_traits::One;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crate::keys::Bytes;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub chain_id: u32,
    pub version: u32,
    pub difficulty: usize,
    pub random: u32,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Transaction>,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub prev_block_hash: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub hash: Bytes,
}

impl Block {
    pub fn new(index: u64, timestamp: i64, chain_id: u32, version: u32, prev_block_hash: Bytes, transaction: Option<Transaction>) -> Self {
        Block {
            index,
            timestamp,
            chain_id,
            version,
            // TODO make difficulty parameter
            difficulty: 20,
            random: 0,
            nonce: 0,
            transaction,
            prev_block_hash,
            hash: Bytes::default(),
        }
    }

    pub fn hash(data: &[u8]) -> Bytes {
        let mut buf: [u8; 32] = [0; 32];
        let mut digest = Sha256::new();
        digest.input(data);
        digest.result(&mut buf);
        Bytes::new(buf.to_vec())
    }

    pub fn is_genesis(&self) -> bool {
        self.index == 0 && self.transaction.is_none() && self.prev_block_hash == Bytes::default()
    }
}