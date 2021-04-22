extern crate serde;
extern crate serde_json;

use std::fmt::Debug;
use serde::{Serialize, Deserialize};
use crate::bytes::Bytes;
use crate::Transaction;
use crate::blockchain::hash_utils::{hash_difficulty, key_hash_difficulty};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub version: u32,
    pub difficulty: u32,
    pub random: u32,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Transaction>,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub prev_block_hash: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub hash: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub pub_key: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub signature: Bytes,
}

impl Block {
    pub fn new(transaction: Option<Transaction>, pub_key: Bytes, prev_block_hash: Bytes, difficulty: u32) -> Self {
        Block {
            index: 0,
            timestamp: 0,
            version: 0,
            difficulty,
            random: 0,
            nonce: 0,
            transaction,
            prev_block_hash,
            hash: Bytes::default(),
            pub_key,
            signature: Bytes::default()
        }
    }

    pub fn from_all_params(index: u64, timestamp: i64, version: u32, difficulty: u32, random: u32, nonce: u64, prev_block_hash: Bytes, hash: Bytes, pub_key: Bytes, signature: Bytes, transaction: Option<Transaction>) -> Self {
        Block {
            index,
            timestamp,
            version,
            difficulty,
            random,
            nonce,
            transaction,
            prev_block_hash,
            hash,
            pub_key,
            signature
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.index == 1 && self.transaction.is_none() && self.prev_block_hash == Bytes::default()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Vec::from(serde_json::to_string(&self).unwrap().as_bytes())
    }

    /// Checks if this block is superior than the other
    pub fn is_better_than(&self, other: &Block) -> bool {
        if self.transaction.is_some() && other.transaction.is_none() {
            return true;
        }
        let my_diff = hash_difficulty(self.hash.as_slice()) + key_hash_difficulty(self.hash.as_slice());
        let it_diff = hash_difficulty(other.hash.as_slice()) + key_hash_difficulty(other.hash.as_slice());
        if my_diff > it_diff {
            return true;
        }

        false
    }
}