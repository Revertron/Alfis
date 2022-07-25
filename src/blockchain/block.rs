extern crate serde;
extern crate serde_json;

use std::cell::RefCell;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::blockchain::hash_utils::{hash_difficulty, key_hash_difficulty};
use crate::blockchain::transaction::TransactionType;
use crate::bytes::Bytes;
use crate::Transaction;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub version: u32,
    pub difficulty: u32,
    pub random: u32,
    pub nonce: u64,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub hash: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub prev_block_hash: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub pub_key: Bytes,
    #[serde(default, skip_serializing_if = "Bytes::is_zero")]
    pub signature: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Transaction>,
    #[serde(default, skip)]
    hash_good: RefCell<bool>
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
            signature: Bytes::default(),
            hash_good: RefCell::new(false)
        }
    }

    #[allow(clippy::too_many_arguments)]
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
            signature,
            hash_good: RefCell::new(false)
        }
    }

    pub fn from_bytes(data: &[u8]) -> serde_cbor::Result<Self> {
        serde_cbor::from_slice(data)
    }

    pub fn is_genesis(&self) -> bool {
        self.index == 1 &&
            matches!(Transaction::get_type(&self.transaction), TransactionType::Origin) &&
            self.prev_block_hash == Bytes::default()
    }

    pub fn is_hash_good(&self) -> bool {
        *self.hash_good.borrow()
    }

    pub fn set_hash_good(&self, good: bool) {
        *self.hash_good.borrow_mut() = good;
    }

    /// Serializes block to CBOR for network
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }

    /// Serializes block to bincode format for hashing.
    pub fn as_bytes_compact(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Checks if this block is superior than the other
    pub fn is_better_than(&self, other: &Block) -> bool {
        if self.transaction.is_some() && other.transaction.is_none() {
            return true;
        }
        let hash_diff = hash_difficulty(self.hash.as_slice()) + key_hash_difficulty(self.hash.as_slice());
        let my_diff = (hash_diff << 16) + (self.hash.get_tail_u64() % 0xFFFF) as u32;
        let hash_diff = hash_difficulty(other.hash.as_slice()) + key_hash_difficulty(other.hash.as_slice());
        let it_diff = (hash_diff << 16) + (other.hash.get_tail_u64() % 0xFFFF) as u32;

        if my_diff > it_diff {
            return true;
        }

        if my_diff == it_diff && self.nonce != other.nonce {
            return self.nonce < other.nonce;
        }

        false
    }
}