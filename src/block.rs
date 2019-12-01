extern crate serde;
extern crate serde_json;
extern crate num_bigint;
extern crate num_traits;

use super::*;
use rand::{thread_rng, Rng};
use std::fmt::Debug;
use chrono::{Utc, DateTime};
use serde::{Serialize, Deserialize};
use num_bigint::BigUint;
use num_traits::One;
use crypto::sha2::Sha512;
use crypto::digest::Digest;

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
    pub prev_block_hash: Hash,
    #[serde(skip_serializing_if = "Hash::is_default")]
    pub hash: Hash,
}

impl Block {
    pub fn new(index: u64, timestamp: i64, chain_id: u32, version: u32, prev_block_hash: Hash, transaction: Option<Transaction>) -> Self {
        Block {
            index,
            timestamp,
            chain_id,
            version,
            difficulty: 18,
            random: 0,
            nonce: 0,
            transaction,
            prev_block_hash,
            hash: Hash::default(),
        }
    }

    pub fn mine(&mut self) {
        self.random = rand::random();
        let data = serde_json::to_string(&self).unwrap();
        println!("Mining block:\n{}", data);
        for nonce_attempt in 0..std::u64::MAX {
            self.nonce = nonce_attempt;
            self.timestamp = Utc::now().timestamp();
            let hash = Self::hash(serde_json::to_string(&self).unwrap().as_bytes());
            if hash_is_good(&hash.as_bytes(), self.difficulty) {
                self.hash = hash;
                return;
            }
        }
    }

    pub fn hash(data: &[u8]) -> Hash {
        let mut buf: [u8; 64] = [0; 64];
        let mut digest = Sha512::new();
        digest.input(data);
        digest.result(&mut buf);
        Hash::from_vec(&buf.to_vec())
    }

    pub fn is_genesis(&self) -> bool {
        self.index == 0 && self.transaction.is_none() && self.prev_block_hash == Hash::default()
    }
}

fn hash_is_good(hash: &[u8], difficulty: usize) -> bool {
    let target = BigUint::one() << ((hash.len() << 3) - difficulty);
    let hash_int = BigUint::from_bytes_be(&hash);

    return hash_int < target;
}