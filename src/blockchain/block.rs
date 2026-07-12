extern crate serde;
extern crate serde_json;

use std::cell::RefCell;
use std::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::blockchain::compact::put_bytes;

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

    /// Serializes the block to its compact hashing/signing preimage.
    ///
    /// This is the consensus preimage for the block hash and signature. The byte layout
    /// reproduces the previous `bincode::serde::encode_to_vec(_, config::legacy())` output
    /// exactly (see [`crate::blockchain::compact`]); it must never change or existing block
    /// hashes and signatures would stop validating.
    pub fn as_bytes_compact(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        // Fixed-width little-endian scalars, in struct field order.
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.difficulty.to_le_bytes());
        out.extend_from_slice(&self.random.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        // `Bytes` fields carry `skip_serializing_if = "Bytes::is_zero"`: omit when zero.
        if !self.hash.is_zero() {
            put_bytes(&mut out, &self.hash);
        }
        if !self.prev_block_hash.is_zero() {
            put_bytes(&mut out, &self.prev_block_hash);
        }
        if !self.pub_key.is_zero() {
            put_bytes(&mut out, &self.pub_key);
        }
        if !self.signature.is_zero() {
            put_bytes(&mut out, &self.signature);
        }
        // `transaction` carries `skip_serializing_if = "Option::is_none"`: `None` omits the
        // field entirely, `Some` emits the bincode `Option` tag (`1u8`) then the value.
        if let Some(transaction) = &self.transaction {
            out.push(1u8);
            transaction.encode_compact(&mut out);
        }
        out
    }

    /// Checks if this block is superior to the other
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

#[cfg(test)]
mod compact_format_tests {
    use crate::blockchain::block::Block;
    use crate::blockchain::transaction::Transaction;
    use crate::bytes::Bytes;
    use crate::commons::to_hex;

    fn b32(fill: u8) -> Bytes {
        Bytes::new(vec![fill; 32])
    }

    fn b64(fill: u8) -> Bytes {
        Bytes::new(vec![fill; 64])
    }

    /// Signing block: no transaction, all hash-fields populated.
    fn block_signing() -> Block {
        Block::from_all_params(
            42, 1_700_000_000, 0, 20, 7, 123456789,
            b32(0x11), // prev_block_hash
            b32(0x22), // hash
            b32(0x33), // pub_key
            b64(0x44), // signature
            None,
        )
    }

    /// Domain block: transaction present, one Bytes field zero (exercises skip).
    fn block_domain() -> Block {
        let tx = Transaction::new(
            b32(0xaa),          // identity
            b32(0xbb),          // confirmation
            String::from("dom"),// class
            String::from("{\"zone\":\"test\"}"), // data
            b32(0xcc),          // signing
            Bytes::default(),   // encryption (zero -> skipped)
        );
        Block::from_all_params(
            1, 1_700_000_001, 0, 24, 0, 987654321,
            Bytes::default(), // prev_block_hash (zero -> skipped)
            b32(0x55),        // hash
            b32(0x66),        // pub_key
            b64(0x77),        // signature
            Some(tx),
        )
    }

    /// Empty block: every skippable field is zero/absent.
    fn block_empty() -> Block {
        Block::from_all_params(
            0, 0, 0, 0, 0, 0,
            Bytes::default(),
            Bytes::default(),
            Bytes::default(),
            Bytes::default(),
            None,
        )
    }

    // Golden bytes captured from bincode 2.0.1 `encode_to_vec(.., config::legacy())`.
    // These are the CONSENSUS PREIMAGE for block hashing and signing: any drift here
    // silently forks the network. A replacement serializer must reproduce these exactly.
    const GOLDEN_SIGNING: &str = "2A0000000000000000F153650000000000000000140000000700000015CD5B070000000040000000000000003232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323240000000000000003131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313140000000000000003333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333380000000000000003434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434";
    const GOLDEN_DOMAIN: &str = "010000000000000001F1536500000000000000001800000000000000B168DE3A0000000040000000000000003535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353535353540000000000000003636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363680000000000000003737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737010300000000000000646F6D4000000000000000414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414000000000000000424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424000000000000000434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343430F000000000000007B227A6F6E65223A2274657374227D";
    const GOLDEN_EMPTY: &str = "000000000000000000000000000000000000000000000000000000000000000000000000";

    /// The consensus-critical byte format of `as_bytes_compact()` must never change.
    /// Fixtures exercise: fixed-int LE scalars, `Bytes` as length-prefixed hex strings,
    /// `skip_serializing_if` (zero `Bytes`/empty `String`/`None` omitted), and `Some(tx)`.
    #[test]
    fn compact_bytes_are_stable() {
        assert_eq!(to_hex(&block_signing().as_bytes_compact()), GOLDEN_SIGNING, "signing block");
        assert_eq!(to_hex(&block_domain().as_bytes_compact()), GOLDEN_DOMAIN, "domain block");
        assert_eq!(to_hex(&block_empty().as_bytes_compact()), GOLDEN_EMPTY, "empty block");
    }
}