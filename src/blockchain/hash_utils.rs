use blakeout::Blakeout;
use num_bigint::BigUint;
use num_traits::One;

use crate::{Block, Bytes, Keystore};
use sha2::{Sha256, Digest};

/// Checks block's hash and returns true on valid hash or false otherwise
pub fn check_block_hash(block: &Block) -> bool {
    let mut copy: Block = block.clone();
    copy.hash = Bytes::default();
    copy.signature = Bytes::default();
    let data = serde_json::to_string(&copy).unwrap();
    blakeout_data(data.as_bytes()) == block.hash
}

/// Hashes data by given hasher
pub fn blakeout_data(data: &[u8]) -> Bytes {
    let mut digest = Blakeout::default();
    digest.update(data);
    Bytes::from_bytes(digest.result())
}

/// Checks block's signature, returns true if the signature is valid, false otherwise
pub fn check_block_signature(block: &Block) -> bool {
    let mut copy = block.clone();
    copy.signature = Bytes::default();
    Keystore::check(&copy.as_bytes(), &copy.pub_key, &block.signature)
}

/// Hashes some identity (domain in case of DNS). If you give it a public key, it will hash with it as well.
/// Giving public key is needed to create a confirmation field in [Transaction]
pub fn hash_identity(identity: &str, key: Option<&Bytes>) -> Bytes {
    let mut digest = Sha256::default();
    digest.update(identity.as_bytes());
    if let Some(key) = key {
        digest.update(key.as_slice());
    }
    Bytes::from_bytes(&digest.finalize()[..])
}

/// There is no default PartialEq implementation for arrays > 32 in size
pub fn same_hash(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // We iterate whole slices to eliminate timing attacks
    let mut result = true;
    for (x, y) in left.iter().zip(right) {
        if x != y {
            result = false;
        }
    }
    result
}

/// Checks if this hash contains enough zeroes
pub fn hash_is_good(hash: &[u8], difficulty: usize) -> bool {
    let target = BigUint::one() << ((hash.len() << 3) - difficulty);
    let hash_int = BigUint::from_bytes_be(&hash);

    return hash_int < target;
}
