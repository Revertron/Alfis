use blakeout::Blakeout;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_bigint::BigUint;
use num_traits::One;

use crate::{Block, Bytes, Keystore};

/// Creates needed hasher by current blockchain version
pub(crate) fn get_hasher_for_version(version: u32) -> Box<dyn Digest> {
    match version {
        2 => Box::new(Blakeout::default()),
        _ => Box::new(Sha256::new())
    }
}

/// Checks block's hash and returns true on valid hash or false otherwise
pub fn check_block_hash(block: &Block) -> bool {
    let mut copy: Block = block.clone();
    copy.hash = Bytes::default();
    copy.signature = Bytes::default();
    let data = serde_json::to_string(&copy).unwrap();
    let mut hasher = get_hasher_for_version(block.version);
    hash_data(&mut *hasher, data.as_bytes()) == block.hash
}

/// Hashes data by given hasher
pub fn hash_data(digest: &mut dyn Digest, data: &[u8]) -> Bytes {
    let mut buf = match digest.output_bytes() {
        32 => Bytes::zero32(),
        64 => Bytes::zero64(),
        _ => panic!("Supplied wrong digest!")
    };

    digest.input(data);
    digest.result(buf.as_mut_slice());
    buf
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
    let mut buf: [u8; 32] = [0; 32];
    let mut digest = Sha256::new();
    digest.input_str(identity);
    if let Some(key) = key {
        digest.input(key.as_slice());
    }
    digest.result(&mut buf);
    Bytes::from_bytes(&buf)
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
