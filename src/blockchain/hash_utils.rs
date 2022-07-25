use std::convert::TryInto;

use blakeout::Blakeout;
use sha2::{Digest, Sha256};

use crate::{Block, Bytes, Keystore};

/// Checks block's hash and returns true on valid hash or false otherwise
pub fn check_block_hash(block: &Block) -> bool {
    // If this block's hash was already checked as good
    if block.is_hash_good() {
        return true;
    }
    let mut copy: Block = block.clone();
    copy.hash = Bytes::default();
    copy.signature = Bytes::default();
    let good = blakeout_data(&copy.as_bytes_compact()) == block.hash;
    block.set_hash_good(good);
    good
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
    Keystore::check(&copy.as_bytes_compact(), &copy.pub_key, &block.signature)
}

/// Hashes some identity (domain in case of DNS). If you give it a public key, it will hash with it as well.
/// Giving public key is needed to create a confirmation field in [Transaction](crate::blockchain::Transaction)
pub fn hash_identity(identity: &str, key: Option<&Bytes>) -> Bytes {
    let mut base = hash_sha256(identity.as_bytes());
    let identity = hash_sha256(&base);
    match key {
        None => Bytes::from_bytes(&identity),
        Some(key) => {
            let mut buf = Vec::new();
            buf.append(&mut base);
            buf.append(&mut key.to_vec());
            Bytes::from_bytes(&hash_sha256(&buf))
        }
    }
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

/// Returns hash difficulty (sum of zeroes from start and end)
#[inline]
pub fn hash_difficulty(hash: &[u8]) -> u32 {
    let bytes: [u8; 8] = hash[..8].try_into().unwrap();
    let int_start = u64::from_be_bytes(bytes);
    let bytes: [u8; 8] = hash[hash.len() - 8..].try_into().unwrap();
    let int_end = u64::from_be_bytes(bytes);
    int_start.leading_zeros() + int_end.trailing_zeros()
}

/// Returns hash difficulty for keys (only from the start)
#[inline]
pub fn key_hash_difficulty(hash: &[u8]) -> u32 {
    let bytes: [u8; 8] = hash[..8].try_into().unwrap();
    let int = u64::from_be_bytes(bytes);
    int.leading_zeros()
}

/// Hashes data by Sha256 algorithm
#[inline]
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::default();
    digest.update(data.as_ref());
    Vec::from(&digest.finalize()[..])
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::blockchain::hash_utils::hash_sha256;

    #[test]
    #[ignore]
    pub fn test_hash() {
        let id = b"example.com";
        let key = b"some_key";

        let base = hash_sha256(id);

        let identity = hash_sha256(&base);

        let mut buf = Vec::new();
        buf.append(&mut identity.clone());
        buf.append(&mut key.to_vec());
        let confirmation = hash_sha256(&buf);

        println!("result1 = {:?}", &base);
        println!("result2 = {:?}", &identity);
        println!("result3 = {:?}", &confirmation);
    }

    #[test]
    #[ignore]
    fn test_hash_is_good() {
        let hash = vec![0u8, 0u8, 0u8, 255, 255, 255, 255, 255];
        let bytes: [u8; 8] = hash[..8].try_into().unwrap();
        let int = u64::from_be_bytes(bytes);
        println!("int = {}", int);
    }
}
