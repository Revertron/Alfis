use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use std::fmt::{Debug, Formatter};
use std::fmt;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

/// A small wrap-up to use Chacha20 encryption for domain names.
#[derive(Clone)]
pub struct Chacha {
    pub cipher: ChaCha20Poly1305
}

impl Chacha {
    pub fn new(seed: &[u8]) -> Self {
        let key = Key::from_slice(seed);
        let cipher = ChaCha20Poly1305::new(key);
        Chacha { cipher }
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(nonce);
        match self.cipher.encrypt(nonce, data.as_ref()) {
            Ok(bytes) => { bytes }
            Err(_) => {
                warn!("Error encrypting data!");
                Vec::new()
            }
        }
    }

    pub fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(nonce);
        match self.cipher.decrypt(nonce, data.as_ref()) {
            Ok(bytes) => { bytes }
            Err(_) => {
                warn!("Error decrypting data!");
                Vec::new()
            }
        }
    }
}

impl Debug for Chacha {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.write_str("ChaCha20Poly1305")
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Chacha;
    use crate::to_hex;

    #[test]
    pub fn test_curved_chacha() {
        let buf = b"178135D209C697625E3EC71DA5C760382E54936F824EE5083908DA66B14ECE18";
        let keys1 = Chacha::new(b"178135D209C697625E3EC71DA5C76038", );
        let bytes = keys1.encrypt(b"TEST", &buf[..12]);
        println!("{}", to_hex(&bytes));

        let keys2 = Chacha::new(b"178135D209C697625E3EC71DA5C76038");
        let bytes2 = keys2.decrypt(&bytes, &buf[..12]);

        assert_eq!(String::from_utf8(bytes2).unwrap(), "TEST");
    }
}