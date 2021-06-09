use std::fmt;
use std::fmt::{Debug, Formatter};

use ecies_ed25519::{decrypt, encrypt, Error, PublicKey, SecretKey};
use rand_old::{CryptoRng, RngCore};

use crate::{from_hex, to_hex};

pub struct CryptoBox {
    pub(crate) secret: SecretKey,
    pub(crate) public: PublicKey
}

impl CryptoBox {
    pub fn new(seed: &[u8]) -> Self {
        let secret = SecretKey::from_bytes(seed).expect("Unable to parse secret key");
        let public = PublicKey::from_secret(&secret);
        Self { secret, public }
    }

    pub fn generate<R>(csprng: &mut R) -> Self where R: CryptoRng + RngCore {
        let (secret, public) = ecies_ed25519::generate_keypair(csprng);
        Self { secret, public }
    }

    pub fn from_strings(secret: &str, public: &str) -> Self {
        let secret = SecretKey::from_bytes(&from_hex(secret).unwrap()).unwrap();
        let public = PublicKey::from_bytes(&from_hex(public).unwrap()).unwrap();
        Self { secret, public }
    }

    pub fn hide(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let mut random = rand_old::thread_rng();
        encrypt(&self.public, msg, &mut random)
    }

    pub fn reveal(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        decrypt(&self.secret, msg)
    }

    pub fn encrypt(public: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        let public = PublicKey::from_bytes(public).unwrap();
        let mut random = rand_old::thread_rng();
        encrypt(&public, message, &mut random)
    }

    pub fn decrypt(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        let secret = SecretKey::from_bytes(secret).unwrap();
        decrypt(&secret, &message)
    }
}

impl Debug for CryptoBox {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoBox")
            .field("public", &to_hex(&self.public.to_bytes()))
            .finish()
    }
}

impl Clone for CryptoBox {
    fn clone(&self) -> Self {
        let secret = SecretKey::from_bytes(&self.secret.as_bytes()[..]).expect("Unable clone secret key");
        let public = PublicKey::from_secret(&secret);
        Self { secret, public }
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use crate::crypto::CryptoBox;

    const TEXT: &str = "Some very secret message";

    #[test]
    pub fn hide_reveal() {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let coder = CryptoBox::new(&buf);
        let encrypted = coder.hide(TEXT.as_bytes()).unwrap();
        let decrypted = coder.reveal(&encrypted.as_slice()).unwrap();

        assert_eq!(TEXT, &String::from_utf8(decrypted).unwrap());
    }
}