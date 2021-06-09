extern crate ed25519_dalek;
extern crate rand;
extern crate serde;
extern crate serde_json;

use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{atomic, Arc, Mutex};
use std::time::Instant;
use std::{fs, thread};

use blakeout::Blakeout;
use ed25519_dalek::Keypair;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_old::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use self::ed25519_dalek::ed25519::signature::Signature;
use self::ed25519_dalek::{PublicKey, SecretKey, Signer, Verifier};
use crate::blockchain::hash_utils::*;
use crate::bytes::Bytes;
use crate::commons::KEYSTORE_DIFFICULTY;
use crate::crypto::CryptoBox;
use crate::event::Event;
use crate::eventbus::{post, register};
use crate::{from_hex, setup_miner_thread, to_hex, Context};

#[derive(Debug)]
pub struct Keystore {
    keypair: Keypair,
    hash: RefCell<Bytes>,
    path: String,
    crypto_box: CryptoBox,
    old: bool
}

impl Keystore {
    pub fn new() -> Self {
        let mut csprng = rand_old::thread_rng();
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        let crypto_box = CryptoBox::generate(&mut csprng);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), crypto_box, old: false }
    }

    pub fn from_random<R>(csprng: &mut R) -> Self where R: CryptoRng + RngCore {
        let keypair = ed25519_dalek::Keypair::generate(csprng);
        let crypto_box = CryptoBox::generate(csprng);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), crypto_box, old: false }
    }

    pub fn from_bytes(seed: &[u8]) -> Self {
        let keypair = Keypair::from_bytes(seed).expect("Error creating keypair from bytes!");
        let mut csprng = rand_old::thread_rng();
        let crypto_box = CryptoBox::generate(&mut csprng);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), crypto_box, old: false }
    }

    pub fn from_random_bytes(key: &[u8]) -> Self {
        let secret = SecretKey::from_bytes(&key).unwrap();
        let public = PublicKey::from(&secret);
        let keypair = Keypair { secret, public };
        let mut csprng = rand_old::thread_rng();
        let crypto_box = CryptoBox::generate(&mut csprng);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), crypto_box, old: false }
    }

    pub fn from_file(filename: &str, _password: &str) -> Option<Self> {
        let path = Path::new(filename);
        match fs::read(&path) {
            Ok(key) => {
                match toml::from_slice::<Keys>(key.as_slice()) {
                    Ok(keys) => {
                        let secret = SecretKey::from_bytes(&from_hex(&keys.signing.secret).unwrap()).unwrap();
                        let public = PublicKey::from_bytes(&from_hex(&keys.signing.public).unwrap()).unwrap();
                        let keypair = Keypair { secret, public };
                        let crypto_box = CryptoBox::from_strings(&keys.encryption.secret, &keys.encryption.public);
                        let keystore = Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::from(filename), crypto_box, old: false };
                        let bytes = Bytes::from_bytes(&keystore.keypair.public.to_bytes());
                        if check_public_key_strength(&bytes, KEYSTORE_DIFFICULTY) {
                            Some(keystore)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        error!("Error loading keystore from {}: {}", filename, e);
                        None
                    }
                }
            }
            Err(_) => {
                None
            }
        }
    }

    pub fn save(&mut self, filename: &str, _password: &str) {
        match File::create(Path::new(filename)) {
            Ok(mut f) => {
                //TODO implement key encryption
                let keys = self.get_keys();
                let data = toml::to_string(&keys).unwrap();
                f.write_all(data.trim().as_bytes()).expect("Error saving keystore");
                self.path = filename.to_owned();
            }
            Err(_) => { error!("Error saving key file!"); }
        }
    }

    pub fn get_public(&self) -> Bytes {
        Bytes::from_bytes(&self.keypair.public.to_bytes())
    }

    pub fn get_private(&self) -> Bytes {
        Bytes::from_bytes(&self.keypair.secret.to_bytes())
    }

    pub fn get_encryption_public(&self) -> Bytes {
        Bytes::from_bytes(self.crypto_box.public.as_bytes())
    }

    pub fn get_keys(&self) -> Keys {
        let signing = KeyPack::new(to_hex(&self.keypair.public.to_bytes()), to_hex(&self.keypair.secret.to_bytes()));
        let encryption = KeyPack::new(to_hex(&self.crypto_box.public.to_bytes()), to_hex(&self.crypto_box.secret.to_bytes()));
        Keys::new(false, signing, encryption)
    }

    pub fn get_path(&self) -> &str {
        &self.path
    }

    pub fn get_hash(&self) -> Bytes {
        if self.hash.borrow().is_empty() {
            self.hash.replace(blakeout_data(&self.get_public()));
        }
        self.hash.borrow().clone()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.keypair.sign(message).to_bytes()
    }

    pub fn check(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
        let key = PublicKey::from_bytes(public_key).expect("Wrong public key!");
        let signature = Signature::from_bytes(signature).unwrap();
        match key.verify(message, &signature) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    pub fn encrypt(&self, message: &[u8]) -> Bytes {
        let encrypted = self.crypto_box.hide(message).unwrap();
        Bytes::from_bytes(&encrypted)
    }

    pub fn decrypt(&self, message: &[u8]) -> Bytes {
        match self.crypto_box.reveal(message) {
            Ok(decrypted) => Bytes::from_bytes(&decrypted),
            Err(_) => {
                warn!("Decryption failed");
                Bytes::default()
            }
        }
    }
}

impl Clone for Keystore {
    fn clone(&self) -> Self {
        let keypair = Keypair::from_bytes(&self.keypair.to_bytes()).unwrap();
        Self { keypair, hash: RefCell::new(Bytes::default()), path: self.path.clone(), crypto_box: self.crypto_box.clone(), old: self.old }
    }
}

impl PartialEq for Keystore {
    fn eq(&self, other: &Self) -> bool {
        self.keypair.to_bytes().eq(&other.keypair.to_bytes())
    }
}

/// Checks if some public key is "strong" enough to mine domains
/// TODO Optimize by caching Blakeout somewhere
pub fn check_public_key_strength(key: &Bytes, strength: u32) -> bool {
    let bytes = blakeout_data(&key);
    key_hash_difficulty(&bytes) >= strength
}

pub fn create_key(context: Arc<Mutex<Context>>) {
    let mining = Arc::new(AtomicBool::new(true));
    let miners_count = Arc::new(AtomicUsize::new(0));
    post(Event::KeyGeneratorStarted);
    let lower = context.lock().unwrap().settings.mining.lower;
    let threads = context.lock().unwrap().settings.mining.threads;
    let threads = match threads {
        0 => num_cpus::get(),
        _ => threads
    };
    for cpu in 0..threads {
        let context = Arc::clone(&context);
        let mining = mining.clone();
        let miners_count = miners_count.clone();
        thread::spawn(move || {
            miners_count.fetch_add(1, atomic::Ordering::SeqCst);
            if lower {
                setup_miner_thread(cpu as u32);
            }
            match generate_key(KEYSTORE_DIFFICULTY, mining.clone()) {
                None => {
                    debug!("Keystore mining finished");
                }
                Some(keystore) => {
                    let mut context = context.lock().unwrap();
                    let hash = keystore.get_hash().to_string();
                    let path = keystore.get_path().to_owned();
                    let public = keystore.get_public().to_string();
                    info!("Key mined successfully! Public key: {}, hash: {}", &public, &hash);
                    context.add_keystore(keystore);
                    post(Event::KeyCreated { path, public, hash });
                }
            }
            let miners = miners_count.fetch_sub(1, atomic::Ordering::SeqCst) - 1;
            if miners == 0 {
                post(Event::KeyGeneratorStopped);
            }
        });
    }
    register(move |_uuid, e| {
        if e == Event::ActionStopMining {
            info!("Stopping keystore miner");
            mining.store(false, atomic::Ordering::SeqCst);
            false
        } else {
            true
        }
    });
}

fn generate_key(difficulty: u32, mining: Arc<AtomicBool>) -> Option<Keystore> {
    use self::rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut time = Instant::now();
    let mut count = 0u128;
    let mut digest = Blakeout::default();
    let mut buf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut buf);
        let secret = SecretKey::from_bytes(&buf).unwrap();
        let public = PublicKey::from(&secret);
        digest.reset();
        digest.update(public.as_bytes());
        if key_hash_difficulty(digest.result()) >= difficulty {
            mining.store(false, atomic::Ordering::SeqCst);
            let keystore = Keystore::from_random_bytes(&buf);
            return Some(keystore);
        }
        if !mining.load(atomic::Ordering::SeqCst) {
            return None;
        }
        let elapsed = time.elapsed().as_millis();
        if elapsed >= 60000 {
            debug!("Mining speed {} H/s", count / 60);
            time = Instant::now();
            count = 0;
        }
        count += 1;
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPack {
    public: String,
    secret: String
}

impl KeyPack {
    pub fn new(public: String, secret: String) -> Self {
        Self { public, secret }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Keys {
    encrypted: bool,
    signing: KeyPack,
    encryption: KeyPack
}

impl Keys {
    pub fn new(encrypted: bool, signing: KeyPack, encryption: KeyPack) -> Self {
        Self { encrypted, signing, encryption }
    }
}

#[cfg(test)]
mod tests {
    use crate::Keystore;

    #[test]
    pub fn test_signature() {
        let keystore: Keystore = Keystore::new();
        let data = b"{ identity: 178135D209C697625E3EC71DA5C760382E54936F824EE5083908DA66B14ECE18,\
    confirmation: A4A0AFECD1A511825226F0D3437C6C6BDAE83554040AA7AEB49DEFEAB0AE9EA4 }";
        let signature = keystore.sign(data);
        assert!(Keystore::check(data, &keystore.get_public(), &signature), "Wrong signature!")
    }
}