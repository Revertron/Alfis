extern crate rand;
extern crate ed25519_dalek;
extern crate serde;
extern crate serde_json;

use std::thread;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, atomic, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize};

use ed25519_dalek::Keypair;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use crate::blockchain::hash_utils::*;
use crate::{Context, setup_miner_thread};
use crate::event::Event;
use crate::commons::KEYSTORE_DIFFICULTY;
use crate::bytes::Bytes;
use blakeout::Blakeout;
use std::time::Instant;
use std::cell::RefCell;
use self::ed25519_dalek::{Signer, PublicKey, Verifier, SecretKey};
use self::ed25519_dalek::ed25519::signature::Signature;
use rand_old::{CryptoRng, RngCore};
use rand_old::rngs::OsRng;
use crate::crypto::Chacha;

#[derive(Debug)]
pub struct Keystore {
    keypair: Keypair,
    hash: RefCell<Bytes>,
    path: String,
    chacha: Chacha
}

impl Keystore {
    pub fn new() -> Self {
        let mut csprng = OsRng::default();
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        let chacha = get_chacha(&keypair);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), chacha }
    }

    pub fn from_random<R>(csprng: &mut R) -> Self where R: CryptoRng + RngCore {
        let keypair = ed25519_dalek::Keypair::generate(csprng);
        let chacha = get_chacha(&keypair);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), chacha }
    }

    pub fn from_bytes(seed: &[u8]) -> Self {
        let keypair = Keypair::from_bytes(seed).expect("Error creating keypair from bytes!");
        let chacha = get_chacha(&keypair);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), chacha }
    }

    pub fn from_random_bytes(key: &[u8]) -> Self {
        let secret = SecretKey::from_bytes(&key).unwrap();
        let public = PublicKey::from(&secret);
        let keypair = Keypair { secret, public };
        let chacha = get_chacha(&keypair);
        Keystore { keypair, hash: RefCell::new(Bytes::default()), path: String::new(), chacha }
    }

    pub fn from_file(filename: &str, _password: &str) -> Option<Self> {
        let path = Path::new(filename);
        match fs::read(&path) {
            Ok(key) => {
                if key.len() == 32 {
                    let mut keystore = Keystore::from_random_bytes(key.as_slice());
                    keystore.path = path.to_str().unwrap().to_owned();
                    let bytes = Bytes::from_bytes(&keystore.keypair.public.to_bytes());
                    return if check_public_key_strength(&bytes, KEYSTORE_DIFFICULTY) {
                        Some(keystore)
                    } else {
                        None
                    };
                }
                let mut keystore = Self::from_bytes(key.as_slice());
                keystore.path = path.to_str().unwrap().to_owned();
                let bytes = Bytes::from_bytes(&keystore.keypair.public.to_bytes());
                return if check_public_key_strength(&bytes, KEYSTORE_DIFFICULTY) {
                    Some(keystore)
                } else {
                    None
                };
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
                let bytes = self.keypair.to_bytes();
                f.write_all(&bytes).expect("Error saving keystore");
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
            Ok(_) => { true }
            Err(_) => { false }
        }
    }

    pub fn encrypt(&self, message: &[u8], nonce: &[u8]) -> Bytes {
        let encrypted = self.chacha.encrypt(message, nonce);
        Bytes::from_bytes(&encrypted)
    }

    pub fn decrypt(&self, message: &[u8], nonce: &[u8]) -> Bytes {
        let decrypted = self.chacha.decrypt(message, nonce);
        Bytes::from_bytes(&decrypted)
    }
}

impl Clone for Keystore {
    fn clone(&self) -> Self {
        let keypair = Keypair::from_bytes(&self.keypair.to_bytes()).unwrap();
        Self { keypair, hash: RefCell::new(Bytes::default()), path: self.path.clone(), chacha: self.chacha.clone() }
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
    context.lock().unwrap().bus.post(Event::KeyGeneratorStarted);
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
                    mining.store(false, atomic::Ordering::SeqCst);
                    let mut context = context.lock().unwrap();
                    let hash = keystore.get_hash().to_string();
                    info!("Key mined successfully: {:?}, hash: {}", &keystore.get_public(), &hash);
                    context.bus.post(Event::KeyCreated { path: keystore.get_path().to_owned(), public: keystore.get_public().to_string(), hash });
                    context.set_keystore(Some(keystore));
                }
            }
            let miners = miners_count.fetch_sub(1, atomic::Ordering::SeqCst) - 1;
            if miners == 0 {
                context.lock().unwrap().bus.post(Event::KeyGeneratorStopped);
            }
        });
    }
    context.lock().unwrap().bus.register(move |_uuid, e| {
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
        let keystore = Keystore::from_random_bytes(&buf);
        digest.reset();
        digest.update(keystore.get_public().as_slice());
        if key_hash_difficulty(digest.result()) >= difficulty {
            info!("Generated keypair with public key: {:?} and hash {:?}", &keystore.get_public(), &keystore.get_hash());
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

fn get_chacha(keypair: &Keypair) -> Chacha {
    let mut digest = Blakeout::new();
    digest.update(&keypair.to_bytes());
    let seed = digest.result();
    Chacha::new(seed)
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