extern crate crypto;
extern crate serde;
extern crate serde_json;

use std::thread;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, atomic, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize};

use crypto::ed25519::{keypair, signature, verify};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand::{Rng, RngCore, thread_rng};
use serde::{Deserialize, Serialize};

use crate::blockchain::hash_utils::*;
use crate::{Context, setup_miner_thread};
use crate::event::Event;
use crate::commons::KEYSTORE_DIFFICULTY;
use crate::bytes::Bytes;
use blakeout::Blakeout;
use self::crypto::digest::Digest;
use std::time::Instant;
use std::cell::RefCell;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keystore {
    private_key: Bytes,
    public_key: Bytes,
    #[serde(skip)]
    hash: RefCell<Bytes>,
    #[serde(skip)]
    path: String,
    #[serde(skip)]
    seed: Vec<u8>,
}

impl Keystore {
    pub fn new() -> Self {
        let mut buf = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut buf);
        let (private, public) = keypair(&buf);
        Keystore { private_key: Bytes::from_bytes(&private), public_key: Bytes::from_bytes(&public), hash: RefCell::new(Bytes::default()), path: String::new(), seed: Vec::from(&buf[..]) }
    }

    pub fn from_bytes(seed: &[u8]) -> Self {
        let (private, public) = keypair(&seed);
        Keystore { private_key: Bytes::from_bytes(&private), public_key: Bytes::from_bytes(&public), hash: RefCell::new(Bytes::default()), path: String::new(), seed: Vec::from(seed) }
    }

    pub fn from_file(filename: &str, _password: &str) -> Option<Self> {
        let path = Path::new(filename);
        match fs::read(&path) {
            Ok(key) => {
                let mut keystore = Self::from_bytes(key.as_slice());
                keystore.path = path.to_str().unwrap().to_owned();
                Some(keystore)
            }
            Err(_) => {
                None
            }
        }
    }

    //TODO Implement error conditions
    pub fn save(&mut self, filename: &str, _password: &str) {
        match File::create(Path::new(filename)) {
            Ok(mut f) => {
                //TODO implement key encryption
                f.write_all(&self.seed).expect("Error saving keystore");
                self.path = filename.to_owned();
            }
            Err(_) => { error!("Error saving key file!"); }
        }
    }

    pub fn get_public(&self) -> Bytes {
        self.public_key.clone()
    }

    pub fn get_private(&self) -> Bytes {
        self.private_key.clone()
    }

    pub fn get_path(&self) -> &str {
        &self.path
    }

    pub fn get_hash(&self) -> Bytes {
        if self.hash.borrow().is_empty() {
            self.hash.replace(hash_data(&mut Blakeout::default(), &self.public_key));
        }
        self.hash.borrow().clone()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        signature(message, &self.private_key)
    }

    pub fn check(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
        verify(message, public_key, signature)
    }
}

/// Checks if some public key is "strong" enough to mine domains
/// TODO Optimize by caching Blakeout somewhere
pub fn check_public_key_strength(key: &Bytes, strength: usize) -> bool {
    let bytes = hash_data(&mut Blakeout::default(), &key);
    hash_is_good(&bytes, strength)
}

pub fn create_key(context: Arc<Mutex<Context>>) {
    let mining = Arc::new(AtomicBool::new(true));
    let miners_count = Arc::new(AtomicUsize::new(0));
    { context.lock().unwrap().bus.post(Event::KeyGeneratorStarted); }
    for cpu in 0..num_cpus::get() {
        let context = context.clone();
        let mining = mining.clone();
        let miners_count = miners_count.clone();
        thread::spawn(move || {
            setup_miner_thread(cpu as u32);
            miners_count.fetch_add(1, atomic::Ordering::SeqCst);
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
                    context.set_keystore(keystore);
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

fn generate_key(difficulty: usize, mining: Arc<AtomicBool>) -> Option<Keystore> {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    let mut digest = Blakeout::default();
    let mut time = Instant::now();
    let mut count = 0u128;
    loop {
        rng.fill_bytes(&mut buf);
        let keystore = Keystore::from_bytes(&buf);
        digest.reset();
        digest.input(&keystore.public_key);
        digest.result(&mut buf);
        if hash_is_good(&buf, difficulty) {
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