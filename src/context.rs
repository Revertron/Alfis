use crate::{Keystore, Blockchain, Bus, Bytes};
use crate::event::Event;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Read;

pub struct Context {
    pub settings: Settings,
    pub keystore: Keystore,
    pub blockchain: Blockchain,
    pub bus: Bus<Event>,
}

impl Context {
    /// Creating an essential context to work with
    pub fn new(settings: Settings, keystore: Keystore, blockchain: Blockchain) -> Context {
        Context { settings, keystore, blockchain, bus: Bus::new() }
    }

    /// Load keystore and return Context
    pub fn load_keystore<S: Into<String>>(mut self, name: S, password: S) -> Context {
        let filename = &name.into();
        match Keystore::from_file(filename, &password.into()) {
            None => {
                println!("Error loading keystore '{}'!", filename);
            },
            Some(keystore) => {
                self.keystore = keystore;
            },
        }
        self
    }

    pub fn get_keystore(&self) -> Keystore {
        self.keystore.clone()
    }

    pub fn set_keystore(&mut self, keystore: Keystore) {
        self.keystore = keystore;
    }

    pub fn get_blockchain(&self) -> &Blockchain {
        &self.blockchain
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub origin: String,
    pub version: u32,
    pub key_file: String,
    pub listen: String,
    pub public: bool,
    pub peers: Vec<String>
}

impl Settings {
    pub fn new<S: Into<String>>(settings: S) -> serde_json::Result<Settings> {
        serde_json::from_str(&settings.into())
    }

    pub fn load(file_name: &str) -> Option<Settings> {
        match File::open(file_name) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                let loaded = serde_json::from_str(&text);
                return if loaded.is_ok() {
                    Some(loaded.unwrap())
                } else {
                    None
                }
            },
            Err(..) => None
        }
    }

    pub fn get_origin(&self) -> Bytes {
        if self.origin.eq("") {
            return Bytes::zero32();
        }
        let origin = crate::from_hex(&self.origin).expect("Wrong origin in settings");
        Bytes::from_bytes(origin.as_slice())
    }
}