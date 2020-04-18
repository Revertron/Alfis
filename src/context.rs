use crate::{Keystore, Blockchain};
use std::collections::HashMap;

pub struct Context {
    pub(crate) settings: Settings,
    pub(crate) keystore: Keystore,
    pub(crate) blockchain: Blockchain,
}

impl Context {
    /// Creating an essential context to work with
    pub fn new(settings: Settings, keystore: Keystore, blockchain: Blockchain) -> Context {
        Context { settings, keystore, blockchain }
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
}

pub struct Settings {
    pub chain_id: u32,
    pub version: u32,
    salts: HashMap<String, String>
}

impl Settings {
    /// TODO parse settings
    pub fn new<S: Into<String>>(chain_id: u32, version: u32, settings: S) -> Settings {
        Settings { chain_id, version, salts: HashMap::new() }
    }
}