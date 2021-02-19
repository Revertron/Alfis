use crate::{Blockchain, Bus, Keystore};
use crate::event::Event;
use crate::settings::Settings;

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