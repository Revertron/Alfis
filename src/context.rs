use crate::{Chain, Bus, Keystore, Settings, ExternalZones};
use crate::event::Event;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};
use crate::miner::MinerState;

pub struct Context {
    pub app_version: String,
    pub settings: Settings,
    pub keystore: Option<Keystore>,
    pub chain: Chain,
    pub x_zones: ExternalZones,
    pub bus: Bus<Event>,
    pub miner_state: MinerState,
}

impl Context {
    /// Creating an essential context to work with
    pub fn new(app_version: String, settings: Settings, keystore: Option<Keystore>, chain: Chain) -> Context {
        Context {
            app_version,
            settings,
            keystore,
            chain,
            x_zones: ExternalZones::new(),
            bus: Bus::new(),
            miner_state: MinerState { mining: false, full: false }
        }
    }

    /// Load keystore and return Context
    pub fn load_keystore<S: Into<String>>(mut self, name: S, password: S) -> Context {
        let filename = &name.into();
        match Keystore::from_file(filename, &password.into()) {
            None => {
                warn!("Error loading keystore '{}'!", filename);
            },
            Some(keystore) => {
                self.keystore = Some(keystore);
            },
        }
        self
    }

    pub fn get_keystore(&self) -> Option<Keystore> {
        self.keystore.clone()
    }

    pub fn set_keystore(&mut self, keystore: Option<Keystore>) {
        self.keystore = keystore;
    }

    pub fn get_chain(&self) -> &Chain {
        &self.chain
    }
}