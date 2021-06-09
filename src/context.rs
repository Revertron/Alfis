#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use crate::miner::MinerState;
use crate::{Bytes, Chain, Keystore, Settings};

pub struct Context {
    pub app_version: String,
    pub settings: Settings,
    pub keystores: Vec<Keystore>,
    active_key: usize,
    pub chain: Chain,
    pub miner_state: MinerState
}

impl Context {
    /// Creating an essential context to work with
    pub fn new(app_version: String, settings: Settings, keystores: Vec<Keystore>, chain: Chain) -> Context {
        Context { app_version, settings, keystores, active_key: 0, chain, miner_state: MinerState { mining: false, full: false } }
    }

    pub fn get_keystore(&self) -> Option<&Keystore> {
        self.keystores.get(self.active_key)
    }

    pub fn get_keystore_mut(&mut self) -> Option<&mut Keystore> {
        self.keystores.get_mut(self.active_key)
    }

    pub fn get_keystores(&self) -> &Vec<Keystore> {
        &self.keystores
    }

    pub fn has_keys(&self) -> bool {
        !self.keystores.is_empty()
    }

    pub fn set_keystores(&mut self, keystore: Vec<Keystore>) {
        self.keystores = keystore;
        self.active_key = 0;
    }

    pub fn add_keystore(&mut self, keystore: Keystore) {
        self.keystores.push(keystore);
        self.active_key = self.keystores.len() - 1;
    }

    pub fn select_key_by_index(&mut self, index: usize) -> bool {
        if index < self.keystores.len() {
            self.active_key = index;
            return true;
        }
        false
    }

    pub fn select_key_by_public(&mut self, public: &Bytes) -> bool {
        for (i, key) in self.keystores.iter().enumerate() {
            if key.get_public().eq(public) {
                self.active_key = i;
                return true;
            }
        }
        false
    }

    pub fn get_active_key_index(&self) -> usize {
        self.active_key
    }

    pub fn get_chain(&self) -> &Chain {
        &self.chain
    }
}