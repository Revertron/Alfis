use sqlite::{Connection, State, Statement};

use crate::{Block, Bytes, Keystore, Transaction, hash_is_good};
use crate::settings::Settings;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};
use std::collections::HashSet;
use std::cell::RefCell;
use chrono::Utc;
use crate::blockchain::transaction::hash_identity;
use crate::blockchain::blockchain::BlockQuality::*;
use crate::blockchain::BLOCK_DIFFICULTY;

const DB_NAME: &str = "blockchain.db";

pub struct Blockchain {
    origin: Bytes,
    pub version: u32,
    pub blocks: Vec<Block>,
    last_block: Option<Block>,
    max_height: u64,
    db: Connection,
    zones: RefCell<HashSet<String>>
}

impl Blockchain {
    pub fn new(settings: &Settings) -> Self {
        let origin = settings.get_origin();
        let version = settings.version;

        let db = sqlite::open(DB_NAME).expect("Unable to open blockchain DB");
        let mut blockchain = Blockchain{ origin, version, blocks: Vec::new(), last_block: None, max_height: 0, db, zones: RefCell::new(HashSet::new()) };
        blockchain.init_db();
        blockchain
    }

    /// Reads options from DB or initializes and writes them to DB if not found
    fn init_db(&mut self) {
        match self.db.prepare("SELECT * FROM blocks ORDER BY id DESC LIMIT 1;") {
            Ok(mut statement) => {
                while statement.next().unwrap() == State::Row {
                    match Self::get_block_from_statement(&mut statement) {
                        None => { error!("Something wrong with block in DB!"); }
                        Some(block) => {
                            info!("Loaded last block: {:?}", &block);
                            self.version = block.version;
                            self.last_block = Some(block);
                        }
                    }
                    debug!("Blockchain version from DB = {}", self.version);
                }
            }
            Err(_) => {
                info!("No blockchain database found. Creating new.");
                self.db.execute("
                    CREATE TABLE blocks (
                                         'id' BIGINT,
                                         'timestamp' BIGINT,
                                         'version' TEXT,
                                         'difficulty' INTEGER,
                                         'random' INTEGER,
                                         'nonce' INTEGER,
                                         'transaction' TEXT,
                                         'prev_block_hash' BINARY,
                                         'hash' BINARY,
                                         'pub_key' BINARY,
                                         'signature' BINARY
                                         );
                    CREATE INDEX block_index ON blocks (id);
                    CREATE TABLE transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, identity BINARY, confirmation BINARY, method TEXT, data TEXT, pub_key BINARY);
                    CREATE INDEX ids ON transactions (identity);"
                ).expect("Error creating blocks table");
            }
        }
    }

    pub fn add_block(&mut self, block: Block) {
        info!("Adding block:\n{:?}", &block);
        self.blocks.push(block.clone());
        self.last_block = Some(block.clone());
        let transaction = block.transaction.clone();

        {
            // Adding block to DB
            let mut statement = self.db.prepare("INSERT INTO blocks (\
                    id, timestamp, version, difficulty, random, nonce, 'transaction',\
                    prev_block_hash, hash, pub_key, signature)\
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);").unwrap();
            statement.bind(1, block.index as i64).expect("Error in bind");
            statement.bind(2, block.timestamp as i64).expect("Error in bind");
            statement.bind(3, block.version as i64).expect("Error in bind");
            statement.bind(4, block.difficulty as i64).expect("Error in bind");
            statement.bind(5, block.random as i64).expect("Error in bind");
            statement.bind(6, block.nonce as i64).expect("Error in bind");
            match &transaction {
                None => { statement.bind(7, "").expect("Error in bind"); }
                Some(transaction) => {
                    statement.bind(7, transaction.to_string().as_ref() as &str).expect("Error in bind");
                }
            }
            statement.bind(8, block.prev_block_hash.as_bytes()).expect("Error in bind");
            statement.bind(9, block.hash.as_bytes()).expect("Error in bind");
            statement.bind(10, block.pub_key.as_bytes()).expect("Error in bind");
            statement.bind(11, block.signature.as_bytes()).expect("Error in bind");
            statement.next().expect("Error adding block to DB");
        }

        if let Some(transaction) = transaction {
            self.add_transaction(&transaction);
        }
    }

    fn add_transaction(&mut self, t: &Transaction) {
        let mut statement = self.db.prepare("INSERT INTO transactions (identity, confirmation, method, data, pub_key) VALUES (?, ?, ?, ?, ?)").unwrap();
        statement.bind(1, t.identity.as_bytes()).expect("Error in bind");
        statement.bind(2, t.confirmation.as_bytes()).expect("Error in bind");
        statement.bind(3, t.method.as_ref() as &str).expect("Error in bind");
        statement.bind(4, t.data.as_ref() as &str).expect("Error in bind");
        statement.bind(5, t.pub_key.as_bytes()).expect("Error in bind");
        statement.next().expect("Error adding transaction to DB");
    }

    pub fn get_block(&self, index: u64) -> Option<Block> {
        match self.db.prepare("SELECT * FROM blocks WHERE id=? LIMIT 1;") {
            Ok(mut statement) => {
                statement.bind(1, index as i64).expect("Error in bind");
                while statement.next().unwrap() == State::Row {
                    return match Self::get_block_from_statement(&mut statement) {
                        None => {
                            error!("Something wrong with block in DB!");
                            None
                        }
                        Some(block) => {
                            debug!("Loaded block: {:?}", &block);
                            Some(block)
                        }
                    }
                }
                None
            }
            Err(_) => {
                warn!("Can't find requested block {}", index);
                None
            }
        }
    }

    pub fn is_domain_available(&self, domain: &str, keystore: &Keystore) -> bool {
        if domain.is_empty() {
            return false;
        }
        let identity_hash = hash_identity(domain, None);
        let mut statement = self.db.prepare("SELECT pub_key FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;").unwrap();
        statement.bind(1, identity_hash.as_bytes()).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let pub_key = Bytes::from_bytes(statement.read::<Vec<u8>>(0).unwrap().as_slice());
            if !pub_key.eq(&keystore.get_public()) {
                return false;
            }
        }

        let parts: Vec<&str> = domain.rsplitn(2, ".").collect();
        if parts.len() > 1 {
            // We do not support third level domains
            if parts.last().unwrap().contains(".") {
                return false;
            }
            return self.is_zone_in_blockchain(parts.first().unwrap());
        }

        true
    }

    pub fn is_zone_in_blockchain(&self, zone: &str) -> bool {
        if self.zones.borrow().contains(zone) {
            return true;
        }

        // Checking for existing zone in DB
        let identity_hash = hash_identity(zone, None);
        let mut statement = self.db.prepare("SELECT identity FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;").unwrap();
        statement.bind(1, identity_hash.as_bytes()).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            // If there is such a zone
            self.zones.borrow_mut().insert(zone.to_owned());
            return true;
        }
        false
    }

    pub fn get_domain_transaction(&self, domain: &str) -> Option<Transaction> {
        if domain.is_empty() {
            return None;
        }
        let identity_hash = hash_identity(domain, None);

        let mut statement = self.db.prepare("SELECT * FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;").unwrap();
        statement.bind(1, identity_hash.as_bytes()).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let identity = Bytes::from_bytes(statement.read::<Vec<u8>>(1).unwrap().as_slice());
            let confirmation = Bytes::from_bytes(statement.read::<Vec<u8>>(2).unwrap().as_slice());
            let method = statement.read::<String>(3).unwrap();
            let data = statement.read::<String>(4).unwrap();
            let pub_key = Bytes::from_bytes(statement.read::<Vec<u8>>(5).unwrap().as_slice());
            let transaction = Transaction { identity, confirmation, method, data, pub_key };
            debug!("Found transaction for domain {}: {:?}", domain, &transaction);
            if transaction.check_identity(domain) {
                return Some(transaction);
            }
        }
        None
    }

    pub fn get_domain_info(&self, domain: &str) -> Option<String> {
        match self.get_domain_transaction(domain) {
            None => { None }
            Some(transaction) => { Some(transaction.data) }
        }
    }

    pub fn last_block(&self) -> Option<Block> {
        self.last_block.clone()
    }

    pub fn height(&self) -> u64 {
        match self.last_block {
            None => { 0u64 }
            Some(ref block) => {
                block.index + 1
            }
        }
    }

    pub fn max_height(&self) -> u64 {
        self.max_height
    }

    pub fn update_max_height(&mut self, height: u64) {
        if height > self.max_height {
            self.max_height = height;
        }
    }

    pub fn check_new_block(&self, block: &Block) -> BlockQuality {
        let timestamp = Utc::now().timestamp();
        if block.timestamp > timestamp {
            warn!("Ignoring block from the future:\n{:?}", &block);
            return Bad;
        }
        if !hash_is_good(block.hash.as_bytes(), BLOCK_DIFFICULTY as usize) {
            warn!("Ignoring block with low difficulty:\n{:?}", &block);
            return Bad;
        }
        if !hash_is_good(block.hash.as_bytes(), block.difficulty as usize) {
            warn!("Ignoring block with low difficulty:\n{:?}", &block);
            return Bad;
        }
        match &self.last_block {
            None => {
                if !block.is_genesis() {
                    return Future;
                }
                if !self.origin.is_zero() && block.hash != self.origin {
                    warn!("Mining gave us a bad block:\n{:?}", &block);
                    return Bad;
                }
            }
            Some(last_block) => {
                if block.timestamp < last_block.timestamp && block.index > last_block.index {
                    warn!("Ignoring block with timestamp/index collision:\n{:?}", &block);
                    return Bad;
                }
                if last_block.index + 1 < block.index {
                    warn!("Got block from the future");
                    return Future;
                }
                if last_block.index >= block.index && last_block.hash == block.hash {
                    warn!("Ignoring block {}, we already have it", block.index);
                    return Twin;
                }
                if last_block.index == block.index && last_block.hash != block.hash {
                    warn!("Got forked block {} with hash {:?} instead of {:?}", block.index, block.hash, last_block.hash);
                    return Fork;
                }
            }
        }
        if !check_block_hash(block) {
            warn!("Block {:?} has wrong hash! Ignoring!", &block);
            return Bad;
        }
        if !check_block_signature(&block) {
            warn!("Block {:?} has wrong signature! Ignoring!", &block);
            return Bad;
        }

        Good
    }

    fn get_block_from_statement(statement: &mut Statement) -> Option<Block> {
        let index = statement.read::<i64>(0).unwrap() as u64;
        let timestamp = statement.read::<i64>(1).unwrap();
        let version = statement.read::<i64>(2).unwrap() as u32;
        let difficulty = statement.read::<i64>(3).unwrap() as u32;
        let random = statement.read::<i64>(4).unwrap() as u32;
        let nonce = statement.read::<i64>(5).unwrap() as u64;
        let transaction = Transaction::from_json(&statement.read::<String>(6).unwrap());
        let prev_block_hash = Bytes::from_bytes(statement.read::<Vec<u8>>(7).unwrap().as_slice());
        let hash = Bytes::from_bytes(statement.read::<Vec<u8>>(8).unwrap().as_slice());
        let pub_key = Bytes::from_bytes(statement.read::<Vec<u8>>(9).unwrap().as_slice());
        let signature = Bytes::from_bytes(statement.read::<Vec<u8>>(10).unwrap().as_slice());
        Some(Block::from_all_params(index, timestamp, version, difficulty, random, nonce, prev_block_hash, hash, pub_key, signature, transaction))
    }
}

#[derive(PartialEq)]
pub enum BlockQuality {
    Good,
    Twin,
    Future,
    Bad,
    Fork
}

pub fn check_block_hash(block: &Block) -> bool {
    let mut copy: Block = block.clone();
    copy.hash = Bytes::default();
    copy.signature = Bytes::default();
    let data = serde_json::to_string(&copy).unwrap();
    crate::blockchain::block::hash(data.as_bytes()) == block.hash
}

pub fn check_block_signature(block: &Block) -> bool {
    let mut copy = block.clone();
    copy.signature = Bytes::zero64();
    let data = serde_json::to_string(&copy).unwrap();
    Keystore::check(data.as_bytes(), copy.pub_key.as_bytes(), block.signature.as_bytes())
}
