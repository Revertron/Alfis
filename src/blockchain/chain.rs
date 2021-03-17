use std::cell::RefCell;
use std::collections::HashSet;

use chrono::Utc;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use sqlite::{Connection, State, Statement};

use crate::{Block, Bytes, Keystore, Transaction};
use crate::blockchain::constants::*;
use crate::blockchain::enums::BlockQuality;
use crate::blockchain::enums::BlockQuality::*;
use crate::blockchain::hash_utils::*;
use crate::settings::Settings;
use crate::keys::check_public_key_strength;
use std::cmp::{min, max};
use crate::blockchain::transaction::{ZoneData, DomainData};
use std::ops::Deref;

const DB_NAME: &str = "blockchain.db";
const SQL_CREATE_TABLES: &str = "CREATE TABLE blocks (
                                 'id' BIGINT NOT NULL PRIMARY KEY,
                                 'timestamp' BIGINT NOT NULL,
                                 'version' INT,
                                 'difficulty' INTEGER,
                                 'random' INTEGER,
                                 'nonce' INTEGER,
                                 'transaction' TEXT,
                                 'prev_block_hash' BINARY,
                                 'hash' BINARY,
                                 'pub_key' BINARY,
                                 'signature' BINARY);
            CREATE INDEX block_index ON blocks (id);
            CREATE TABLE transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, identity BINARY, confirmation BINARY, method TEXT, data TEXT, pub_key BINARY);
            CREATE INDEX ids ON transactions (identity);";
const SQL_ADD_BLOCK: &str = "INSERT INTO blocks (id, timestamp, version, difficulty, random, nonce, 'transaction',\
                          prev_block_hash, hash, pub_key, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
const SQL_GET_LAST_BLOCK: &str = "SELECT * FROM blocks ORDER BY id DESC LIMIT 1;";
const SQL_ADD_TRANSACTION: &str = "INSERT INTO transactions (identity, confirmation, method, data, pub_key) VALUES (?, ?, ?, ?, ?)";
const SQL_GET_BLOCK_BY_ID: &str = "SELECT * FROM blocks WHERE id=? LIMIT 1;";
const SQL_GET_LAST_FULL_BLOCK: &str = "SELECT * FROM blocks WHERE `transaction`<>'' ORDER BY id DESC LIMIT 1;";
const SQL_GET_LAST_FULL_BLOCK_FOR_KEY: &str = "SELECT * FROM blocks WHERE `transaction`<>'' AND pub_key = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_PUBLIC_KEY_BY_ID: &str = "SELECT pub_key FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_ID_BY_ID: &str = "SELECT identity FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_TRANSACTION_BY_ID: &str = "SELECT * FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;";

pub struct Chain {
    origin: Bytes,
    pub version: u32,
    pub blocks: Vec<Block>,
    last_block: Option<Block>,
    last_full_block: Option<Block>,
    max_height: u64,
    db: Connection,
    zones: RefCell<HashSet<String>>,
}

impl Chain {
    pub fn new(settings: &Settings) -> Self {
        let origin = settings.get_origin();

        let db = sqlite::open(DB_NAME).expect("Unable to open blockchain DB");
        let mut chain = Chain {
            origin,
            version: CHAIN_VERSION,
            blocks: Vec::new(),
            last_block: None,
            last_full_block: None,
            max_height: 0,
            db,
            zones: RefCell::new(HashSet::new()),
        };
        chain.init_db();
        chain
    }

    /// Reads options from DB or initializes and writes them to DB if not found
    fn init_db(&mut self) {
        // Trying to get last block from DB to check its version
        let block: Option<Block> = match self.db.prepare(SQL_GET_LAST_BLOCK) {
            Ok(mut statement) => {
                let mut result = None;
                while statement.next().unwrap() == State::Row {
                    match Self::get_block_from_statement(&mut statement) {
                        None => {
                            error!("Something wrong with block in DB!");
                            panic!();
                        }
                        Some(block) => {
                            debug!("Loaded last block: {:?}", &block);
                            result = Some(block);
                            break;
                        }
                    }
                }
                result
            }
            Err(_) => {
                info!("No blockchain database found. Creating new.");
                self.db.execute(SQL_CREATE_TABLES).expect("Error creating blocks table");
                None
            }
        };
        // If some block loaded we check its version and determine if we need some migration
        if let Some(block) = block {
            self.max_height = block.index;
            if self.version > block.version {
                self.migrate_db(block.version, self.version);
            } else if self.version < block.version {
                error!("Version downgrade {}->{} is not supported!", block.version, self.version);
                panic!();
            }
            // Cache some info
            self.last_block = Some(block.clone());
            if block.transaction.is_some() {
                self.last_full_block = Some(block);
            } else {
                self.last_full_block = self.get_last_full_block(None);
            }
        }
    }

    fn migrate_db(&mut self, from: u32, to: u32) {
        debug!("Migrating DB from {} to {}", from, to);
    }

    pub fn add_block(&mut self, block: Block) {
        info!("Adding block:\n{:?}", &block);
        self.blocks.push(block.clone());
        self.last_block = Some(block.clone());
        if block.transaction.is_some() {
            self.last_full_block = Some(block.clone());
        }
        let transaction = block.transaction.clone();
        if self.add_block_to_table(block).is_ok() {
            if let Some(transaction) = transaction {
                self.add_transaction_to_table(&transaction).expect("Error adding transaction");
            }
        }
    }

    /// Adds block to blocks table
    fn add_block_to_table(&mut self, block: Block) -> sqlite::Result<State> {
        let mut statement = self.db.prepare(SQL_ADD_BLOCK)?;
        statement.bind(1, block.index as i64)?;
        statement.bind(2, block.timestamp as i64)?;
        statement.bind(3, block.version as i64)?;
        statement.bind(4, block.difficulty as i64)?;
        statement.bind(5, block.random as i64)?;
        statement.bind(6, block.nonce as i64)?;
        match &block.transaction {
            None => { statement.bind(7, "")?; }
            Some(transaction) => {
                statement.bind(7, transaction.to_string().as_str())?;
            }
        }
        statement.bind(8, &**block.prev_block_hash)?;
        statement.bind(9, &**block.hash)?;
        statement.bind(10, &**block.pub_key)?;
        statement.bind(11, &**block.signature)?;
        statement.next()
    }

    /// Adds transaction to transactions table
    fn add_transaction_to_table(&mut self, t: &Transaction) -> sqlite::Result<State> {
        let mut statement = self.db.prepare(SQL_ADD_TRANSACTION)?;
        statement.bind(1, &**t.identity)?;
        statement.bind(2, &**t.confirmation)?;
        statement.bind(3, t.method.as_ref() as &str)?;
        statement.bind(4, t.data.as_ref() as &str)?;
        statement.bind(5, &**t.pub_key)?;
        statement.next()
    }

    pub fn get_block(&self, index: u64) -> Option<Block> {
        match self.db.prepare(SQL_GET_BLOCK_BY_ID) {
            Ok(mut statement) => {
                statement.bind(1, index as i64).expect("Error in bind");
                while statement.next().unwrap() == State::Row {
                    return match Self::get_block_from_statement(&mut statement) {
                        None => {
                            error!("Something wrong with block in DB!");
                            None
                        }
                        Some(block) => {
                            trace!("Loaded block: {:?}", &block);
                            Some(block)
                        }
                    };
                }
                None
            }
            Err(_) => {
                warn!("Can't find requested block {}", index);
                None
            }
        }
    }

    /// Gets last block that has a Transaction within
    pub fn get_last_full_block(&self, pub_key: Option<&[u8]>) -> Option<Block> {
        if let Some(block) = &self.last_full_block {
            match pub_key {
                None => { return Some(block.clone()); }
                Some(key) => {
                    if block.pub_key.deref().eq(key) {
                        return Some(block.clone());
                    }
                }
            }
        }

        let mut statement = match pub_key {
            None => {
                self.db.prepare(SQL_GET_LAST_FULL_BLOCK).expect("Unable to prepare")
            }
            Some(pub_key) => {
                let mut statement = self.db.prepare(SQL_GET_LAST_FULL_BLOCK_FOR_KEY).expect("Unable to prepare");
                statement.bind(1, pub_key).expect("Unable to bind");
                statement
            }
        };
        while statement.next().unwrap() == State::Row {
            return match Self::get_block_from_statement(&mut statement) {
                None => {
                    error!("Something wrong with block in DB!");
                    None
                }
                Some(block) => {
                    trace!("Got last full block: {:?}", &block);
                    Some(block)
                }
            };
        }
        None
    }

    /// Checks if any domain is available to mine for this client (pub_key)
    pub fn is_domain_available(&self, domain: &str, keystore: &Keystore) -> bool {
        if domain.is_empty() {
            return false;
        }
        let identity_hash = hash_identity(domain, None);
        if !self.is_id_available(&identity_hash, &keystore.get_public()) {
            return false;
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

    /// Checks if this identity is free or is owned by the same pub_key
    pub fn is_id_available(&self, identity: &Bytes, public_key: &Bytes) -> bool {
        let mut statement = self.db.prepare(SQL_GET_PUBLIC_KEY_BY_ID).unwrap();
        statement.bind(1, &***identity).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let pub_key = Bytes::from_bytes(&statement.read::<Vec<u8>>(0).unwrap());
            if !pub_key.eq(public_key) {
                return false;
            }
        }
        true
    }

    /// Checks if some zone exists in our blockchain
    pub fn is_zone_in_blockchain(&self, zone: &str) -> bool {
        if self.zones.borrow().contains(zone) {
            return true;
        }

        // Checking for existing zone in DB
        let identity_hash = hash_identity(zone, None);
        if self.is_id_in_blockchain(&identity_hash) {
            // If there is such a zone
            self.zones.borrow_mut().insert(zone.to_owned());
            return true;
        }
        false
    }

    /// Checks if some id exists in our blockchain
    pub fn is_id_in_blockchain(&self, id: &Bytes) -> bool {
        // Checking for existing zone in DB
        let mut statement = self.db.prepare(SQL_GET_ID_BY_ID).unwrap();
        statement.bind(1, &***id).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            // If there is such a zone
            return true;
        }
        false
    }

    /// Gets full Transaction info for any domain. Used by DNS part.
    pub fn get_domain_transaction(&self, domain: &str) -> Option<Transaction> {
        if domain.is_empty() {
            return None;
        }
        let identity_hash = hash_identity(domain, None);

        let mut statement = self.db.prepare(SQL_GET_TRANSACTION_BY_ID).unwrap();
        statement.bind(1, &**identity_hash).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let identity = Bytes::from_bytes(&statement.read::<Vec<u8>>(1).unwrap());
            let confirmation = Bytes::from_bytes(&statement.read::<Vec<u8>>(2).unwrap());
            let method = statement.read::<String>(3).unwrap();
            let data = statement.read::<String>(4).unwrap();
            let pub_key = Bytes::from_bytes(&statement.read::<Vec<u8>>(5).unwrap());
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

    pub fn get_zone_difficulty(&self, zone: &str) -> u32 {
        match self.get_domain_transaction(zone) {
            None => { u32::max_value() }
            Some(transaction) => {
                match serde_json::from_str::<ZoneData>(&transaction.data) {
                    Ok(data) => { data.difficulty }
                    Err(_) => {
                        warn!("Wrong data for zone {}!", zone);
                        u32::max_value()
                    }
                }
            }
        }
    }

    pub fn last_block(&self) -> Option<Block> {
        self.last_block.clone()
    }

    pub fn height(&self) -> u64 {
        match self.last_block {
            None => { 0u64 }
            Some(ref block) => {
                block.index
            }
        }
    }

    pub fn last_hash(&self) -> Bytes {
        match &self.last_block {
            None => { Bytes::default() }
            Some(block) => { block.hash.clone() }
        }
    }

    pub fn next_allowed_block(&self) -> u64 {
        match self.last_full_block {
            None => { self.height() + 1 }
            Some(ref block) => {
                if block.index < LOCKER_BLOCK_START {
                    self.height() + 1
                } else {
                    max(block.index, self.height()) + LOCKER_BLOCK_SIGNS
                }
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

    /// Check if this block can be added to our blockchain
    pub fn check_new_block(&self, block: &Block) -> BlockQuality {
        let timestamp = Utc::now().timestamp();
        if block.timestamp > timestamp {
            warn!("Ignoring block from the future:\n{:?}", &block);
            return Bad;
        }
        if !check_public_key_strength(&block.pub_key, KEYSTORE_DIFFICULTY) {
            warn!("Ignoring block with weak public key:\n{:?}", &block);
            return Bad;
        }
        let difficulty = match block.transaction {
            None => { LOCKER_DIFFICULTY }
            Some(_) => { BLOCK_DIFFICULTY }
        };
        if block.difficulty < difficulty {
            warn!("Block difficulty is lower than needed");
            return Bad;
        }
        if !hash_is_good(&block.hash, block.difficulty as usize) {
            warn!("Ignoring block with low difficulty:\n{:?}", &block);
            return Bad;
        }
        if !check_block_hash(block) {
            warn!("Block {:?} has wrong hash! Ignoring!", &block);
            return Bad;
        }
        if !check_block_signature(&block) {
            warn!("Block {:?} has wrong signature! Ignoring!", &block);
            return Bad;
        }
        if let Some(transaction) = &block.transaction {
            if !self.is_id_available(&transaction.identity, &block.pub_key) {
                warn!("Block {:?} is trying to spoof an identity!", &block);
                return Bad;
            }
            if let Some(last) = self.get_last_full_block(Some(&block.pub_key)) {
                let new_id = !self.is_id_in_blockchain(&transaction.identity);
                if new_id && last.timestamp + FULL_BLOCKS_INTERVAL > block.timestamp {
                    warn!("Block {:?} is mined too early!", &block);
                    return Bad;
                }
            }
            if let Ok(data) = serde_json::from_str::<DomainData>(&transaction.data) {
                if self.get_zone_difficulty(&data.zone) > block.difficulty {
                    warn!("Block {:?} is mined with too low difficulty!", &block);
                    return Bad;
                }
            }
        }
        match &self.last_block {
            None => {
                if !block.is_genesis() {
                    warn!("Block is from the future, how is this possible?");
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
                    warn!("Block is from the future, how is this possible?");
                    return Future;
                }
                if block.index > LOCKER_BLOCK_START {
                    // If this block is locked part of blockchain
                    if let Some(full_block) = &self.last_full_block {
                        let locker_blocks = self.height() - full_block.index;
                        if locker_blocks < LOCKER_BLOCK_SIGNS {
                            // Last full block is not locked enough
                            if block.transaction.is_some() {
                                warn!("Someone mined full block over full block");
                                return Bad;
                            } else {
                                if self.check_block_for_lock(&block, full_block) == Bad {
                                    return Bad;
                                }
                            }
                        } else if locker_blocks < LOCKER_BLOCK_LOCKERS && block.transaction.is_none() {
                            if self.check_block_for_lock(&block, full_block) == Bad {
                                return Bad;
                            }
                        }
                    }
                }

                if block.index <= last_block.index {
                    if last_block.hash == block.hash {
                        warn!("Ignoring block {}, we already have it", block.index);
                        return Twin;
                    }
                    if let Some(my_block) = self.get_block(block.index) {
                        return if my_block.hash != block.hash {
                            warn!("Got forked block {} with hash {:?} instead of {:?}", block.index, block.hash, last_block.hash);
                            Fork
                        } else {
                            warn!("Ignoring block {}, we already have it", block.index);
                            Twin
                        };
                    }
                }

            }
        }

        Good
    }

    fn check_block_for_lock(&self, block: &Block, full_block: &Block) -> BlockQuality {
        // If we got a locker/signing block
        let lockers: HashSet<Bytes> = self.get_block_lockers(full_block).into_iter().collect();
        if !lockers.contains(&block.pub_key) {
            warn!("Ignoring block {}, as wrong locker", block.index);
            return Bad;
        }
        // If this locker's public key has already locked/signed that block we return error
        for i in (full_block.index + 1)..block.index {
            let locker = self.get_block(i).expect("Error in DB!");
            if locker.pub_key == block.pub_key {
                warn!("Ignoring block {}, already locked by this key", block.index);
                return Bad;
            }
        }
        Good
    }

    /// Gets a public key of a node that needs to mine "locker" block above this block
    /// block - last full block
    pub fn get_block_lockers(&self, block: &Block) -> Vec<Bytes> {
        let mut result = Vec::new();
        if block.index < LOCKER_BLOCK_START {
            return result;
        }
        let mut set = HashSet::new();
        let tail = block.hash.get_tail_u64();
        let interval = min(block.index, LOCKER_BLOCK_INTERVAL) - 1;
        let start_index = block.index - interval;
        let mut count = 1;
        while set.len() < LOCKER_BLOCK_LOCKERS as usize {
            let index = start_index + ((tail * count) % LOCKER_BLOCK_INTERVAL);
            if let Some(b) = self.get_block(index) {
                if b.pub_key != block.pub_key && !set.contains(&b.pub_key) {
                    result.push(b.pub_key.clone());
                    set.insert(b.pub_key);
                }
                count += 1;
            }
        }
        trace!("Got lockers for block {}: {:?}", block.index, &result);
        result
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