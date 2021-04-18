use std::cell::RefCell;
use std::collections::{HashSet, HashMap};
use std::fs;
use std::path::Path;

use chrono::Utc;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use sqlite::{Connection, State, Statement};

use crate::{Block, Bytes, Keystore, Transaction, check_domain, get_domain_zone, is_yggdrasil_record, from_hex};
use crate::commons::constants::*;
use crate::blockchain::types::{BlockQuality, MineResult, Options};
use crate::blockchain::types::BlockQuality::*;
use crate::blockchain::hash_utils::*;
use crate::settings::Settings;
use crate::keys::check_public_key_strength;
use std::cmp::max;
use crate::blockchain::transaction::{ZoneData, DomainData};
use std::ops::Deref;
use crate::blockchain::types::MineResult::*;
use crate::event::Event;

const DB_NAME: &str = "blockchain.db";
const TEMP_DB_NAME: &str = "temp.db";
const SQL_CREATE_TABLES: &str = include_str!("sql/create_db.sql");
const SQL_ADD_BLOCK: &str = "INSERT INTO blocks (id, timestamp, version, difficulty, random, nonce, 'transaction',\
                          prev_block_hash, hash, pub_key, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
const SQL_REPLACE_BLOCK: &str = "UPDATE blocks SET timestamp = ?, version = ?, difficulty = ?, random = ?, nonce = ?, 'transaction' = ?,\
                          prev_block_hash = ?, hash = ?, pub_key = ?, signature = ? WHERE id = ?;";
const SQL_GET_LAST_BLOCK: &str = "SELECT * FROM blocks ORDER BY id DESC LIMIT 1;";
const SQL_GET_FIRST_BLOCK_FOR_KEY: &str = "SELECT id FROM blocks WHERE pub_key = ? LIMIT 1;";
const SQL_ADD_DOMAIN: &str = "INSERT INTO domains (id, timestamp, identity, confirmation, data, pub_key) VALUES (?, ?, ?, ?, ?, ?)";
const SQL_ADD_ZONE: &str = "INSERT INTO zones (id, timestamp, identity, confirmation, data, pub_key) VALUES (?, ?, ?, ?, ?, ?)";
const SQL_DELETE_DOMAIN: &str = "DELETE FROM domains WHERE id = ?";
const SQL_DELETE_ZONE: &str = "DELETE FROM zones WHERE id = ?";
const SQL_GET_BLOCK_BY_ID: &str = "SELECT * FROM blocks WHERE id=? LIMIT 1;";
const SQL_GET_LAST_FULL_BLOCK: &str = "SELECT * FROM blocks WHERE `transaction`<>'' ORDER BY id DESC LIMIT 1;";
const SQL_GET_LAST_FULL_BLOCK_FOR_KEY: &str = "SELECT * FROM blocks WHERE `transaction`<>'' AND pub_key = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_DOMAIN_PUBLIC_KEY_BY_ID: &str = "SELECT pub_key FROM domains WHERE identity = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_ZONE_PUBLIC_KEY_BY_ID: &str = "SELECT pub_key FROM zones WHERE identity = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_DOMAIN_BY_ID: &str = "SELECT * FROM domains WHERE identity = ? ORDER BY id DESC LIMIT 1;";
const SQL_GET_DOMAINS_BY_KEY: &str = "SELECT * FROM domains WHERE pub_key = ?;";
const SQL_GET_ZONES: &str = "SELECT data FROM zones;";

const SQL_GET_OPTIONS: &str = "SELECT * FROM options;";

pub struct Chain {
    origin: Bytes,
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
        let zones = RefCell::new(HashSet::new());
        let mut chain = Chain { origin, last_block: None, last_full_block: None, max_height: 0, db, zones };
        chain.init_db();
        chain
    }

    /// Reads options from DB or initializes and writes them to DB if not found
    fn init_db(&mut self) {
        let options = self.get_options();
        if !self.origin.is_zero() && !options.origin.is_empty() && self.origin.to_string() != options.origin {
            self.clear_db();
        }
        if options.version < DB_VERSION {
            self.migrate_db(options.version, DB_VERSION);
        }

        // Trying to get last block from DB to check its version
        // If some block loaded we check its version and determine if we need some migration
        if let Some(block) = self.load_last_block() {
            // Cache some info
            self.last_block = Some(block.clone());
            if block.transaction.is_some() {
                self.last_full_block = Some(block);
            } else {
                self.last_full_block = self.get_last_full_block(None);
            }
        }
    }

    fn load_last_block(&mut self) -> Option<Block> {
        match self.db.prepare(SQL_GET_LAST_BLOCK) {
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
            Err(e) => {
                info!("No blockchain database found. Creating new. {}", e);
                self.db.execute(SQL_CREATE_TABLES).expect("Error creating DB tables");
                None
            }
        }
    }

    fn migrate_db(&mut self, from: u32, to: u32) {
        debug!("Migrating DB from {} to {}", from, to);
    }

    fn clear_db(&mut self) {
        warn!("Clearing DB");
        // We cannot close DB connection and recreate file,
        // therefore we switch our db to temporary file, delete main DB and switch back.
        // I know that this is a crutch, but this way I don't need to use Option<db> :)
        self.db = sqlite::open(TEMP_DB_NAME).expect("Unable to open temporary blockchain DB");
        let file = Path::new(DB_NAME);
        if fs::remove_file(&file).is_err() {
            panic!("Unable to remove database!");
        }
        self.db = sqlite::open(DB_NAME).expect("Unable to open blockchain DB");
        let file = Path::new(TEMP_DB_NAME);
        let _ = fs::remove_file(&file).is_err();
    }

    fn get_options(&self) -> Options {
        let mut options = Options::empty();
        if let Ok(mut statement) = self.db.prepare(SQL_GET_OPTIONS) {
            while let State::Row = statement.next().unwrap() {
                let name = statement.read::<String>(0).unwrap();
                let value = statement.read::<String>(1).unwrap();
                match name.as_ref() {
                    "origin" => options.origin = value,
                    "version" => options.version = value.parse().unwrap(),
                    _ => {}
                }
            }
        }
        options
    }

    pub fn add_block(&mut self, block: Block) {
        debug!("Adding block:\n{:?}", &block);
        let index = block.index;
        let timestamp = block.timestamp;
        self.last_block = Some(block.clone());
        if block.transaction.is_some() {
            self.last_full_block = Some(block.clone());
        }
        let transaction = block.transaction.clone();
        if self.add_block_to_table(block).is_ok() {
            if let Some(transaction) = transaction {
                self.add_transaction_to_table(index, timestamp, &transaction).expect("Error adding transaction");
            }
        }
    }

    pub fn replace_block(&mut self, index: u64, block: Block) -> sqlite::Result<()> {
        debug!("Replacing block {} with:\n{:?}", index, &block);
        let old_block = self.get_block(index).unwrap();
        if old_block.transaction.is_some() {
            let _ = self.delete_transaction(index);
        }

        let index = block.index;
        let timestamp = block.timestamp;
        self.last_block = Some(block.clone());
        if block.transaction.is_some() {
            self.last_full_block = Some(block.clone());
        }
        let transaction = block.transaction.clone();
        if self.replace_block_in_table(block).is_ok() {
            if let Some(transaction) = transaction {
                self.add_transaction_to_table(index, timestamp, &transaction).expect("Error adding transaction");
            }
        }
        Ok(())
    }

    pub fn update(&mut self, keystore: &Option<Keystore>) -> Option<Event> {
        if self.height() < BLOCK_SIGNERS_START {
            trace!("Too early to start block signings");
            return None;
        }
        if keystore.is_none() {
            trace!("We can't sign blocks without keys");
            return None;
        }
        if self.height() < self.max_height() {
            trace!("No signing while syncing");
            return None;
        }

        let block = self.last_block().unwrap();
        if block.transaction.is_none() {
            trace!("No need to sign signing block");
            return None;
        }
        let keystore = keystore.clone().unwrap().clone();
        let signers: HashSet<Bytes> = self.get_block_signers(&block).into_iter().collect();
        if signers.contains(&keystore.get_public()) {
            info!("We have an honor to mine signing block!");
            let keystore = Box::new(keystore);
            // We start mining sign block after some time, not everyone in the same time
            let start = Utc::now().timestamp() + (rand::random::<i64>() % BLOCK_SIGNERS_START_RANDOM);
            return Some(Event::ActionMineLocker { start, index: block.index + 1, hash: block.hash, keystore });
        } else if !signers.is_empty() {
            info!("Signing block must be mined by other nodes");
        }
        None
    }

    pub fn update_sign_block_for_mining(&self, mut block: Block) -> Option<Block> {
        if let Some(full_block) = &self.last_full_block {
            let sign_count = self.height() - full_block.index;
            if sign_count >= BLOCK_SIGNERS_MIN {
                return None;
            }
            block.index = self.height() + 1;
            block.prev_block_hash = self.last_block.clone().unwrap().hash;
        }
        None
    }

    fn delete_transaction(&mut self, index: u64) -> sqlite::Result<()> {
        let mut statement = self.db.prepare(SQL_DELETE_DOMAIN)?;
        statement.bind(1, index as i64)?;
        statement.next()?;

        let mut statement = self.db.prepare(SQL_DELETE_ZONE)?;
        statement.bind(1, index as i64)?;
        statement.next()?;
        Ok(())
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

    /// Replaces block in blocks table on arrival of better block from some fork
    fn replace_block_in_table(&mut self, block: Block) -> sqlite::Result<State> {
        let mut statement = self.db.prepare(SQL_REPLACE_BLOCK)?;
        statement.bind(1, block.timestamp as i64)?;
        statement.bind(2, block.version as i64)?;
        statement.bind(3, block.difficulty as i64)?;
        statement.bind(4, block.random as i64)?;
        statement.bind(5, block.nonce as i64)?;
        match &block.transaction {
            None => { statement.bind(6, "")?; }
            Some(transaction) => {
                statement.bind(6, transaction.to_string().as_str())?;
            }
        }
        statement.bind(7, &**block.prev_block_hash)?;
        statement.bind(8, &**block.hash)?;
        statement.bind(9, &**block.pub_key)?;
        statement.bind(10, &**block.signature)?;
        statement.bind(11, block.index as i64)?;
        statement.next()
    }

    /// Adds transaction to transactions table
    fn add_transaction_to_table(&mut self, index: u64, timestamp: i64, t: &Transaction) -> sqlite::Result<State> {
        let sql = match t.class.as_ref() {
            "domain" => SQL_ADD_DOMAIN,
            "zone" => SQL_ADD_ZONE,
            _ => return Err(sqlite::Error { code: None, message: None })
        };

        let mut statement = self.db.prepare(sql)?;
        statement.bind(1, index as i64)?;
        statement.bind(2, timestamp)?;
        statement.bind(3, &**t.identity)?;
        statement.bind(4, &**t.confirmation)?;
        statement.bind(5, t.data.as_ref() as &str)?;
        statement.bind(6, &**t.pub_key)?;
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
                            //trace!("Loaded block: {:?}", &block);
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
                    //trace!("Got last full block: {:?}", &block);
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
        if !self.is_id_available(&identity_hash, &keystore.get_public(), false) {
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
    pub fn is_id_available(&self, identity: &Bytes, public_key: &Bytes, zone: bool) -> bool {
        let sql = match zone {
            true => { SQL_GET_ZONE_PUBLIC_KEY_BY_ID }
            false => { SQL_GET_DOMAIN_PUBLIC_KEY_BY_ID }
        };

        let mut statement = self.db.prepare(sql).unwrap();
        statement.bind(1, &***identity).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let pub_key = Bytes::from_bytes(&statement.read::<Vec<u8>>(0).unwrap());
            if !pub_key.eq(public_key) {
                return false;
            }
        }
        true
    }

    pub fn get_zones(&self) -> Vec<ZoneData> {
        let mut map = HashMap::new();
        match self.db.prepare(SQL_GET_ZONES) {
            Ok(mut statement) => {
                while statement.next().unwrap() == State::Row {
                    let data = statement.read::<String>(0).unwrap();
                    //debug!("Got zone data {}", &data);
                    if let Ok(zone_data) = serde_json::from_str::<ZoneData>(&data) {
                        map.insert(zone_data.name.clone(), zone_data);
                    }
                }
            }
            Err(e) => {
                warn!("Can't get zones from DB {}", e);
            }
        }
        let result: Vec<ZoneData> = map.drain().map(|(_, value)| value).collect();
        result
    }

    /// Checks if some zone exists in our blockchain
    pub fn is_zone_in_blockchain(&self, zone: &str) -> bool {
        if self.zones.borrow().contains(zone) {
            return true;
        }

        // Checking for existing zone in DB
        let identity_hash = hash_identity(zone, None);
        if self.is_id_in_blockchain(&identity_hash, true) {
            // If there is such a zone
            self.zones.borrow_mut().insert(zone.to_owned());
            return true;
        }
        false
    }

    /// Checks if some id exists in our blockchain
    pub fn is_id_in_blockchain(&self, id: &Bytes, zone: bool) -> bool {
        let sql = match zone {
            true => { SQL_GET_ZONE_PUBLIC_KEY_BY_ID }
            false => { SQL_GET_DOMAIN_PUBLIC_KEY_BY_ID }
        };
        // Checking for existing zone in DB
        let mut statement = self.db.prepare(sql).unwrap();
        statement.bind(1, &***id).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            // If there is such a zone
            return true;
        }
        false
    }

    pub fn can_mine_domain(&self, domain: &str, pub_key: &Bytes) -> MineResult {
        let name = domain.to_lowercase();
        if !check_domain(&name, true) {
            return WrongName;
        }
        let zone = get_domain_zone(&name);
        if !self.is_zone_in_blockchain(&zone) {
            return WrongZone;
        }
        if let Some(transaction) = self.get_domain_transaction(&name) {
            if transaction.pub_key.ne(pub_key) {
                return NotOwned;
            }
        }
        let identity_hash = hash_identity(&name, None);
        if let Some(last) = self.get_last_full_block(Some(&pub_key)) {
            let new_id = !self.is_id_in_blockchain(&identity_hash, false);
            let time = last.timestamp + NEW_DOMAINS_INTERVAL - Utc::now().timestamp();
            if new_id && time > 0 {
                return Cooldown { time }
            }
        }

        Fine
    }

    /// Gets full Transaction info for any domain. Used by DNS part.
    pub fn get_domain_transaction(&self, domain: &str) -> Option<Transaction> {
        if domain.is_empty() {
            return None;
        }
        let identity_hash = hash_identity(domain, None);

        let mut statement = self.db.prepare(SQL_GET_DOMAIN_BY_ID).unwrap();
        statement.bind(1, &**identity_hash).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let timestamp = statement.read::<i64>(1).unwrap();
            if timestamp < Utc::now().timestamp() - DOMAIN_LIFETIME {
                // This domain is too old
                return None;
            }
            let identity = Bytes::from_bytes(&statement.read::<Vec<u8>>(2).unwrap());
            let confirmation = Bytes::from_bytes(&statement.read::<Vec<u8>>(3).unwrap());
            let class = String::from("domain");
            let data = statement.read::<String>(4).unwrap();
            let pub_key = Bytes::from_bytes(&statement.read::<Vec<u8>>(5).unwrap());
            let transaction = Transaction { identity, confirmation, class, data, pub_key };
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

    pub fn get_my_domains(&self, keystore: &Option<Keystore>) -> HashMap<Bytes, (String, i64, DomainData)> {
        if keystore.is_none() {
            return HashMap::new();
        }

        let mut result = HashMap::new();
        let keystore = keystore.clone().unwrap();
        let pub_key = keystore.get_public();
        let mut statement = self.db.prepare(SQL_GET_DOMAINS_BY_KEY).unwrap();
        statement.bind(1, &**pub_key).expect("Error in bind");
        while let State::Row = statement.next().unwrap() {
            let index = statement.read::<i64>(0).unwrap() as u64;
            let timestamp = statement.read::<i64>(1).unwrap();
            let identity = Bytes::from_bytes(&statement.read::<Vec<u8>>(2).unwrap());
            let confirmation = Bytes::from_bytes(&statement.read::<Vec<u8>>(3).unwrap());
            let class = String::from("domain");
            let data = statement.read::<String>(4).unwrap();
            let pub_key = Bytes::from_bytes(&statement.read::<Vec<u8>>(5).unwrap());
            let transaction = Transaction { identity: identity.clone(), confirmation, class, data, pub_key };
            //debug!("Found transaction for domain {}: {:?}", domain, &transaction);
            if let Some(data) = transaction.get_domain_data() {
                let b = self.get_block(index - 1).unwrap();
                let domain = keystore.decrypt(data.domain.as_slice(), &b.hash.as_slice()[..12]);
                let mut domain = String::from_utf8(domain.to_vec()).unwrap();
                if domain.is_empty() {
                    domain = String::from("unknown");
                }
                trace!("Found my domain {}", domain);
                result.insert(identity, (domain, timestamp, data));
            }
        }
        result
    }

    pub fn get_zone_difficulty(&self, zone: &str) -> u32 {
        let zones = self.get_zones();
        for z in zones.iter() {
            if z.name.eq(zone) {
                return z.difficulty;
            }
        }
        u32::MAX
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

    pub fn next_allowed_full_block(&self) -> u64 {
        match self.last_full_block {
            None => { self.height() + 1 }
            Some(ref block) => {
                if block.index < BLOCK_SIGNERS_START {
                    self.height() + 1
                } else {
                    max(block.index + BLOCK_SIGNERS_MIN, self.height() + 1)
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
        if block.version > CHAIN_VERSION {
            warn!("Ignoring block from unsupported version:\n{:?}", &block);
            return Bad;
        }
        let timestamp = Utc::now().timestamp();
        if block.timestamp > timestamp + 60 {
            warn!("Ignoring block from the future:\n{:?}", &block);
            return Bad;
        }
        if !check_public_key_strength(&block.pub_key, KEYSTORE_DIFFICULTY) {
            warn!("Ignoring block with weak public key:\n{:?}", &block);
            return Bad;
        }
        let difficulty = match &block.transaction {
            None => {
                if block.index == 1 {
                    ZONE_DIFFICULTY
                } else {
                    LOCKER_DIFFICULTY
                }
            }
            Some(t) => { self.get_difficulty_for_transaction(&t) }
        };
        if block.difficulty < difficulty {
            warn!("Block difficulty is lower than needed");
            return Bad;
        }
        if hash_difficulty(&block.hash) < block.difficulty {
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

        let faulty_block_hash = "0000133B790B61460D757E1F1F2D04480C8340D28CA73AE5AF27DBBF60548D00";
        let bytes = Bytes::from_bytes(&from_hex(faulty_block_hash).unwrap());
        if block.hash == bytes {
            warn!("Block {:?} is faulty! Ignoring!", &block);
            return Bad;
        }

        if let Some(transaction) = &block.transaction {
            // TODO check for zone transaction
            if !self.is_id_available(&transaction.identity, &block.pub_key, false) || !self.is_id_available(&transaction.identity, &block.pub_key, true) {
                warn!("Block {:?} is trying to spoof an identity!", &block);
                return Bad;
            }
            if let Some(last) = self.get_last_full_block(Some(&block.pub_key)) {
                let new_id = !self.is_id_in_blockchain(&transaction.identity, false);
                if new_id && last.timestamp + NEW_DOMAINS_INTERVAL > block.timestamp {
                    warn!("Block {:?} is mined too early!", &block);
                    return Bad;
                }
            }
            // Check if yggdrasil only quality of zone is not violated
            if let Some(block_data) = transaction.get_domain_data() {
                let zones = self.get_zones();
                for z in &zones {
                    if z.name == block_data.zone {
                        if z.yggdrasil {
                            for record in &block_data.records {
                                if !is_yggdrasil_record(record) {
                                    warn!("Someone mined domain with clearnet records for Yggdrasil only zone!");
                                    return Bad;
                                }
                            }
                        }
                    }
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
                    warn!("Block {} arrived too early.", block.index);
                    return Future;
                }
                if block.index > BLOCK_SIGNERS_START {
                    // If this block is main, signed part of blockchain
                    if !self.is_good_sign_block(&block) {
                        return Bad;
                    }
                }

                if block.index <= last_block.index {
                    if block.index == last_block.index && last_block.hash == block.hash {
                        debug!("Ignoring block {}, we already have it", block.index);
                        return Twin;
                    }
                    if let Some(my_block) = self.get_block(block.index) {
                        return if my_block.hash != block.hash {
                            warn!("Got forked block {} with hash {:?} instead of {:?}", block.index, block.hash, last_block.hash);
                            Fork
                        } else {
                            debug!("Ignoring block {}, we already have it", block.index);
                            Twin
                        };
                    }
                }

            }
        }

        Good
    }

    /// Checks if this block is a good signature block
    fn is_good_sign_block(&self, block: &Block) -> bool {
        if let Some(full_block) = &self.last_full_block {
            let sign_count = self.height() - full_block.index;
            if sign_count < BLOCK_SIGNERS_MIN {
                // Last full block is not locked enough
                if block.transaction.is_some() {
                    warn!("Not enough signing blocks over full {} block!", full_block.index);
                    return false;
                } else {
                    if !self.is_good_signer_for_block(&block, full_block, sign_count) {
                        return false;
                    }
                }
            } else if sign_count < BLOCK_SIGNERS_ALL && block.transaction.is_none() {
                if !self.is_good_signer_for_block(&block, full_block, sign_count) {
                    return false;
                }
            }
        }
        true
    }

    /// Check if this block's owner is a good candidate to sign last full block
    fn is_good_signer_for_block(&self, block: &Block, full_block: &Block, sign_count: u64) -> bool {
        // If the time for chosen signers is up
        if self.can_sign_by_pos(sign_count, full_block.timestamp, block.timestamp, &block.pub_key) {
            return true;
        }
        // If we got a locker/signing block
        let signers: HashSet<Bytes> = self.get_block_signers(full_block).into_iter().collect();
        if !signers.contains(&block.pub_key) {
            warn!("Ignoring block {} from '{:?}', as wrong signer!", block.index, &block.pub_key);
            return false;
        }
        // If this signers' public key has already locked/signed that block we return error
        for i in (full_block.index + 1)..block.index {
            let signer = self.get_block(i).expect("Error in DB!");
            if signer.pub_key == block.pub_key {
                warn!("Ignoring block {} from '{:?}', already signed by this key", block.index, &block.pub_key);
                return false;
            }
        }
        true
    }

    /// Gets an id of first block of this public key
    fn get_first_block_id_for_key(&self, key: &Bytes) -> u64 {
        match self.db.prepare(SQL_GET_FIRST_BLOCK_FOR_KEY) {
            Ok(mut statement) => {
                statement.bind(1, &***key).expect("Error in bind");
                while statement.next().unwrap() == State::Row {
                    return statement.read::<i64>(0).unwrap() as u64;
                }
                0
            }
            Err(_) => {
                0
            }
        }
    }

    /// Check if an owner of this public key can sign full block by PoS scheme (be in first 1000 users)
    fn can_sign_by_pos(&self, sign_count: u64, block_time: i64, now: i64, pub_key: &Bytes) -> bool {
        if sign_count < BLOCK_SIGNERS_MIN && block_time - now > BLOCK_SIGNERS_TIME {
            let index = self.get_first_block_id_for_key(&pub_key);
            if index > 0 && index <= BLOCK_POS_SIGNERS {
                return true;
            }
        }
        false
    }

    fn get_difficulty_for_transaction(&self, transaction: &Transaction) -> u32 {
        match transaction.class.as_ref() {
            "domain" => {
                return match serde_json::from_str::<DomainData>(&transaction.data) {
                    Ok(data) => {
                        for zone in self.get_zones().iter() {
                            if zone.name == data.zone {
                                return zone.difficulty;
                            }
                        }
                        u32::MAX
                    }
                    Err(_) => {
                        warn!("Error parsing DomainData from {:?}", transaction);
                        u32::MAX
                    }
                }
            }
            "zone" => { ZONE_DIFFICULTY }
            _ => { u32::MAX }
        }
    }

    /// Gets public keys of a node that needs to mine "signature" block above this block
    /// block - last full block
    pub fn get_block_signers(&self, block: &Block) -> Vec<Bytes> {
        let mut result = Vec::new();
        if block.index < BLOCK_SIGNERS_START {
            return result;
        }
        let mut set = HashSet::new();
        let tail = block.signature.get_tail_u64();
        let mut count = 1;
        let window = self.height() - 1; // Without the last block
        while set.len() < BLOCK_SIGNERS_ALL as usize {
            let index = ((tail * count) % window) + 1; // We want it to start from 1
            if let Some(b) = self.get_block(index) {
                if b.pub_key != block.pub_key && !set.contains(&b.pub_key) {
                    result.push(b.pub_key.clone());
                    set.insert(b.pub_key);
                }
            }
            count += 1;
        }
        trace!("Got signers for block {}: {:?}", block.index, &result);
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