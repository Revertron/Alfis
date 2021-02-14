use sqlite::{Connection, State, Statement};

use crate::{Block, Bytes, Keystore, Transaction, Settings};

const DB_NAME: &str = "blockchain.db";

pub struct Blockchain {
    origin: Bytes,
    pub version: u32,
    pub blocks: Vec<Block>,
    last_block: Option<Block>,
    db: Connection,
}

impl Blockchain {
    pub fn new(settings: &Settings) -> Self {
        let origin = settings.get_origin();
        let version = settings.version;

        let db = sqlite::open(DB_NAME).expect("Unable to open blockchain DB");
        let mut blockchain = Blockchain{ origin, version, blocks: Vec::new(), last_block: None, db};
        blockchain.init_db();
        blockchain
    }

    /// Reads options from DB or initializes and writes them to DB if not found
    fn init_db(&mut self) {
        match self.db.prepare("SELECT * FROM blocks ORDER BY id DESC LIMIT 1;") {
            Ok(mut statement) => {
                while statement.next().unwrap() == State::Row {
                    match Self::get_block_from_statement(&mut statement) {
                        None => { println!("Something wrong with block in DB!"); }
                        Some(block) => {
                            println!("Loaded last block: {:?}", &block);
                            self.version = block.version;
                            self.last_block = Some(block);
                        }
                    }
                    println!("Blockchain version from DB = {}", self.version);
                }
            }
            Err(_) => {
                println!("No blockchain database found. Creating new.");
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
                                         'hash' BINARY
                                         );
                    CREATE INDEX block_index ON blocks (id);
                    CREATE TABLE transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, identity BINARY, confirmation BINARY, method TEXT, data TEXT, pub_key BINARY, signature BINARY);
                    CREATE INDEX ids ON transactions (identity);"
                ).expect("Error creating blocks table");
            }
        }
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), &str> {
        if !self.check_block(&block, &self.last_block) {
            println!("Bad block found, ignoring:\n{:?}", &block);
            return Err("Bad block found, ignoring");
        }
        println!("Adding block:\n{:?}", &block);
        self.blocks.push(block.clone());
        self.last_block = Some(block.clone());
        let transaction = block.transaction.clone();

        {
            // Adding block to DB
            let mut statement = self.db.prepare("INSERT INTO blocks (\
                    id, timestamp, version, difficulty, random,\
                    nonce, 'transaction', prev_block_hash, hash)\
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);").unwrap();
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
            statement.next().expect("Error adding block to DB");
        }

        match &transaction {
            None => {
                Err("Error adding transaction!")
            }
            Some(transaction) => {
                self.add_transaction(transaction);
                Ok(())
            }
        }
    }

    fn add_transaction(&mut self, t: &Transaction) {
        let mut statement = self.db.prepare("INSERT INTO transactions (identity, confirmation, method, data, pub_key, signature) VALUES (?, ?, ?, ?, ?, ?)").unwrap();
        statement.bind(1, t.identity.as_bytes()).expect("Error in bind");
        statement.bind(2, t.confirmation.as_bytes()).expect("Error in bind");
        statement.bind(3, t.method.as_ref() as &str).expect("Error in bind");
        statement.bind(4, t.data.as_ref() as &str).expect("Error in bind");
        statement.bind(5, t.pub_key.as_bytes()).expect("Error in bind");
        statement.bind(6, t.signature.as_bytes()).expect("Error in bind");
        statement.next().expect("Error adding transaction to DB");
    }

    pub fn get_block(&self, index: u64) -> Option<Block> {
        match self.db.prepare("SELECT * FROM blocks WHERE id=? LIMIT 1;") {
            Ok(mut statement) => {
                statement.bind(1, index as i64).expect("Error in bind");
                while statement.next().unwrap() == State::Row {
                    return match Self::get_block_from_statement(&mut statement) {
                        None => {
                            println!("Something wrong with block in DB!");
                            None
                        }
                        Some(block) => {
                            println!("Loaded block: {:?}", &block);
                            Some(block)
                        }
                    }
                }
                None
            }
            Err(_) => {
                println!("Can't find block {}", index);
                None
            }
        }
    }

    pub fn is_domain_available(&self, domain: &str, keystore: &Keystore) -> bool {
        if domain.is_empty() {
            return false;
        }
        let identity_hash = Transaction::hash_identity(domain);
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
            // Checking for available zone, for this domain
            let identity_hash = Transaction::hash_identity(parts.first().unwrap());
            let mut statement = self.db.prepare("SELECT identity FROM transactions WHERE identity = ? ORDER BY id DESC LIMIT 1;").unwrap();
            statement.bind(1, identity_hash.as_bytes()).expect("Error in bind");
            while let State::Row = statement.next().unwrap() {
                // If there is such a zone
                return true;
            }
            return false;
        }

        true
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

    /*pub fn check(&self) -> bool {
        let mut prev_block = None;
        for block in self.blocks.iter() {
            if !self.check_block(block, &prev_block) {
                println!("Block {:?} is bad", block);
                return false;
            }
            prev_block = Some(block);
        }
        true
    }*/

    fn check_block(&self, block: &Block, prev_block: &Option<Block>) -> bool {
        if !check_block_hash(block) {
            println!("{:?} has wrong hash! Ignoring!", &block);
            return false;
        }
        // TODO make transaction not Optional
        let transaction = block.transaction.as_ref().unwrap();
        if !check_transaction_signature(&transaction) {
            println!("{:?} has wrong signature! Ignoring block!", &transaction);
            return false;
        }
        match prev_block {
            None => {
                if block.index != 0 {
                    return false;
                }

                if self.origin.is_zero() && block.index > 0 {
                    panic!("Error adding block {} without origin! Please, fill in origin in config!", block.index);
                }

                self.origin.is_zero() || block.hash.eq(&self.origin)
            }
            Some(prev) => {
                if block.index != prev.index + 1 {
                    println!("Discarding block with index {} as not needed now", block.index);
                    return false;
                }
                block.prev_block_hash.eq(&prev.hash)
            }
        }
    }

    fn get_block_from_statement(statement: &mut Statement) -> Option<Block> {
        let index = statement.read::<i64>(0).unwrap() as u64;
        let timestamp = statement.read::<i64>(1).unwrap();
        let version = statement.read::<i64>(2).unwrap() as u32;
        let difficulty = statement.read::<i64>(3).unwrap() as usize;
        let random = statement.read::<i64>(4).unwrap() as u32;
        let nonce = statement.read::<i64>(5).unwrap() as u64;
        let transaction = Transaction::from_json(&statement.read::<String>(6).unwrap());
        let prev_block_hash = Bytes::from_bytes(statement.read::<Vec<u8>>(7).unwrap().as_slice());
        let hash = Bytes::from_bytes(statement.read::<Vec<u8>>(8).unwrap().as_slice());
        Some(Block::from_all_params(index, timestamp, version, difficulty, random, nonce, prev_block_hash, hash, transaction))
    }
}

pub fn check_block_hash(block: &Block) -> bool {
    let mut copy: Block = block.clone();
    copy.hash = Bytes::default();
    let data = serde_json::to_string(&copy).unwrap();
    Block::hash(data.as_bytes()) == block.hash
}

pub fn check_transaction_signature(transaction: &Transaction) -> bool {
    let mut copy = transaction.clone();
    copy.signature = Bytes::zero64();
    let data = copy.get_bytes();
    Keystore::check(data.as_slice(), copy.pub_key.as_bytes(), transaction.signature.as_bytes())
}
