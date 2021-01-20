use crate::{Block, Transaction, Bytes};
use chrono::Utc;
use sqlite::{Connection, State, Readable, Statement, Error};

const DB_NAME: &str = "blockchain.db";

pub struct Blockchain {
    pub chain_name: String,
    pub version_flags: u32,
    pub blocks: Vec<Block>,
    last_block: Option<Block>,
    db: Connection,
}

impl Blockchain {
    pub fn new(chain_name: &str, version_flags: u32) -> Self {
        let db = sqlite::open(DB_NAME).expect("Unable to open blockchain DB");
        let mut blockchain = Blockchain{ chain_name: chain_name.to_owned(), version_flags, blocks: Vec::new(), last_block: None, db};
        blockchain.init_db();
        blockchain
    }

    /// Reads options from DB or initializes and writes them to DB if not found
    fn init_db(&mut self) {
        match self.db.prepare("SELECT * FROM blocks ORDER BY id DESC LIMIT 1;") {
            Ok(mut statement) => {
                while statement.next().unwrap() == State::Row {
                    match Self::get_block(&mut statement) {
                        None => { println!("Something wrong with block in DB!"); }
                        Some(block) => {
                            println!("Loaded last block: {:?}", &block);
                            self.chain_name = block.chain_name.clone();
                            self.version_flags = block.version_flags;
                            self.last_block = Some(block);
                        }
                    }
                    println!("Loaded from DB: chain_name = {}, version_flags = {}", self.chain_name, self.version_flags);
                }
            }
            Err(_) => {
                println!("No blockchain database found. Creating new.");
                self.db.execute("
                    CREATE TABLE blocks (
                                         'id' BIGINT,
                                         'timestamp' BIGINT,
                                         'chain_name' TEXT,
                                         'version_flags' TEXT,
                                         'difficulty' INTEGER,
                                         'random' INTEGER,
                                         'nonce' INTEGER,
                                         'transaction' TEXT,
                                         'prev_block_hash' BINARY,
                                         'hash' BINARY
                                         );
                    CREATE INDEX block_index ON blocks (id);"
                ).expect("Error creating blocks table");
            }
        }
    }

    fn get_block(statement: &mut Statement) -> Option<Block> {
        let index = statement.read::<i64>(0).unwrap() as u64;
        let timestamp = statement.read::<i64>(1).unwrap();
        let chain_name = statement.read::<String>(2).unwrap();
        let version_flags = statement.read::<i64>(3).unwrap() as u32;
        let difficulty = statement.read::<i64>(4).unwrap() as usize;
        let random = statement.read::<i64>(5).unwrap() as u32;
        let nonce = statement.read::<i64>(6).unwrap() as u64;
        let transaction = Transaction::from_json(&statement.read::<String>(7).unwrap());
        let prev_block_hash = Bytes::from_bytes(statement.read::<Vec<u8>>(8).unwrap().as_slice());
        let hash = Bytes::from_bytes(statement.read::<Vec<u8>>(9).unwrap().as_slice());
        Some(Block::from_all_params(index, timestamp, &chain_name, version_flags, difficulty, random, nonce, prev_block_hash, hash, transaction))
    }

    pub fn add_block(&mut self, block: Block) {
        if self.check_block(&block, &self.last_block) {
            println!("Adding block:\n{:?}", &block);
            self.blocks.push(block.clone());
            self.last_block = Some(block.clone());

            // Adding block to DB
            let mut statement = self.db.prepare("INSERT INTO blocks (\
            id, timestamp, chain_name, version_flags, difficulty,\
            random, nonce, 'transaction', prev_block_hash, hash)\
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").unwrap();
            statement.bind(1, block.index as i64);
            statement.bind(2, block.timestamp as i64);
            statement.bind(3, &*block.chain_name);
            statement.bind(4, block.version_flags as i64);
            statement.bind(5, block.difficulty as i64);
            statement.bind(6, block.random as i64);
            statement.bind(7, block.nonce as i64);
            match block.transaction {
                None => { statement.bind(8, ""); }
                Some(transaction) => { statement.bind(8, &*transaction.to_string()); }
            }
            statement.bind(9, block.prev_block_hash.as_bytes());
            statement.bind(10, block.hash.as_bytes());
            statement.next().expect("Error adding block to DB");
        } else {
            println!("Bad block found, ignoring:\n{:?}", &block);
        }
    }

    pub fn get_last_block(&self) -> Option<Block> {
        self.last_block.clone()
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
        if !Self::check_block_hash(block) {
            return false;
        }
        if prev_block.is_none() {
            return true;
        }

        return block.prev_block_hash == prev_block.as_ref().unwrap().hash;
    }

    pub fn check_block_hash(block: &Block) -> bool {
        // We need to clear Hash value to rehash it without it for check :(
        let mut copy: Block = block.clone();
        copy.hash = Bytes::default();
        let data = serde_json::to_string(&copy).unwrap();
        Block::hash(data.as_bytes()) == block.hash
    }
}