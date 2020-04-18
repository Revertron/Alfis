use crate::{Transaction, Block, Keystore, Key, Context};
use std::sync::{Mutex, Arc};
use crypto::digest::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use chrono::Utc;
use num_bigint::BigUint;
use num_traits::One;
use crypto::sha2::Sha256;
use std::thread;

pub struct Miner {
    context: Arc<Mutex<Context>>,
    keystore: Keystore,
    chain_id: u32,
    version: u32,
    transactions: Arc<Mutex<Vec<Transaction>>>,
    last_block: Option<Block>,
    running: Arc<AtomicBool>,
}

impl Miner {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        let c = context.lock().unwrap();
        Miner {
            context: context.clone(),
            keystore: c.keystore.clone(),
            chain_id: c.settings.chain_id,
            version: c.settings.version,
            transactions: Arc::new(Mutex::new(Vec::new())),
            last_block: c.blockchain.blocks.last().cloned(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.lock().unwrap().push(transaction);
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn mine(&mut self) {
        let transaction = { self.transactions.lock().unwrap().first().cloned() };
        match transaction {
            Some(transaction) => {
                self.mine_internal(transaction);
            },
            None => {
                println!("Nothing to mine");
            },
        }
    }

    pub fn is_mining(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn mine_internal(&mut self, mut transaction: Transaction) {
        let mut last_block_time = 0i64;
        let block = {
            // Signing it with private key from Keystore
            let sign_hash = self.keystore.sign(&transaction.get_bytes());
            transaction.set_signature(Key::from_bytes(&sign_hash));

            match &self.last_block {
                None => {
                    // Creating a block with that signed transaction
                    Block::new(0,Utc::now().timestamp(), self.chain_id, self.version, Key::zero32(), Some(transaction))
                },
                Some(block) => {
                    last_block_time = block.timestamp;
                    // Creating a block with that signed transaction
                    Block::new(block.index + 1,Utc::now().timestamp(), self.chain_id, self.version, block.hash.clone(), Some(transaction))
                },
            }
        };
        //let blockchain = self.blockchain.clone();
        let transactions = self.transactions.clone();
        let running = self.running.clone();
        running.store(true, Ordering::Relaxed);
        let context = self.context.clone();
        thread::spawn(move || {
            match find_hash(&mut Sha256::new(), block, last_block_time, running.clone()) {
                None => {
                    println!("Mining stopped");
                },
                Some(block) => {
                    //blockchain.lock().unwrap().add_block(block);
                    transactions.lock().unwrap().remove(0);
                    running.store(false, Ordering::Relaxed);
                    context.lock().unwrap().blockchain.add_block(block);
                },
            }
        });
    }
}

fn find_hash(digest: &mut dyn Digest, mut block: Block, prev_block_time: i64, running: Arc<AtomicBool>) -> Option<Block> {
    let mut buf: [u8; 32] = [0; 32];
    block.random = rand::random();
    let start_difficulty = block.difficulty;
    for nonce in 0..std::u64::MAX {
        if !running.load(Ordering::Relaxed) {
            return None;
        }
        block.timestamp = Utc::now().timestamp();
        block.nonce = nonce;
        // TODO uncomment for real run
        //block.difficulty = start_difficulty + get_time_difficulty(prev_block_time, block.timestamp);

        digest.reset();
        digest.input(serde_json::to_string(&block).unwrap().as_bytes());
        digest.result(&mut buf);
        if hash_is_good(&buf, block.difficulty) {
            block.hash = Key::from_bytes(&buf);
            return Some(block);
        }
    }
    None
}

fn get_time_difficulty(prev_time: i64, now: i64) -> usize {
    let diff = now - prev_time;
    if diff < 900_000 {
        (900_000 as usize - diff as usize) / 60_000
    } else {
        0
    }
}

fn hash_is_good(hash: &[u8], difficulty: usize) -> bool {
    let target = BigUint::one() << ((hash.len() << 3) - difficulty);
    let hash_int = BigUint::from_bytes_be(&hash);

    return hash_int < target;
}