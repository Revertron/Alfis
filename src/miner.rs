use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_cpus;

use crate::{Block, Bytes, Context, hash_is_good, Keystore, Transaction};
use crate::event::Event;

pub struct Miner {
    context: Arc<Mutex<Context>>,
    keystore: Keystore,
    chain_name: String,
    version_flags: u32,
    transactions: Arc<Mutex<Vec<Transaction>>>,
    last_block: Option<Block>,
    running: Arc<AtomicBool>,
    mining: Arc<AtomicBool>,
    cond_var: Arc<Condvar>
}

impl Miner {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        let c = context.lock().unwrap();
        Miner {
            context: context.clone(),
            keystore: c.keystore.clone(),
            chain_name: c.settings.chain_name.clone(),
            version_flags: c.settings.version_flags,
            transactions: Arc::new(Mutex::new(Vec::new())),
            last_block: c.blockchain.blocks.last().cloned(),
            running: Arc::new(AtomicBool::new(false)),
            mining: Arc::new(AtomicBool::new(false)),
            cond_var: Arc::new(Condvar::new())
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.lock().unwrap().push(transaction);
        self.cond_var.notify_one();
    }

    pub fn stop(&mut self) {
        self.mining.store(false, Ordering::Relaxed);
        self.running.store(false, Ordering::Relaxed);
        self.cond_var.notify_all();
    }

    pub fn start_mining_thread(&mut self) {
        let context = self.context.clone();
        let transactions = self.transactions.clone();
        let running = self.running.clone();
        let mining = self.mining.clone();
        let cond_var = self.cond_var.clone();
        thread::spawn(move || {
            running.store(true, Ordering::Relaxed);
            while running.load(Ordering::Relaxed) {
                // If some transaction is being mined now, we yield
                if mining.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let mut lock = transactions.lock().unwrap();
                if lock.len() > 0 {
                    println!("Starting to mine some transaction");
                    let transaction = lock.remove(0);
                    mining.store(true, Ordering::Relaxed);
                    Miner::mine_internal(context.clone(), transactions.clone(), transaction, mining.clone(), cond_var.clone());
                } else {
                    println!("Waiting for transactions");
                    cond_var.wait(lock);
                    println!("Got notified on new transaction");
                }
            }
        });
        let mining = self.mining.clone();
        self.context.lock().unwrap().bus.register(move |uuid, e| {
            if e == Event::ActionStopMining {
                mining.store(false, Ordering::Relaxed);
            }
            false
        });
    }

    pub fn is_mining(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn mine_internal(context: Arc<Mutex<Context>>, transactions: Arc<Mutex<Vec<Transaction>>>, mut transaction: Transaction, mining: Arc<AtomicBool>, cond_var: Arc<Condvar>) {
        let mut last_block_time = 0i64;
        let mut chain_name= String::new();
        let mut version_flags= 0u32;
        {
            let mut c = context.lock().unwrap();
            c.bus.post(Event::MinerStarted);
            chain_name = c.settings.chain_name.clone();
            version_flags = c.settings.version_flags;
        }
        let block = {
            if transaction.signature.is_zero() {
                // Signing it with private key from Keystore
                let c = context.lock().unwrap();
                let sign_hash = c.keystore.sign(&transaction.get_bytes());
                transaction.set_signature(Bytes::from_bytes(&sign_hash));
            }

            // Get last block for mining
            let last_block = { context.lock().unwrap().blockchain.get_last_block() };
            match last_block {
                None => {
                    println!("Mining genesis block");
                    // Creating a block with that signed transaction
                    Block::new(0, Utc::now().timestamp(), &chain_name, version_flags, Bytes::zero32(), Some(transaction.clone()))
                },
                Some(block) => {
                    last_block_time = block.timestamp;
                    // Creating a block with that signed transaction
                    Block::new(block.index + 1, Utc::now().timestamp(), &chain_name, version_flags, block.hash.clone(), Some(transaction.clone()))
                },
            }
        };

        let live_threads = Arc::new(AtomicU32::new(0u32));
        let cpus = num_cpus::get();
        println!("Starting {} threads for mining", cpus);
        for _ in 0..cpus {
            let transactions = transactions.clone();
            let context = context.clone();
            let transaction = transaction.clone();
            let block = block.clone();
            let mining = mining.clone();
            let live_threads = live_threads.clone();
            let cond_var = cond_var.clone();
            thread::spawn(move || {
                live_threads.fetch_add(1, Ordering::Relaxed);
                let mut count = 0u32;
                match find_hash(&mut Sha256::new(), block, last_block_time, mining.clone()) {
                    None => {
                        println!("Mining did not find suitable hash or was stopped");
                        count = live_threads.fetch_sub(1, Ordering::Relaxed);
                        // If this is the last thread, but mining was not stopped by another thread
                        if count == 0 && mining.load(Ordering::Relaxed) {
                            // If all threads came empty with mining we return transaction to the queue
                            transactions.lock().unwrap().push(transaction);
                            mining.store(false, Ordering::Relaxed);
                            cond_var.notify_one();
                        }
                    },
                    Some(block) => {
                        count = live_threads.fetch_sub(1, Ordering::Relaxed);
                        let mut context = context.lock().unwrap();
                        context.blockchain.add_block(block);
                        context.bus.post(Event::MinerStopped);
                        mining.store(false, Ordering::Relaxed);
                    },
                }
            });
        }
    }
}

fn find_hash(digest: &mut dyn Digest, mut block: Block, prev_block_time: i64, running: Arc<AtomicBool>) -> Option<Block> {
    let mut buf: [u8; 32] = [0; 32];
    block.random = rand::random();
    println!("Mining block {}", serde_json::to_string(&block).unwrap());
    //let start_difficulty = block.difficulty;
    for nonce in 0..std::u64::MAX {
        if !running.load(Ordering::Relaxed) {
            return None;
        }
        block.timestamp = Utc::now().timestamp();
        block.nonce = nonce;
        // if nonce % 1000 == 0 {
        //     println!("Nonce {}", nonce);
        // }
        // TODO uncomment for real run
        //block.difficulty = start_difficulty + get_time_difficulty(prev_block_time, block.timestamp);

        digest.reset();
        digest.input(serde_json::to_string(&block).unwrap().as_bytes());
        digest.result(&mut buf);
        if hash_is_good(&buf, block.difficulty) {
            block.hash = Bytes::from_bytes(&buf);
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