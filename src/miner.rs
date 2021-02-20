use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_cpus;
use log::{trace, debug, info, warn, error};

use crate::{Block, Bytes, Context, hash_is_good, Transaction};
use crate::event::Event;

pub struct Miner {
    context: Arc<Mutex<Context>>,
    transactions: Arc<Mutex<Vec<Transaction>>>,
    running: Arc<AtomicBool>,
    mining: Arc<AtomicBool>,
    cond_var: Arc<Condvar>
}

impl Miner {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        Miner {
            context: context.clone(),
            transactions: Arc::new(Mutex::new(Vec::new())),
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
                    info!("Got new transaction to mine");
                    let transaction = lock.remove(0);
                    mining.store(true, Ordering::Relaxed);
                    Miner::mine_internal(context.clone(), transactions.clone(), transaction, mining.clone(), cond_var.clone());
                } else {
                    let _ = cond_var.wait(lock).expect("Error in wait lock!");
                }
            }
        });
        let mining = self.mining.clone();
        self.context.lock().unwrap().bus.register(move |_uuid, e| {
            if e == Event::ActionStopMining {
                mining.store(false, Ordering::Relaxed);
            }
            true
        });
    }

    pub fn is_mining(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn mine_internal(context: Arc<Mutex<Context>>, transactions: Arc<Mutex<Vec<Transaction>>>, mut transaction: Transaction, mining: Arc<AtomicBool>, cond_var: Arc<Condvar>) {
        let version= {
            let mut c = context.lock().unwrap();
            c.bus.post(Event::MinerStarted);
            c.settings.version
        };
        let block = {
            if transaction.signature.is_zero() {
                // Signing it with private key from Keystore
                let c = context.lock().unwrap();
                let sign_hash = c.keystore.sign(&transaction.get_bytes());
                transaction.set_signature(Bytes::from_bytes(&sign_hash));
            }

            // Get last block for mining
            let last_block = { context.lock().unwrap().blockchain.last_block() };
            match last_block {
                None => {
                    warn!("Mining genesis block");
                    // Creating a block with that signed transaction
                    Block::new(0, Utc::now().timestamp(), version, Bytes::zero32(), Some(transaction.clone()))
                },
                Some(block) => {
                    // Creating a block with that signed transaction
                    Block::new(block.index + 1, Utc::now().timestamp(), version, block.hash.clone(), Some(transaction.clone()))
                },
            }
        };

        let live_threads = Arc::new(AtomicU32::new(0u32));
        let cpus = num_cpus::get();
        debug!("Starting {} threads for mining", cpus);
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
                match find_hash(&mut Sha256::new(), block, mining.clone()) {
                    None => {
                        debug!("Mining did not find suitable hash or was stopped");
                        let count = live_threads.fetch_sub(1, Ordering::Relaxed);
                        // If this is the last thread, but mining was not stopped by another thread
                        if count == 0 && mining.load(Ordering::Relaxed) {
                            // If all threads came empty with mining we return transaction to the queue
                            transactions.lock().unwrap().push(transaction);
                            mining.store(false, Ordering::Relaxed);
                            cond_var.notify_one();
                        }
                    },
                    Some(block) => {
                        let index = block.index;
                        let mut context = context.lock().unwrap();
                        if context.blockchain.add_block(block).is_err() {
                            warn!("Error adding mined block!");
                            if index == 0 {
                                error!("To mine genesis block you need to make 'origin' an empty string in config.");
                            }
                        }
                        context.bus.post(Event::MinerStopped);
                        mining.store(false, Ordering::Relaxed);
                    },
                }
            });
        }
    }
}

fn find_hash(digest: &mut dyn Digest, mut block: Block, running: Arc<AtomicBool>) -> Option<Block> {
    let mut buf: [u8; 32] = [0; 32];
    block.random = rand::random();
    debug!("Mining block {}", serde_json::to_string(&block).unwrap());
    for nonce in 0..std::u64::MAX {
        if !running.load(Ordering::Relaxed) {
            return None;
        }
        block.timestamp = Utc::now().timestamp();
        block.nonce = nonce;

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