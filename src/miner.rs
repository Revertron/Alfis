use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use num_cpus;
use thread_priority::*;

use crate::{Block, Bytes, Context, hash_is_good};
use crate::blockchain::blockchain::BlockQuality;
use crate::blockchain::{BLOCK_DIFFICULTY, CHAIN_VERSION, LOCKER_DIFFICULTY};
use crate::event::Event;

pub struct Miner {
    context: Arc<Mutex<Context>>,
    blocks: Arc<Mutex<Vec<Block>>>,
    running: Arc<AtomicBool>,
    mining: Arc<AtomicBool>,
    cond_var: Arc<Condvar>
}

impl Miner {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        Miner {
            context: context.clone(),
            blocks: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            mining: Arc::new(AtomicBool::new(false)),
            cond_var: Arc::new(Condvar::new())
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.lock().unwrap().push(block);
        self.cond_var.notify_one();
    }

    pub fn stop(&mut self) {
        self.mining.store(false, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
        self.cond_var.notify_all();
    }

    pub fn start_mining_thread(&mut self) {
        let context = self.context.clone();
        let blocks = self.blocks.clone();
        let running = self.running.clone();
        let mining = self.mining.clone();
        let cond_var = self.cond_var.clone();
        thread::spawn(move || {
            running.store(true, Ordering::SeqCst);
            while running.load(Ordering::SeqCst) {
                // If some transaction is being mined now, we yield
                if mining.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1000));
                    continue;
                }

                let mut lock = blocks.lock().unwrap();
                if lock.len() > 0 {
                    info!("Got new block to mine");
                    let block = lock.remove(0);
                    mining.store(true, Ordering::SeqCst);
                    Miner::mine_internal(context.clone(), block, mining.clone());
                } else {
                    let _ = cond_var.wait(lock).expect("Error in wait lock!");
                }
            }
        });
        let mining = self.mining.clone();
        let blocks = self.blocks.clone();
        let cond_var = self.cond_var.clone();
        self.context.lock().unwrap().bus.register(move |_uuid, e| {
            match e {
                Event::NewBlockReceived => {}
                Event::BlockchainChanged => {}
                Event::ActionStopMining => {
                    mining.store(false, Ordering::SeqCst);
                }
                Event::ActionMineLocker { index, hash } => {
                    if !mining.load(Ordering::SeqCst) {
                        let mut block = Block::new(None, Bytes::default(), hash);
                        block.index = index;
                        blocks.lock().unwrap().push(block);
                        cond_var.notify_all();
                        info!("Added a locker block to mine");
                    }
                }
                _ => {}
            }
            true
        });
    }

    pub fn is_mining(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn mine_internal(context: Arc<Mutex<Context>>, mut block: Block, mining: Arc<AtomicBool>) {
        // Clear signature and hash just in case
        block.signature = Bytes::default();
        block.hash = Bytes::default();
        block.version = CHAIN_VERSION;
        // If this block needs to be a locker
        if block.index > 0 && !block.prev_block_hash.is_empty() {
            info!("Mining locker block");
            block.difficulty = LOCKER_DIFFICULTY;
            block.pub_key = context.lock().unwrap().keystore.get_public();
            match context.lock().unwrap().blockchain.last_block() {
                None => {}
                Some(last_block) => {
                    info!("Last block found");
                    // If we were doing something else and got new block before we could mine this block
                    if last_block.index > block.index || last_block.hash != block.prev_block_hash {
                        warn!("We missed block to lock");
                        context.lock().unwrap().bus.post(Event::MinerStopped);
                        mining.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }
        } else {
            block.difficulty = BLOCK_DIFFICULTY;
            block.index = context.lock().unwrap().blockchain.height() + 1;
            block.prev_block_hash = match context.lock().unwrap().blockchain.last_block() {
                None => { Bytes::default() }
                Some(block) => { block.hash }
            };
        }

        context.lock().unwrap().bus.post(Event::MinerStarted);
        let live_threads = Arc::new(AtomicU32::new(0u32));
        let cpus = num_cpus::get();
        debug!("Starting {} threads for mining", cpus);
        for _ in 0..cpus {
            let context = context.clone();
            let block = block.clone();
            let mining = mining.clone();
            let live_threads = live_threads.clone();
            thread::spawn(move || {
                let _ = set_current_thread_priority(ThreadPriority::Min);
                live_threads.fetch_add(1, Ordering::SeqCst);
                match find_hash(&mut Sha256::new(), block, mining.clone()) {
                    None => {
                        debug!("Mining was cancelled");
                        let count = live_threads.fetch_sub(1, Ordering::SeqCst);
                        // If this is the last thread, but mining was not stopped by another thread
                        if count == 1 {
                            let mut context = context.lock().unwrap();
                            context.bus.post(Event::MinerStopped);
                        }
                    },
                    Some(mut block) => {
                        let index = block.index;
                        let mut context = context.lock().unwrap();
                        block.signature = Bytes::from_bytes(&context.keystore.sign(&block.as_bytes()));
                        if context.blockchain.check_new_block(&block) != BlockQuality::Good {
                            warn!("Error adding mined block!");
                            if index == 0 {
                                error!("To mine genesis block you need to make 'origin' an empty string in config.");
                            }
                        } else {
                            context.blockchain.add_block(block);
                        }
                        context.bus.post(Event::MinerStopped);
                        mining.store(false, Ordering::SeqCst);
                    },
                }
            });
        }
    }
}

fn find_hash(digest: &mut dyn Digest, mut block: Block, running: Arc<AtomicBool>) -> Option<Block> {
    let mut buf: [u8; 32] = [0; 32];
    let difficulty = block.difficulty as usize;
    loop {
        block.random = rand::random();
        debug!("Mining block {}", serde_json::to_string(&block).unwrap());
        for nonce in 0..std::u64::MAX {
            if !running.load(Ordering::Relaxed) {
                return None;
            }
            block.timestamp = Utc::now().timestamp();
            block.nonce = nonce;

            digest.reset();
            digest.input(&block.as_bytes());
            digest.result(&mut buf);
            if hash_is_good(&buf, difficulty) {
                block.hash = Bytes::from_bytes(&buf);
                return Some(block);
            }
        }
    }
}