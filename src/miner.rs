use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering, AtomicU64};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use crypto::digest::Digest;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use num_cpus;

use crate::{Block, Bytes, Context, setup_miner_thread};
use crate::commons::{CHAIN_VERSION, LOCKER_DIFFICULTY, KEYSTORE_DIFFICULTY};
use crate::blockchain::enums::BlockQuality;
use crate::blockchain::hash_utils::*;
use crate::keys::check_public_key_strength;
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
                Event::BlockchainChanged {..} => {}
                Event::ActionStopMining => {
                    mining.store(false, Ordering::SeqCst);
                }
                Event::ActionMineLocker { index, hash } => {
                    if !mining.load(Ordering::SeqCst) {
                        let mut block = Block::new(None, Bytes::default(), hash, LOCKER_DIFFICULTY);
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
            block.pub_key = context.lock().unwrap().keystore.get_public();
            if !check_public_key_strength(&block.pub_key, KEYSTORE_DIFFICULTY) {
                warn!("Can not mine block with weak public key!");
                context.lock().unwrap().bus.post(Event::MinerStopped);
                mining.store(false, Ordering::SeqCst);
                return;
            }
            match context.lock().unwrap().chain.last_block() {
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
            block.index = context.lock().unwrap().chain.height() + 1;
            block.prev_block_hash = match context.lock().unwrap().chain.last_block() {
                None => { Bytes::default() }
                Some(block) => { block.hash }
            };
        }

        context.lock().unwrap().bus.post(Event::MinerStarted);
        let thread_spawn_interval = Duration::from_millis(10);
        let live_threads = Arc::new(AtomicU32::new(0u32));
        let top_block = Arc::new(AtomicU64::new(block.index - 1));
        let cpus = num_cpus::get();
        debug!("Starting {} threads for mining", cpus);
        for cpu in 0..cpus {
            let context = Arc::clone(&context);
            let block = block.clone();
            let mining = Arc::clone(&mining);
            let top_block = Arc::clone(&top_block);
            let live_threads = Arc::clone(&live_threads);
            thread::spawn(move || {
                // Register this thread to receive events from bus
                let top = Arc::clone(&top_block);
                context.lock().unwrap().bus.register(move |_uuid, e| {
                    match e {
                        Event::NewBlockReceived => {}
                        Event::BlockchainChanged { index } => {
                            top.store(index, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    true
                });

                setup_miner_thread(cpu as u32);
                live_threads.fetch_add(1, Ordering::SeqCst);
                let mut hasher = get_hasher_for_version(block.version);
                match find_hash(Arc::clone(&context), &mut *hasher, block, Arc::clone(&mining), top_block) {
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
                        if context.chain.check_new_block(&block) != BlockQuality::Good {
                            warn!("Error adding mined block!");
                            if index == 0 {
                                error!("To mine genesis block you need to make 'origin' an empty string in config.");
                            }
                        } else {
                            if block.index == 1 {
                                context.settings.origin = block.hash.to_string();
                            }
                            context.chain.add_block(block);
                        }
                        context.bus.post(Event::MinerStopped);
                        mining.store(false, Ordering::SeqCst);
                    },
                }
            });
            thread::sleep(thread_spawn_interval);
        }
    }
}

fn find_hash(context: Arc<Mutex<Context>>, digest: &mut dyn Digest, mut block: Block, running: Arc<AtomicBool>, top_block: Arc<AtomicU64>) -> Option<Block> {
    let mut buf: [u8; 32] = [0; 32];
    let difficulty = block.difficulty as usize;
    let full = block.transaction.is_some();
    loop {
        block.random = rand::random();
        block.index = context.lock().unwrap().chain.height() + 1;
        if full && context.lock().unwrap().chain.next_allowed_block() > block.index {
            // We can't mine now, as we need to wait for block to be signed
            thread::sleep(Duration::from_millis(1000));
            continue;
        }
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

            if top_block.load(Ordering::SeqCst) >= block.index {
                // If there is a new block in chain we restart hashing with new data
                break;
            }
        }
    }
}