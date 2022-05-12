use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::{Duration, Instant};

use blakeout::Blakeout;
use chrono::Utc;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use num_cpus;

use crate::blockchain::hash_utils::*;
use crate::blockchain::types::BlockQuality;
use crate::commons::*;
use crate::event::Event;
use crate::eventbus::{post, register};
use crate::keystore::check_public_key_strength;
use crate::{setup_miner_thread, Block, Bytes, Context, Keystore};

#[derive(Clone)]
pub struct MineJob {
    start: i64,
    block: Block,
    keystore: Keystore
}

impl MineJob {
    fn is_full(&self) -> bool {
        self.block.transaction.is_some()
    }

    fn is_signing(&self) -> bool {
        self.block.transaction.is_none()
    }

    fn is_due(&self) -> bool {
        self.start == 0 || self.start < Utc::now().timestamp()
    }
}

#[derive(Clone, Debug)]
pub struct MinerState {
    pub mining: bool,
    pub full: bool
}

pub struct Miner {
    context: Arc<Mutex<Context>>,
    jobs: Arc<Mutex<Vec<MineJob>>>,
    running: Arc<AtomicBool>,
    mining: Arc<AtomicBool>,
    cond_var: Arc<Condvar>
}

impl Miner {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        Miner {
            context,
            jobs: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            mining: Arc::new(AtomicBool::new(false)),
            cond_var: Arc::new(Condvar::new())
        }
    }

    pub fn add_block(&mut self, block: Block, keystore: Keystore) {
        {
            let mut jobs = self.jobs.lock().unwrap();
            if block.transaction.is_none() {
                jobs.retain(|job| job.block.transaction.is_some());
            }
            jobs.push(MineJob { start: 0, block, keystore });
        }
        self.cond_var.notify_one();
    }

    pub fn stop(&mut self) {
        self.mining.store(false, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
        self.cond_var.notify_all();
    }

    pub fn start_mining_thread(&mut self) {
        let context = Arc::clone(&self.context);
        let jobs = self.jobs.clone();
        let running = self.running.clone();
        let mining = self.mining.clone();
        let cond_var = self.cond_var.clone();
        thread::spawn(move || {
            Miner::run_main_loop(&context, jobs, running, mining, cond_var);
        });

        // Add events listener to a [Bus]
        let running = self.running.clone();
        let mining = self.mining.clone();
        register(move |_uuid, e| {
            match e {
                Event::ActionQuit => { running.store(false, Ordering::Relaxed); }
                Event::NewBlockReceived => {}
                Event::BlockchainChanged { .. } => {}
                Event::ActionStopMining => {
                    mining.store(false, Ordering::SeqCst);
                }
                _ => {}
            }
            true
        });
    }

    fn run_main_loop(context: &Arc<Mutex<Context>>, jobs: Arc<Mutex<Vec<MineJob>>>, running: Arc<AtomicBool>, mining: Arc<AtomicBool>, cond_var: Arc<Condvar>) {
        running.store(true, Ordering::SeqCst);
        let delay = Duration::from_secs(30);
        let mut current_job: Option<MineJob> = None;
        while running.load(Ordering::SeqCst) {
            if let Some(ref cur_job) = current_job {
                // If we are mining signing block
                if mining.load(Ordering::Relaxed) && cur_job.is_signing() {
                    sleep(delay);
                    continue;
                }

                // If we are mining something ours
                if mining.load(Ordering::Relaxed) && cur_job.is_full() {
                    let mut signing_waits = false;
                    let mut jobs = jobs.lock().unwrap();
                    if jobs.len() > 0 {
                        debug!("Got new job to mine");
                        let job = jobs.remove(0);
                        // If we have some signing job
                        if job.is_signing() && job.is_due() {
                            info!("Replacing current mining job with signing job!");
                            // We cancel current job, waiting for threads to finish
                            mining.store(false, Ordering::SeqCst);
                            sleep(Duration::from_millis(100));
                            // Return current job to queue
                            jobs.insert(0, current_job.take().unwrap());

                            mining.store(true, Ordering::SeqCst);
                            current_job = Some(job.clone());
                            Miner::mine_internal(Arc::clone(context), job, mining.clone());
                            continue;
                        } else {
                            debug!("This job will wait for now");
                            signing_waits = job.is_signing();
                            jobs.insert(0, job);
                        }
                    }

                    if !signing_waits {
                        if let Ok(context) = context.lock() {
                            let keystores = context.get_keystores();
                            // Ask the blockchain if we have to sign something
                            if let Some((block, keystore)) = context.chain.get_sign_block(keystores) {
                                info!("Got signing job, adding to queue");
                                // We start mining sign block after some time, not everyone in the same time
                                let start = Utc::now().timestamp() + (rand::random::<i64>() % BLOCK_SIGNERS_START_RANDOM);
                                jobs.push(MineJob { start, block, keystore });
                            }
                        }
                    }
                    let _lock = cond_var.wait_timeout(jobs, delay).expect("Error in wait lock!");
                }
            } else {
                let mut jobs = jobs.lock().unwrap();
                if jobs.len() > 0 {
                    debug!("Got new job to mine");
                    let job = jobs.remove(0);
                    if job.is_due() {
                        mining.store(true, Ordering::SeqCst);
                        current_job = Some(job.clone());
                        Miner::mine_internal(Arc::clone(context), job, mining.clone());
                    } else {
                        debug!("This job will wait for now");
                        jobs.insert(0, job);
                    }
                } else {
                    // If our queue is empty
                    if let Ok(context) = context.lock() {
                        let keystores = context.get_keystores();
                        // Ask the blockchain if we have to sign something
                        if let Some((block, keystore)) = context.chain.get_sign_block(keystores) {
                            info!("Got signing job, adding to queue");
                            // We start mining sign block after some time, not everyone in the same time
                            let start = Utc::now().timestamp() + (rand::random::<i64>() % BLOCK_SIGNERS_START_RANDOM);
                            jobs.push(MineJob { start, block, keystore });
                        }
                    }
                }
                let _lock = cond_var.wait_timeout(jobs, delay).expect("Error in wait lock!");
            }

            if !mining.load(Ordering::Relaxed) {
                current_job = None;
            }
        }
        info!("Stopped mining queue thread");
    }

    pub fn is_mining(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn mine_internal(context: Arc<Mutex<Context>>, mut job: MineJob, mining: Arc<AtomicBool>) {
        // Clear signature and hash just in case
        job.block.signature = Bytes::default();
        job.block.hash = Bytes::default();
        job.block.version = CHAIN_VERSION;
        // If this block needs to be a signer
        if job.block.index > 0 && !job.block.prev_block_hash.is_empty() {
            info!("Mining signing block");
            job.block.pub_key = job.keystore.get_public();
            if !check_public_key_strength(&job.block.pub_key, KEYSTORE_DIFFICULTY) {
                warn!("Can not mine block with weak public key!");
                post(Event::MinerStopped { success: false, full: false });
                mining.store(false, Ordering::SeqCst);
                return;
            }
            let new_block = context.lock().unwrap().chain.update_sign_block_for_mining(job.block);
            match new_block {
                None => {
                    warn!("We missed block to lock");
                    post(Event::MinerStopped { success: false, full: false });
                    mining.store(false, Ordering::SeqCst);
                    return;
                }
                Some(block) => {
                    job.block = block;
                }
            }
        } else {
            job.block.index = context.lock().unwrap().chain.get_height() + 1;
            job.block.prev_block_hash = match context.lock().unwrap().chain.last_block() {
                None => Bytes::default(),
                Some(block) => block.hash
            };
        }

        let (lower, threads) = {
            post(Event::MinerStarted);
            let mut context = context.lock().unwrap();
            context.miner_state.mining = true;
            context.miner_state.full = job.block.transaction.is_some();
            (context.settings.mining.lower, context.settings.mining.threads)
        };
        let cpus = num_cpus::get();
        let threads = match threads {
            0 => cpus,
            _ => threads
        } as u32;
        debug!("Starting {} threads for mining", threads);
        debug!("Mining block {}", serde_json::to_string(&job.block).unwrap());
        let thread_spawn_interval = Duration::from_millis(100);
        let live_threads = Arc::new(AtomicU32::new(0u32));
        for cpu in 0..threads {
            let context = Arc::clone(&context);
            let job = job.clone();
            let mining = Arc::clone(&mining);
            let live_threads = Arc::clone(&live_threads);
            thread::spawn(move || {
                live_threads.fetch_add(1, Ordering::SeqCst);
                if lower {
                    setup_miner_thread(cpu);
                }
                let full = job.block.transaction.is_some();
                match find_hash(Arc::clone(&context), job.block, Arc::clone(&mining), cpu) {
                    None => {
                        if live_threads.load(Ordering::Relaxed) >= threads {
                            debug!("Mining was cancelled");
                        }
                        let count = live_threads.fetch_sub(1, Ordering::SeqCst);
                        // If this is the last thread, but mining was not stopped by another thread
                        if count == 1 {
                            if let Ok(mut context) = context.lock() {
                                context.miner_state.mining = false;
                            }
                            post(Event::MinerStopped { success: false, full });
                        }
                    }
                    Some(mut block) => {
                        let index = block.index;
                        let mut context = context.lock().unwrap();
                        block.signature = Bytes::from_bytes(&job.keystore.sign(&block.as_bytes_compact()));
                        let mut success = false;
                        if context.chain.check_new_block(&block) != BlockQuality::Good {
                            warn!("Error adding mined block!");
                            if index == 0 {
                                error!("To mine genesis block you need to make 'origin' an empty string in config.");
                            }
                        } else {
                            info!("Mined good block!");
                            if block.index == 1 {
                                context.settings.origin = block.hash.to_string();
                            }
                            context.chain.add_block(block);
                            success = true;
                        }
                        context.miner_state.mining = false;
                        post(Event::MinerStopped { success, full });
                        mining.store(false, Ordering::SeqCst);
                    }
                }
            });
            thread::sleep(thread_spawn_interval);
        }
    }
}

fn find_hash(context: Arc<Mutex<Context>>, mut block: Block, running: Arc<AtomicBool>, thread: u32) -> Option<Block> {
    let target_diff = block.difficulty;
    let full = block.transaction.is_some();
    let mut digest = Blakeout::new();
    let mut max_diff = 0;
    loop {
        block.random = rand::random();
        block.timestamp = Utc::now().timestamp();
        let waiting_signers = {
            let context = context.lock().unwrap();
            if let Some(b) = context.chain.last_block() {
                block.prev_block_hash = b.hash;
                block.index = b.index + 1;
            }
            context.chain.is_waiting_signers()
        };
        if !running.load(Ordering::Relaxed) {
            return None;
        }
        if full && waiting_signers {
            //trace!("Mining full block is not allowed until previous is not signed");
            // We can't mine now, as we need to wait for block to be signed
            thread::sleep(Duration::from_millis(5000));
            continue;
        }

        let mut time = Instant::now();
        let mut prev_nonce = 0;
        for nonce in 0..u64::MAX {
            if !running.load(Ordering::Relaxed) {
                return None;
            }
            block.nonce = nonce;

            digest.reset();
            digest.update(&block.as_bytes_compact());
            let diff = hash_difficulty(digest.result());
            if diff >= target_diff {
                block.hash = Bytes::from_bytes(digest.result());
                return Some(block);
            }
            if diff > max_diff {
                max_diff = diff;
            }

            let elapsed = time.elapsed().as_millis();
            if elapsed >= 1000 {
                block.timestamp = Utc::now().timestamp();
                if elapsed > 10000 {
                    let speed = (nonce - prev_nonce) / (elapsed as u64 / 1000);
                    //debug!("Mining speed {} H/s, max difficulty {}", speed, max_diff);
                    post(Event::MinerStats { thread, speed, max_diff, target_diff });
                    time = Instant::now();
                    prev_nonce = nonce;
                }

                if block.index > 1 {
                    if let Ok(context) = context.try_lock() {
                        if context.chain.get_height() >= block.index {
                            if !full {
                                //trace!("Blockchain changed while mining signing block, dropping work");
                                running.store(false, Ordering::SeqCst);
                                return None;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}