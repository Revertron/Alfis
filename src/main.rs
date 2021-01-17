#![windows_subsystem = "windows"]
extern crate web_view;
use alfis::{Blockchain, Block, Transaction, Keystore, Bytes, Settings, Context};
use alfis::miner::Miner;
use web_view::*;
use std::thread;
use rand::{Rng, RngCore};

use std::sync::{Arc, Mutex};
extern crate serde;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

extern crate serde_json;

const ONE_YEAR: u16 = 365;
const GENESIS_ZONE: &str = "ygg";
const GENESIS_ZONE_DIFFICULTY: u16 = 20;
const KEYSTORE_DIFFICULTY: usize = 24;
const SETTINGS_FILENAME: &str = "alfis.cfg";

fn main() {
    println!("ALFIS 0.1.0");
    let settings = Settings::load(SETTINGS_FILENAME).expect("Error loading settings");
    let keystore: Keystore = match Keystore::from_file(&settings.key_file, "") {
        None => { generate_key(KEYSTORE_DIFFICULTY, Arc::new(AtomicBool::new(true))).expect("Could not load or generate keypair") }
        Some(keystore) => { keystore }
    };
    let blockchain: Blockchain = Blockchain::new(settings.chain_id, settings.version);
    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(Context::new(settings, keystore, blockchain)));

    let mut miner_obj = Miner::new(context.clone());
    miner_obj.start_mining_thread();
    let miner: Arc<Mutex<Miner>> = Arc::new(Mutex::new(miner_obj));

    create_genesis_if_needed(&context, &miner);
    run_interface(context.clone(), miner.clone());
}

fn create_genesis_if_needed(context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>) {
    // TODO check settings and if there is no mention of bootstrap nodes, generate genesis block
    let keystore = {
        // This code block makes it possible to contain quick lock here, and let the miner below work
        let context_guard = context.lock().unwrap();
        if context_guard.get_blockchain().blocks.is_empty() {
            // If blockchain is empty, we are going to mine a Genesis block
            Some(context_guard.get_keystore())
        } else {
            None
        }
    };

    if keystore.is_some() {
        create_genesis(miner.clone(), GENESIS_ZONE, &keystore.unwrap(), GENESIS_ZONE_DIFFICULTY);
    }
}

fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>) {
    let file_content = include_str!("index.html");
    let styles = inline_style(include_str!("bulma.css"));
    let scripts = inline_script(include_str!("scripts.js"));

    web_view::builder()
        .title("ALFIS 0.1.0")
        .content(Content::Html(file_content.to_owned().replace("{styles}", &styles).replace("{scripts}", &scripts)))
        .size(1024, 720)
        .resizable(true)
        .debug(true)
        .user_data(())
        .invoke_handler(|_web_view, arg| {
            use Cmd::*;
            println!("Command {}", arg);
            match serde_json::from_str(arg).unwrap() {
                LoadKey { name, pass } => {
                    match Keystore::from_file(&name, &pass) {
                        None => {
                            println!("Error loading keystore '{}'!", &name);
                        },
                        Some(k) => {
                            let mut c = context.lock().unwrap();
                            c.set_keystore(k);
                        },
                    }
                },
                CreateKey { name, pass } => {
                    create_key(context.clone(), &name, &pass);
                }
                CreateDomain { name, records, tags } => {
                    let keystore = {
                        let mut guard = context.lock().unwrap();
                        guard.get_keystore()
                    };
                    create_domain(miner.clone(), name, records, &keystore);
                }
                ChangeDomain { name, records, tags } => {
                    let keystore = { context.lock().unwrap().get_keystore() };
                    // TODO
                }
                RenewDomain { name, days } => {}
                TransferDomain { name, owner } => {}
            }
            //dbg!(&signature);
            Ok(())
        })
        .run()
        .unwrap();
}

fn create_genesis<S: Into<String>>(miner: Arc<Mutex<Miner>>, name: S, keystore: &Keystore, difficulty: u16) {
    let mut transaction = Transaction::from_str(name.into(), "zone".to_owned(), difficulty.to_string(), keystore.get_public().clone());
    // Signing it with private key from Signature
    let sign_hash = keystore.sign(&transaction.get_bytes());
    transaction.set_signature(Bytes::from_bytes(&sign_hash));
    let mut miner_guard = miner.lock().unwrap();
    miner_guard.add_transaction(transaction);
}

fn create_domain<S: Into<String>>(miner: Arc<Mutex<Miner>>, name: S, data: S, keystore: &Keystore) {
    let name = name.into();
    println!("Generating domain {}", name);
    //let rec_vector: Vec<String> = records.into().trim().split("\n").map(|s| s.trim()).map(String::from).collect();
    //let tags_vector: Vec<String> = tags.into().trim().split(",").map(|s| s.trim()).map(String::from).collect();
    let mut transaction = { create_transaction(keystore, name, "domain".into(), data.into()) };
    let mut miner_guard = miner.lock().unwrap();
    miner_guard.add_transaction(transaction);
}

fn create_transaction<S: Into<String>>(keystore: &Keystore, name: S, method: S, data: S) -> Transaction {
    // Creating transaction
    // TODO Do not use owner for now, make a field in UI and use it if filled
    let mut transaction = Transaction::from_str(name.into(), method.into(), data.into(), keystore.get_public().clone());
    // Signing it with private key from Signature
    let sign_hash = keystore.sign(&transaction.get_bytes());
    transaction.set_signature(Bytes::from_bytes(&sign_hash));
    transaction
}

fn create_key(context: Arc<Mutex<Context>>, filename: &str, password: &str) {
    let mut mining = Arc::new(AtomicBool::new(true));
    for _ in 0..num_cpus::get() {
        let context = context.clone();
        let filename= filename.to_owned();
        let password= password.to_owned();
        let mining = mining.clone();
        thread::spawn(move || {
            match generate_key(KEYSTORE_DIFFICULTY, mining.clone()) {
                None => { println!("Keystore mining finished"); }
                Some(keystore) => {
                    let mut c = context.lock().unwrap();
                    mining.store(false,Ordering::Relaxed);
                    keystore.save(&filename, &password);
                    c.set_keystore(keystore);
                }
            }
        });
    }
}

fn generate_key(difficulty: usize, mining: Arc<AtomicBool>) -> Option<Keystore> {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 64];
    loop {
        rng.fill_bytes(&mut buf);
        let keystore = Keystore::from_bytes(&buf);
        if keystore.hash_is_good(difficulty) {
            println!("Generated keypair: {:?}", &keystore);
            return Some(keystore);
        }
        if !mining.load(Ordering::Relaxed) {
            return None;
        }
    }
    None
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
pub enum Cmd {
    LoadKey{name: String, pass: String},
    CreateKey{name: String, pass: String},
    CreateDomain{name: String, records: String, tags: String},
    ChangeDomain{name: String, records: String, tags: String},
    RenewDomain{name: String, days: u16},
    TransferDomain{name: String, owner: String},
}

fn inline_style(s: &str) -> String {
    format!(r#"<style type="text/css">{}</style>"#, s)
}

fn inline_script(s: &str) -> String {
    format!(r#"<script type="text/javascript">{}</script>"#, s)
}

fn test_blockchain() -> () {
    let mut blockchain = Blockchain::new(42, 0);
    println!("Blockchain with genesis block has been created");
    let keystore = Keystore::from_file("default.key", "").unwrap();

    /*let mut block = create_transaction(&mut blockchain, keystore.clone(), "test.zz", vec!["AAAA IN 301:2925::1".to_owned()], vec!["testing".to_owned(), "example".to_owned()], 365);

    // Mining the nonce
    block.mine();

    // Our block is ready, we can print it and add to Blockchain
    let s = serde_json::to_string(&block).unwrap();
    println!("Serialized block:\n{}", s);
    blockchain.add_block(block);
    println!("Second block added");

    let block2: Block = serde_json::from_str(&s).unwrap();
    println!("DeSerialized block:\n{:?}", block2);*/

    // Let's check if the blockchain is valid
    if blockchain.check() {
        println!("Blockchain is correct");
    } else {
        println!("Blockchain is corrupted, aborting");
    }
}
