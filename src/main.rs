#![windows_subsystem = "windows"]
extern crate web_view;
extern crate tinyfiledialogs as tfd;

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering, AtomicUsize};
use std::thread;

use rand::RngCore;
use serde::{Deserialize};
use web_view::*;

use alfis::{Blockchain, Bytes, Context, Keystore, Settings, Transaction, Block};
use alfis::event::Event;
use alfis::miner::Miner;
use alfis::p2p::Network;

extern crate serde;
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
        None => {
            println!("Generated temporary keystore. Please, generate full-privileged keys.");
            Keystore::new()
        }
        Some(keystore) => { keystore }
    };
    let blockchain: Blockchain = Blockchain::new(&settings);
    match blockchain.get_block(0) {
        None => { println!("No blocks found in DB"); }
        Some(block) => { println!("Loaded DB with origin {:?}", &block.hash); }
    }
    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(Context::new(settings, keystore, blockchain)));

    let mut miner_obj = Miner::new(context.clone());
    miner_obj.start_mining_thread();
    let miner: Arc<Mutex<Miner>> = Arc::new(Mutex::new(miner_obj));

    let mut network = Network::new(context.clone());
    network.start().expect("Error starting network component");

    create_genesis_if_needed(&context, &miner);
    run_interface(context.clone(), miner.clone());
}

fn create_genesis_if_needed(context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>) {
    // If there is no origin in settings and no blockchain in DB, generate genesis block
    let context = context.lock().unwrap();
    // TODO compare first block's hash to origin
    let last_block = context.get_blockchain().last_block();
    let origin = context.settings.origin.clone();
    if origin.eq("") && last_block.is_none() {
        // If blockchain is empty, we are going to mine a Genesis block
        create_genesis(miner.clone(), GENESIS_ZONE, &context.get_keystore(), GENESIS_ZONE_DIFFICULTY);
    }
}

fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>) {
    let file_content = include_str!("webview/index.html");
    let mut styles= inline_style(include_str!("webview/bulma.css"));
    styles.push_str(&inline_style(include_str!("webview/miner.css")));
    let scripts = inline_script(include_str!("webview/scripts.js"));

    let html = Content::Html(file_content.to_owned().replace("{styles}", &styles).replace("{scripts}", &scripts));
    web_view::builder()
        .title("ALFIS 0.1.0")
        .content(html)
        .size(1024, 720)
        .resizable(true)
        .debug(true)
        .user_data(())
        .invoke_handler(|web_view, arg| {
            use Cmd::*;
            println!("Command {}", arg);
            match serde_json::from_str(arg).unwrap() {
                Loaded => {
                    web_view.eval("showMiningIndicator(false);").expect("Error evaluating!");
                    let handle = web_view.handle();
                    let context_copy = context.clone();
                    let mut c = context.lock().unwrap();
                    c.bus.register(move |_uuid, e| {
                        println!("Got event from bus {:?}", &e);
                        let eval = match e {
                            Event::KeyCreated { path, public } => { format!("keystoreChanged('{}', '{}');", &path, &public) }
                            Event::KeyLoaded { path, public } => { format!("keystoreChanged('{}', '{}');", &path, &public) }
                            Event::KeySaved { path, public } => { format!("keystoreChanged('{}', '{}');", &path, &public) }
                            Event::MinerStarted => { format!("showMiningIndicator({});", true) }
                            Event::KeyGeneratorStarted => { format!("showMiningIndicator({});", true) }
                            Event::MinerStopped => { format!("showMiningIndicator({});", false) }
                            Event::KeyGeneratorStopped => { format!("showMiningIndicator({});", false) }
                            _ => { String::new() }
                        };

                        if !eval.is_empty() {
                            println!("Evaluating {}", &eval);
                            handle.dispatch(move |web_view| {
                                web_view.eval(&eval.replace("\\", "\\\\")).expect("Error evaluating!");
                                return WVResult::Ok(());
                            }).expect("Error dispatching!");
                        }
                        true
                    });
                    let eval = format!("keystoreChanged('{}', '{}');", c.keystore.get_path(), &c.keystore.get_public().to_string());
                    println!("Evaluating {}", &eval);
                    web_view.eval(&eval.replace("\\", "\\\\")).expect("Error evaluating!");
                }
                LoadKey {} => {
                    let result = tfd::open_file_dialog("Open keys file", "", Some((&["*.key"], "*.key")));
                    match result {
                        None => {}
                        Some(file_name) => {
                            match Keystore::from_file(&file_name, "") {
                                None => {
                                    println!("Error loading keystore '{}'!", &file_name);
                                },
                                Some(keystore) => {
                                    println!("Loaded keystore with key: {:?}", &keystore.get_public());
                                    let mut c = context.lock().unwrap();
                                    c.bus.post(Event::KeyLoaded {path: keystore.get_path().to_owned(), public: keystore.get_public().to_string()});
                                    c.set_keystore(keystore);
                                }
                            }
                        }
                    }
                },
                CreateKey {} => {
                    create_key(context.clone());
                }
                SaveKey {} => {
                    let result = tfd::save_file_dialog_with_filter("Save keys file", "", &["*.key"], "Key files (*.key)");
                    match result {
                        None => {}
                        Some(new_path) => {
                            let mut c = context.lock().unwrap();
                            let path = new_path.clone();
                            let public = c.keystore.get_public().to_string();
                            c.keystore.save(&new_path, "");
                            println!("Key file saved to {}", &path);
                            c.bus.post(Event::KeySaved {path, public });
                        }
                    }
                }
                CheckDomain { name} => {
                    let c = context.lock().unwrap();
                    let available = c.get_blockchain().is_domain_available(&name, &c.get_keystore());
                    web_view.eval(&format!("domainAvailable({})", available)).expect("Error evaluating!");
                }
                CreateDomain { name, records, tags } => {
                    let keystore = {
                        let guard = context.lock().unwrap();
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
                StopMining => {
                    context.lock().unwrap().bus.post(Event::ActionStopMining);
                }
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
    let transaction = { create_transaction(keystore, name, "domain".into(), data.into()) };
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

fn create_key(context: Arc<Mutex<Context>>) {
    let mining = Arc::new(AtomicBool::new(true));
    let miners_count = Arc::new(AtomicUsize::new(0));
    { context.lock().unwrap().bus.post(Event::KeyGeneratorStarted); }
    for _ in 0..num_cpus::get() {
        let context = context.clone();
        let mining = mining.clone();
        let miners_count = miners_count.clone();
        thread::spawn(move || {
            miners_count.fetch_add(1, Ordering::Relaxed);
            match generate_key(KEYSTORE_DIFFICULTY, mining.clone()) {
                None => {
                    println!("Keystore mining finished");
                }
                Some(keystore) => {
                    println!("Key mined successfully: {:?}", &keystore.get_public());
                    let mut c = context.lock().unwrap();
                    mining.store(false,Ordering::Relaxed);
                    c.bus.post(Event::KeyCreated {path: keystore.get_path().to_owned(), public: keystore.get_public().to_string()});
                    c.set_keystore(keystore);
                }
            }
            let miners = miners_count.fetch_sub(1, Ordering::Relaxed) - 1;
            if miners == 0 {
                context.lock().unwrap().bus.post(Event::KeyGeneratorStopped);
            }
        });
    }
    context.lock().unwrap().bus.register(move |_uuid, e| {
        if e == Event::ActionStopMining {
            mining.store(false, Ordering::Relaxed);
        }
        false
    });
}

fn generate_key(difficulty: usize, mining: Arc<AtomicBool>) -> Option<Keystore> {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
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
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
pub enum Cmd {
    Loaded,
    LoadKey{},
    CreateKey{},
    SaveKey{},
    CheckDomain{name: String},
    CreateDomain{name: String, records: String, tags: String},
    ChangeDomain{name: String, records: String, tags: String},
    RenewDomain{name: String, days: u16},
    TransferDomain{name: String, owner: String},
    StopMining,
}

fn inline_style(s: &str) -> String {
    format!(r#"<style type="text/css">{}</style>"#, s)
}

fn inline_script(s: &str) -> String {
    format!(r#"<script type="text/javascript">{}</script>"#, s)
}
