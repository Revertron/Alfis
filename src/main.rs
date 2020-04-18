#![windows_subsystem = "windows"]
extern crate web_view;
use alfis::{Blockchain, Block, Action, Transaction, Keystore, Key, Settings, Context};
use web_view::*;
use std::thread;
use std::sync::{Arc, Mutex};

extern crate serde;
use serde::{Serialize, Deserialize};
use alfis::miner::Miner;
use std::collections::HashMap;

extern crate serde_json;

fn main() {
    println!("ALFIS 0.1.0");
    let settings = Settings::new(42, 0,"");
    let keystore: Keystore = Keystore::from_file("default.key", "").unwrap();
    let blockchain: Blockchain = Blockchain::new(settings.chain_id, settings.version);
    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(Context::new(settings, keystore, blockchain)));

    let miner: Arc<Mutex<Miner>> = Arc::new(Mutex::new(Miner::new(context.clone())));

    // TODO check settings and if there is no mention of bootstrap nodes, generate genesis block
    /*let chain_for_genesis = blockchain.clone();
    thread::spawn(move || {
        let mut block = Blockchain::genesis(42, 0);
        // TODO remake genesis to use Miner
        block.mine();
        chain_for_genesis.lock().unwrap().add_block(block);
        println!("Blockchain with genesis block has been created");
    });*/
    run_interface(context.clone(), miner.clone());
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
                    let mut c = context.lock().unwrap();
                    c.set_keystore(Keystore::new());
                }
                CreateDomain { name, records, tags } => {
                    let mut c = context.lock().unwrap();
                    create_domain(miner.clone(), name, records, tags, c.get_keystore());
                }
                ChangeDomain { name, records, tags } => {

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

fn create_domain(miner: Arc<Mutex<Miner>>, name: String, records: String, tags: String, keystore: Keystore) {
    let rec_vector: Vec<String> = records.trim().split("\n").map(|s| s.trim()).map(String::from).collect();
    let tags_vector: Vec<String> = tags.trim().split(",").map(|s| s.trim()).map(String::from).collect();
    let mut transaction = { transaction_new_domain(keystore, name, rec_vector, tags_vector, 365) };
    let mut miner_guard = miner.lock().unwrap();
    miner_guard.add_transaction(transaction);
    miner_guard.mine();
}

fn transaction_claim_name<S: Into<String>>(keystore: Keystore, name: S, salt: S) -> Transaction {
    // Creating transaction
    let action = Action::claim_name(name.into(), salt.into(), &keystore);
    let mut transaction = Transaction::new(action, keystore.get_public().clone());
    // Signing it with private key from Signature
    let sign_hash = keystore.sign(&transaction.get_bytes());
    transaction.set_signature(Key::from_bytes(&sign_hash));
    transaction
}

fn transaction_new_domain<S: Into<String>>(keystore: Keystore, name: S, records: Vec<String>, tags: Vec<String>, days: u16) -> Transaction {
    // Creating transaction
    let action = Action::new_domain(name.into(), &keystore, records, tags, days);
    let mut transaction = Transaction::new(action, keystore.get_public().clone());
    // Signing it with private key from Signature
    let sign_hash = keystore.sign(&transaction.get_bytes());
    transaction.set_signature(Key::from_bytes(&sign_hash));
    transaction
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
