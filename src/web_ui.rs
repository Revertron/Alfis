extern crate web_view;
extern crate tinyfiledialogs as tfd;
extern crate serde;
extern crate serde_json;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use web_view::Content;
#[allow(unused_imports)]
use log::{debug, error, info, LevelFilter, trace, warn};
use serde::Deserialize;

use alfis::{Block, Bytes, Context, Keystore, Transaction};
use alfis::miner::Miner;
use alfis::{keys, check_domain};
use alfis::event::Event;
use alfis::dns::protocol::DnsRecord;
use alfis::blockchain::ZONE_MAX_LENGTH;
use Cmd::*;

pub fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>) {
    let file_content = include_str!("webview/index.html");
    let mut styles = inline_style(include_str!("webview/bulma.css"));
    styles.push_str(&inline_style(include_str!("webview/busy_indicator.css")));
    let scripts = inline_script(include_str!("webview/scripts.js"));

    let html = Content::Html(file_content.to_owned().replace("{styles}", &styles).replace("{scripts}", &scripts));
    let title = format!("ALFIS {}", env!("CARGO_PKG_VERSION"));
    let mut interface = web_view::builder()
        .title(&title)
        .content(html)
        .size(1023, 720)
        .min_size(895, 350)
        .resizable(true)
        .debug(false)
        .user_data(())
        .invoke_handler(|web_view, arg| {
            debug!("Command {}", arg);
            match serde_json::from_str(arg).unwrap() {
                Loaded => {
                    web_view.eval("showMiningIndicator(false, false);").expect("Error evaluating!");
                    let handle = web_view.handle();
                    let mut status = Status::new();
                    let mut c = context.lock().unwrap();
                    c.bus.register(move |_uuid, e| {
                        debug!("Got event from bus {:?}", &e);
                        let eval = match e {
                            Event::KeyCreated { path, public, hash } => { format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash) }
                            Event::KeyLoaded { path, public, hash } => { format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash) }
                            Event::KeySaved { path, public, hash } => { format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash) }
                            Event::MinerStarted => {
                                status.mining = true;
                                String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                            }
                            Event::KeyGeneratorStarted => {
                                status.mining = true;
                                String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                            }
                            Event::MinerStopped | Event::KeyGeneratorStopped => {
                                status.mining = false;
                                if status.syncing {
                                    String::from("setLeftStatusBarText('Syncing...'); showMiningIndicator(true, true);")
                                } else {
                                    String::from("setLeftStatusBarText('Idle'); showMiningIndicator(false, false);")
                                }
                            }
                            Event::Syncing { have, height } => {
                                status.syncing = true;
                                status.synced_blocks = have;
                                status.sync_height = height;
                                if status.mining {
                                    String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                                } else {
                                    format!("setLeftStatusBarText('Synchronizing {}/{}'); showMiningIndicator(true, true);", have, height)
                                }
                            }
                            Event::SyncFinished => {
                                status.syncing = false;
                                if status.mining {
                                    String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                                } else {
                                    format!("setLeftStatusBarText('Idle'); showMiningIndicator(false, false);")
                                }
                            }
                            Event::NetworkStatus { nodes, blocks } => {
                                if status.mining || status.syncing || nodes < 3 {
                                    format!("setRightStatusBarText('Nodes: {}, Blocks: {}')", nodes, blocks)
                                } else {
                                    format!("setLeftStatusBarText('Idle'); setRightStatusBarText('Nodes: {}, Blocks: {}')", nodes, blocks)
                                }
                            }
                            _ => { String::new() }
                        };

                        if !eval.is_empty() {
                            debug!("Evaluating {}", &eval);
                            handle.dispatch(move |web_view| {
                                web_view.eval(&eval.replace("\\", "\\\\"))
                            }).expect("Error dispatching!");
                        }
                        true
                    });
                    let eval = format!("keystoreChanged('{}', '{}', '{}');", c.keystore.get_path(), &c.keystore.get_public().to_string(), &c.keystore.get_hash().to_string());
                    debug!("Evaluating {}", &eval);
                    web_view.eval(&eval.replace("\\", "\\\\")).expect("Error evaluating!");
                }
                LoadKey {} => {
                    let result = tfd::open_file_dialog("Open keys file", "", Some((&["*.key"], "*.key")));
                    match result {
                        None => {}
                        Some(file_name) => {
                            match Keystore::from_file(&file_name, "") {
                                None => {
                                    error!("Error loading keystore '{}'!", &file_name);
                                }
                                Some(keystore) => {
                                    info!("Loaded keystore with key: {:?}", &keystore.get_public());
                                    let mut c = context.lock().unwrap();
                                    let path = keystore.get_path().to_owned();
                                    let public = keystore.get_public().to_string();
                                    let hash = keystore.get_hash().to_string();
                                    c.bus.post(Event::KeyLoaded { path, public, hash });
                                    c.set_keystore(keystore);
                                }
                            }
                        }
                    }
                }
                CreateKey {} => {
                    keys::create_key(context.clone());
                }
                SaveKey {} => {
                    let result = tfd::save_file_dialog_with_filter("Save keys file", "", &["*.key"], "Key files (*.key)");
                    match result {
                        None => {}
                        Some(new_path) => {
                            let mut c = context.lock().unwrap();
                            let path = new_path.clone();
                            let public = c.keystore.get_public().to_string();
                            let hash = c.keystore.get_hash().to_string();
                            c.keystore.save(&new_path, "");
                            info!("Key file saved to {}", &path);
                            c.bus.post(Event::KeySaved { path, public, hash });
                        }
                    }
                }
                CheckDomain { name } => {
                    let name = name.to_lowercase();
                    let c = context.lock().unwrap();
                    let available = c.get_chain().is_domain_available(&name, &c.get_keystore());
                    web_view.eval(&format!("domainAvailable({})", available)).expect("Error evaluating!");
                }
                CreateDomain { name, records, .. } => {
                    debug!("Got records: {}", records);
                    let name = name.to_lowercase();
                    if !check_domain(&name, true) {
                        return Ok(());
                    }
                    if serde_json::from_str::<Vec<DnsRecord>>(&records).is_ok() {
                        let (keystore, transaction) = {
                            let context = context.lock().unwrap();
                            (context.get_keystore(), context.chain.get_domain_transaction(&name))
                        };
                        match transaction {
                            None => {
                                create_domain(context.clone(), miner.clone(), &name, &records, &keystore);
                            }
                            Some(transaction) => {
                                if transaction.pub_key == keystore.get_public() {
                                    create_domain(context.clone(), miner.clone(), &name, &records, &keystore);
                                } else {
                                    warn!("Tried to mine not owned domain!");
                                    let _ = web_view.eval(&format!("showWarning('{}');", "You cannot change domain that you don't own!"));
                                }
                            }
                        }
                    } else {
                        warn!("Error in DNS records for domain!");
                        let _ = web_view.eval(&format!("showWarning('{}');", "Something wrong with your records! Please, correct the error and try again."));
                    }
                }
                ChangeDomain { .. } => {}
                RenewDomain { .. } => {}
                TransferDomain { .. } => {}
                CheckZone { name } => {
                    let name = name.to_lowercase();
                    if name.len() > ZONE_MAX_LENGTH || !check_domain(&name, false) || context.lock().unwrap().x_zones.has_zone(&name) {
                        web_view.eval("zoneAvailable(false)").expect("Error evaluating!");
                    } else {
                        let c = context.lock().unwrap();
                        let available = c.get_chain().is_domain_available(&name, &c.get_keystore());
                        web_view.eval(&format!("zoneAvailable({})", available)).expect("Error evaluating!");
                    }
                }
                CreateZone { name, data } => {
                    let name = name.to_lowercase();
                    if name.len() > ZONE_MAX_LENGTH || !check_domain(&name, false) || context.lock().unwrap().x_zones.has_zone(&name) {
                        warn!("This zone is unavailable for mining!");
                        let _ = web_view.eval(&format!("showWarning('{}');", "This zone is unavailable for mining!"));
                        return Ok(());
                    }
                    let data = data.to_lowercase();
                    let (keystore, transaction) = {
                        let context = context.lock().unwrap();
                        (context.get_keystore(), context.chain.get_domain_transaction(&name))
                    };
                    match transaction {
                        None => {
                            create_domain(context.clone(), miner.clone(), &name, &data, &keystore);
                        }
                        Some(transaction) => {
                            if transaction.pub_key == keystore.get_public() {
                                create_domain(context.clone(), miner.clone(), &name, &data, &keystore);
                            } else {
                                warn!("Tried to mine not owned domain!");
                                let _ = web_view.eval(&format!("showWarning('{}');", "You cannot change domain that you don't own!"));
                            }
                        }
                    }
                }
                StopMining => {
                    context.lock().unwrap().bus.post(Event::ActionStopMining);
                }
            }
            //dbg!(&signature);
            Ok(())
        })
        .build()
        .expect("Error building GUI");

    // We use this ugly loop to lower CPU usage a lot.
    // If we use .run() or only .step() in a loop without sleeps it will try
    // to support 60FPS and uses more CPU than it should.
    let pause = Duration::from_millis(25);
    let mut start = Instant::now();
    loop {
        match interface.step() {
            None => {
                info!("Interface closed, exiting");
                break;
            }
            Some(result) => {
                match result {
                    Ok(_) => {}
                    Err(_) => {
                        error!("Something wrong with webview, exiting");
                        break;
                    }
                }
            }
        }
        if start.elapsed().as_millis() > 1 {
            thread::sleep(pause);
            start = Instant::now();
        }
    }
    interface.exit();
}

fn create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, name: &str, data: &str, keystore: &Keystore) {
    let name = name.to_owned();
    info!("Generating domain or zone {}", &name);
    if context.lock().unwrap().x_zones.has_zone(&name) {
        error!("Unable to mine IANA/OpenNIC/etc zone {}!", &name);
        return;
    }
    //let tags_vector: Vec<String> = tags.into().trim().split(",").map(|s| s.trim()).map(String::from).collect();
    let transaction = Transaction::from_str(name, "dns".to_owned(), data.to_owned(), keystore.get_public().clone());
    let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default());
    miner.lock().unwrap().add_block(block);
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
pub enum Cmd {
    Loaded,
    LoadKey {},
    CreateKey {},
    SaveKey {},
    CheckZone { name: String },
    CreateZone { name: String, data: String },
    CheckDomain { name: String },
    CreateDomain { name: String, records: String, tags: String },
    ChangeDomain { name: String, records: String, tags: String },
    RenewDomain { name: String, days: u16 },
    TransferDomain { name: String, owner: String },
    StopMining,
}

struct Status {
    pub mining: bool,
    pub syncing: bool,
    pub synced_blocks: u64,
    pub sync_height: u64,
    pub nodes_connected: usize,
    pub chain_height: u64
}

impl Status {
    fn new() -> Self {
        Status { mining: false, syncing: false, synced_blocks: 0, sync_height: 0, nodes_connected: 0, chain_height: 0 }
    }
}

fn inline_style(s: &str) -> String {
    format!(r#"<style type="text/css">{}</style>"#, s)
}

fn inline_script(s: &str) -> String {
    format!(r#"<script type="text/javascript">{}</script>"#, s)
}
