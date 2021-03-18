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

use alfis::{Block, Bytes, Context, Keystore, Transaction, get_domain_zone};
use alfis::miner::Miner;
use alfis::{keys, check_domain};
use alfis::event::Event;
use alfis::dns::protocol::DnsRecord;
use alfis::blockchain::{ZONE_MAX_LENGTH, ZONE_DIFFICULTY};
use Cmd::*;
use alfis::blockchain::transaction::{DomainData, ZoneData};
use self::web_view::WebView;
use alfis::blockchain::enums::MineResult;

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
                Loaded => { action_loaded(&context, web_view); }
                LoadKey => { action_load_key(&context, web_view); }
                CreateKey => { keys::create_key(Arc::clone(&context)); }
                SaveKey => { action_save_key(&context); }
                CheckRecord { data } => { action_check_record(web_view, data); }
                CheckDomain { name } => { action_check_domain(&context, web_view, name); }
                MineDomain { name, records, .. } => {
                    action_create_domain(Arc::clone(&context), Arc::clone(&miner), web_view, name, &records);
                }
                TransferDomain { .. } => {}
                CheckZone { name } => { action_check_zone(&context, web_view, name); }
                MineZone { name, data } => { action_create_zone(&context, Arc::clone(&miner), web_view, name, data); }
                StopMining => { context.lock().unwrap().bus.post(Event::ActionStopMining); }
            }
            Ok(())
        })
        .build()
        .expect("Error building GUI");

    run_interface_loop(&mut interface);
    interface.exit();
}

/// Indefinitely loops through WebView steps
fn run_interface_loop(interface: &mut WebView<()>) {
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
}

fn action_check_zone(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>, name: String) {
    let name = name.to_lowercase();
    if name.len() > ZONE_MAX_LENGTH || !check_domain(&name, false) || context.lock().unwrap().x_zones.has_zone(&name) {
        web_view.eval("zoneAvailable(false)").expect("Error evaluating!");
    } else {
        let c = context.lock().unwrap();
        let available = c.get_chain().is_domain_available(&name, &c.get_keystore());
        web_view.eval(&format!("zoneAvailable({})", available)).expect("Error evaluating!");
    }
}

fn action_check_record(web_view: &mut WebView<()>, data: String) {
    match serde_json::from_str::<DnsRecord>(&data) {
        Ok(_) => { web_view.eval("recordOkay(true)").expect("Error evaluating!"); }
        Err(e) => { web_view.eval("recordOkay(false)").expect("Error evaluating!"); dbg!(e); }
    }
}

fn action_check_domain(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>, name: String) {
    let name = name.to_lowercase();
    let c = context.lock().unwrap();
    let available = c.get_chain().is_domain_available(&name, &c.get_keystore());
    web_view.eval(&format!("domainAvailable({})", available)).expect("Error evaluating!");
}

fn action_save_key(context: &Arc<Mutex<Context>>) {
    let result = tfd::save_file_dialog_with_filter("Save keys file", "", &["*.key"], "Key files (*.key)");
    match result {
        None => {}
        Some(new_path) => {
            let mut context = context.lock().unwrap();
            let path = new_path.clone();
            let public = context.keystore.get_public().to_string();
            let hash = context.keystore.get_hash().to_string();
            context.keystore.save(&new_path, "");
            info!("Key file saved to {}", &path);
            context.bus.post(Event::KeySaved { path, public, hash });
        }
    }
}

fn action_load_key(context: &Arc<Mutex<Context>>, _web_view: &mut WebView<()>) {
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

fn action_loaded(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>) {
    web_view.eval("showMiningIndicator(false, false);").expect("Error evaluating!");
    let handle = web_view.handle();
    let mut status = Status::new();
    let mut c = context.lock().unwrap();
    c.bus.register(move |_uuid, e| {
        debug!("Got event from bus {:?}", &e);
        let eval = match e {
            Event::KeyCreated { path, public, hash } |
            Event::KeyLoaded { path, public, hash } |
            Event::KeySaved { path, public, hash } => {
                format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash)
            }
            Event::MinerStarted | Event::KeyGeneratorStarted => {
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

fn action_create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, web_view: &mut WebView<()>, name: String, records: &String) {
    debug!("Creating domain with records: {}", records);
    let c = Arc::clone(&context);
    let context = context.lock().unwrap();
    let pub_key = context.keystore.get_public();
    match context.chain.can_mine_domain(&name, &records, &pub_key) {
        MineResult::Fine => {
            let zone = get_domain_zone(&name);
            let difficulty = context.chain.get_zone_difficulty(&zone);
            if let Ok(records) = serde_json::from_str::<Vec<DnsRecord>>(&records) {
                let data = DomainData::new(zone.clone(), records);
                let data = serde_json::to_string(&data).unwrap();
                create_domain(c, miner, &name, &data, difficulty, &context.keystore);
                let _ = web_view.eval("domainMiningStarted()");
            }
        }
        MineResult::WrongName => { show_warning(web_view, "You can't mine this domain!"); }
        MineResult::WrongData => { show_warning(web_view, "You have an error in records!"); }
        MineResult::WrongKey => { show_warning(web_view, "You can't mine with current key!"); }
        MineResult::WrongZone => { show_warning(web_view, "You can't mine domain in this zone!"); }
        MineResult::NotOwned => { show_warning(web_view, "This domain is already taken, and it is not yours!"); }
        MineResult::Cooldown { time } => {
            show_warning(web_view, &format!("You have cooldown, just {} more minutes!", time / 60));
        }
    }
}

fn action_create_zone(context: &Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, web_view: &mut WebView<()>, name: String, data: String) {
    let name = name.to_lowercase();
    if name.len() > ZONE_MAX_LENGTH || !check_domain(&name, false) || context.lock().unwrap().x_zones.has_zone(&name) {
        warn!("This zone is unavailable for mining!");
        show_warning(web_view, "This zone is unavailable for mining!");
        return;
    }
    let data = data.to_lowercase();
    if serde_json::from_str::<ZoneData>(&data).is_err() {
        warn!("Something wrong with zone data!");
        show_warning(web_view, "Something wrong with zone data!");
        return;
    }
    let (keystore, transaction) = {
        let context = context.lock().unwrap();
        (context.get_keystore(), context.chain.get_domain_transaction(&name))
    };
    match transaction {
        None => {
            create_domain(context.clone(), miner.clone(), &name, &data, ZONE_DIFFICULTY, &keystore);
        }
        Some(transaction) => {
            if transaction.pub_key == keystore.get_public() {
                create_domain(context.clone(), miner.clone(), &name, &data, ZONE_DIFFICULTY, &keystore);
            } else {
                warn!("Tried to mine not owned domain!");
                show_warning(web_view, "You cannot change domain that you don't own!");
            }
        }
    }
}

fn show_warning(web_view: &mut WebView<()>, text: &str) {
    match web_view.eval(&format!("showWarning('{}');", text)) {
        Ok(_) => {}
        Err(_) => { warn!("Error showing warning!"); }
    }
}

fn create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, name: &str, data: &str, difficulty: u32, keystore: &Keystore) {
    let name = name.to_owned();
    info!("Generating domain or zone {}", &name);
    if context.lock().unwrap().x_zones.has_zone(&name) {
        error!("Unable to mine IANA/OpenNIC/etc zone {}!", &name);
        return;
    }
    //let tags_vector: Vec<String> = tags.into().trim().split(",").map(|s| s.trim()).map(String::from).collect();
    let transaction = Transaction::from_str(name, "dns".to_owned(), data.to_owned(), keystore.get_public().clone());
    let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default(), difficulty);
    miner.lock().unwrap().add_block(block);
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
pub enum Cmd {
    Loaded,
    LoadKey,
    CreateKey,
    SaveKey,
    CheckZone { name: String },
    MineZone { name: String, data: String },
    CheckRecord { data: String },
    CheckDomain { name: String },
    MineDomain { name: String, records: String, tags: String },
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
