extern crate open;
extern crate serde;
extern crate serde_json;
extern crate tinyfiledialogs as tfd;
extern crate web_view;

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
#[allow(unused_imports)]
use log::{debug, error, info, LevelFilter, trace, warn};
use serde::Deserialize;
use web_view::Content;

use alfis::{Block, Bytes, Context, get_domain_zone, Keystore, Transaction, ZONE_MIN_DIFFICULTY, is_yggdrasil_record};
use alfis::{check_domain, keys};
use alfis::blockchain::transaction::{DomainData, ZoneData};
use alfis::blockchain::types::MineResult;
use alfis::commons::{ZONE_DIFFICULTY, ZONE_MAX_LENGTH, CLASS_DOMAIN, CLASS_ZONE};
use alfis::dns::protocol::DnsRecord;
use alfis::event::Event;
use alfis::miner::Miner;
use Cmd::*;

use self::web_view::{Handle, WebView};
use alfis::blockchain::hash_utils::hash_identity;

pub fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>) {
    let file_content = include_str!("webview/index.html");
    let mut styles = inline_style(include_str!("webview/bulma.css"));
    styles.push_str(&inline_style(include_str!("webview/styles.css")));
    styles.push_str(&inline_style(include_str!("webview/busy_indicator.css")));
    let scripts = inline_script(include_str!("webview/scripts.js"));

    let html = Content::Html(file_content.to_owned().replace("{styles}", &styles).replace("{scripts}", &scripts));
    let title = format!("ALFIS {}", env!("CARGO_PKG_VERSION"));
    let mut interface = web_view::builder()
        .title(&title)
        .content(html)
        .size(1023, 720)
        .min_size(773, 350)
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
                MineDomain { name, data } => {
                    action_create_domain(Arc::clone(&context), Arc::clone(&miner), web_view, name, data);
                }
                TransferDomain { .. } => {}
                CheckZone { name } => { action_check_zone(&context, web_view, name); }
                MineZone { name, data } => {
                    action_create_zone(Arc::clone(&context), Arc::clone(&miner), web_view, name, data);
                }
                StopMining => { context.lock().unwrap().bus.post(Event::ActionStopMining); }
                Open { link } => {
                    if open::that(&link).is_err() {
                        show_warning(web_view, "Something wrong, I can't open the link 😢");
                    }
                }
            }
            Ok(())
        })
        .build()
        .expect("Error building GUI");

    let mut context = Arc::clone(&context);
    run_interface_loop(&mut context, &mut interface);
    interface.exit();
}

/// Indefinitely loops through WebView steps
fn run_interface_loop(context: &mut Arc<Mutex<Context>>, interface: &mut WebView<()>) {
    // We use this ugly loop to lower CPU usage a lot.
    // If we use .run() or only .step() in a loop without sleeps it will try
    // to support 60FPS and uses more CPU than it should.
    let pause = Duration::from_millis(25);
    let mut start = Instant::now();
    loop {
        match interface.step() {
            None => {
                info!("Interface closed, exiting");
                context.lock().unwrap().bus.post(Event::ActionQuit);
                thread::sleep(Duration::from_millis(100));
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
        if let Some(keystore) = c.get_keystore() {
            let available = c.get_chain().is_domain_available(&name, &keystore);
            web_view.eval(&format!("zoneAvailable({})", available)).expect("Error evaluating!");
        }
    }
}

fn action_check_record(web_view: &mut WebView<()>, data: String) {
    match serde_json::from_str::<DnsRecord>(&data) {
        Ok(_) => { web_view.eval("recordOkay(true)").expect("Error evaluating!"); }
        Err(e) => { web_view.eval("recordOkay(false)").expect("Error evaluating!"); dbg!(e); }
    }
}

fn action_check_domain(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>, name: String) {
    let c = context.lock().unwrap();
    if let Some(keystore) = c.get_keystore() {
        let name = name.to_lowercase();
        let available = c.get_chain().is_domain_available(&name, &keystore);
        web_view.eval(&format!("domainAvailable({})", available)).expect("Error evaluating!");
    }
}

fn action_save_key(context: &Arc<Mutex<Context>>) {
    if context.lock().unwrap().get_keystore().is_none() {
        return;
    }
    let result = tfd::save_file_dialog_with_filter("Save keys file", "", &["*.key"], "Key files (*.key)");
    match result {
        None => {}
        Some(new_path) => {
            let mut context = context.lock().unwrap();
            let path = new_path.clone();
            if let Some(mut keystore) = context.get_keystore() {
                let public = keystore.get_public().to_string();
                let hash = keystore.get_hash().to_string();
                keystore.save(&new_path, "");
                info!("Key file saved to {}", &path);
                context.bus.post(Event::KeySaved { path, public, hash });
            }
        }
    }
}

fn action_load_key(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>) {
    let result = tfd::open_file_dialog("Open keys file", "", Some((&["*.key"], "*.key")));
    match result {
        None => {}
        Some(file_name) => {
            match Keystore::from_file(&file_name, "") {
                None => {
                    error!("Error loading keystore '{}'!", &file_name);
                    show_warning(web_view, "Error loading key!<br>Key cannot be loaded or its difficulty is not enough.");
                    event_fail(web_view, &format!("Error loading key from \\'{}\\'!", &file_name));
                }
                Some(keystore) => {
                    info!("Loaded keystore with key: {:?}", &keystore.get_public());
                    let mut c = context.lock().unwrap();
                    let path = keystore.get_path().to_owned();
                    let public = keystore.get_public().to_string();
                    let hash = keystore.get_hash().to_string();
                    c.bus.post(Event::KeyLoaded { path, public, hash });
                    c.set_keystore(Some(keystore));
                }
            }
        }
    }
}

fn action_loaded(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>) {
    web_view.eval("showMiningIndicator(false, false);").expect("Error evaluating!");
    let handle: Handle<()> = web_view.handle();
    let threads = context.lock().unwrap().settings.mining.threads;
    let threads = match threads {
        0 => num_cpus::get(),
        _ => threads
    };
    let status = Arc::new(Mutex::new(Status::new(threads)));
    let context_copy = Arc::clone(&context);
    let mut c = context.lock().unwrap();

    c.bus.register(move |_uuid, e| {
        //debug!("Got event from bus {:?}", &e);
        let status = Arc::clone(&status);
        let handle = handle.clone();
        let context_copy = Arc::clone(&context_copy);
        let _ = thread::Builder::new().name(String::from("webui")).spawn(move || {
            let mut status = status.lock().unwrap();
            let mut context = context_copy.lock().unwrap();
            let eval = match e {
                Event::KeyCreated { path, public, hash } => {
                    load_domains(&mut context, &handle);
                    event_handle_luck(&handle, "Key successfully created! Don\\'t forget to save it!");
                    let mut s = format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash);
                    s.push_str(" showSuccess('New key mined successfully! Save it to a safe place!')");
                    s
                }
                Event::KeyLoaded { path, public, hash } |
                Event::KeySaved { path, public, hash } => {
                    load_domains(&mut context, &handle);
                    format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash)
                }
                Event::MinerStarted | Event::KeyGeneratorStarted => {
                    status.mining = true;
                    status.max_diff = 0;
                    event_handle_info(&handle, "Mining started");
                    String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                }
                Event::MinerStopped { success, full} => {
                    status.mining = false;
                    status.max_diff = 0;
                    let mut s = if status.syncing {
                        String::from("setLeftStatusBarText('Syncing...'); showMiningIndicator(true, true);")
                    } else {
                        String::from("setLeftStatusBarText('Idle'); showMiningIndicator(false, false);")
                    };
                    if full {
                        match success {
                            true => {
                                event_handle_luck(&handle, "Mining is successful!");
                                s.push_str(" showSuccess('Block successfully mined!')");
                            }
                            false => {
                                event_handle_info(&handle, "Mining finished without result.");
                                s.push_str(" showSuccess('Mining unsuccessful, sorry.')");
                            }
                        }
                    }
                    s
                }
                Event::MinerStats { thread, speed, max_diff, target_diff } => {
                    if status.max_diff < max_diff {
                        status.max_diff = max_diff;
                    }
                    status.set_thread_speed(thread, speed);
                    if thread == threads - 1 {
                        format!("setLeftStatusBarText('Mining speed {} H/s, max found difficulty {}/{}.'); showMiningIndicator(true, false);", status.get_speed(), status.max_diff, target_diff)
                    } else {
                        String::new()
                    }
                }
                Event::KeyGeneratorStopped => {
                    status.mining = false;
                    if status.syncing {
                        String::from("setLeftStatusBarText('Syncing...'); showMiningIndicator(true, true);")
                    } else {
                        String::from("setLeftStatusBarText('Idle'); showMiningIndicator(false, false);")
                    }
                }
                Event::Syncing { have, height } => {
                    event_handle_info(&handle, "Syncing started...");
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
                    event_handle_info(&handle, "Syncing finished.");
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
                Event::BlockchainChanged {index} => {
                    debug!("Current blockchain height is {}", index);
                    event_handle_info(&handle, &format!("Blockchain changed, current block count is {} now.", index));
                    if let Ok(zones) = serde_json::to_string(&context.chain.get_zones()) {
                        let _ = handle.dispatch(move |web_view|{
                            web_view.eval(&format!("zonesChanged('{}');", &zones))
                        });
                    }
                    String::new() // Nothing
                }
                _ => { String::new() }
            };

            if !eval.is_empty() {
                handle.dispatch(move |web_view| {
                    web_view.eval(&eval.replace("\\", "\\\\"))
                }).expect("Error dispatching!");
            }
        });
        true
    });

    if let Some(keystore) = c.get_keystore() {
        let path = keystore.get_path().to_owned();
        let public = keystore.get_public().to_string();
        let hash = keystore.get_hash().to_string();
        c.bus.post(Event::KeyLoaded { path, public, hash });
    }
    let index = c.chain.get_height();
    c.bus.post(Event::BlockchainChanged { index });
    event_info(web_view, "Application loaded");
}

fn load_domains(context: &mut MutexGuard<Context>, handle: &Handle<()>) {
    let _ = handle.dispatch(move |web_view|{
        web_view.eval("clearMyDomains();")
    });
    let domains = context.chain.get_my_domains(&context.keystore);
    debug!("Domains: {:?}", &domains.values());
    for (_identity, (domain, timestamp, data)) in domains {
        let d = serde_json::to_string(&data).unwrap();
        let command = format!("addMyDomain('{}', {}, '{}');", &domain, timestamp, &d);
        let _ = handle.dispatch(move |web_view|{
            web_view.eval(&command)
        });
    }
    let _ = handle.dispatch(move |web_view|{
        web_view.eval("refreshMyDomains();")
    });
}

fn action_create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, web_view: &mut WebView<()>, name: String, data: String) {
    debug!("Creating domain with data: {}", &data);
    let c = Arc::clone(&context);
    let context = context.lock().unwrap();
    if context.get_keystore().is_none() {
        show_warning(web_view, "You don't have keys loaded!<br>Load or mine the keys and try again.");
        return;
    }
    if context.chain.is_waiting_signers() {
        show_warning(web_view, "Waiting for last full block to be signed. Try again later.");
        info!("Waiting for last full block to be signed. Try again later.");
        return;
    }
    let keystore = context.get_keystore().unwrap();
    let pub_key = keystore.get_public();
    let data = match serde_json::from_str::<DomainData>(&data) {
        Ok(data) => { data }
        Err(e) => {
            show_warning(web_view, "Something wrong with domain data. I cannot mine it.");
            warn!("Error parsing data: {}", e);
            return;
        }
    };
    // Check if yggdrasil only quality of zone is not violated
    let zones = context.chain.get_zones();
    for z in &zones {
        if z.name == data.zone {
            if z.yggdrasil {
                for record in &data.records {
                    if !is_yggdrasil_record(record) {
                        show_warning(web_view, &format!("Zone {} is Yggdrasil only, you cannot use IPs from clearnet!", &data.zone));
                        return;
                    }
                }
            }
        }
    }
    match context.chain.can_mine_domain(&name, &pub_key) {
        MineResult::Fine => {
            let zone = get_domain_zone(&name);
            let difficulty = context.chain.get_zone_difficulty(&zone);
            std::mem::drop(context);
            create_domain(c, miner, CLASS_DOMAIN, &name, data, difficulty, &keystore);
            let _ = web_view.eval("domainMiningStarted();");
            event_info(web_view, &format!("Mining of domain \\'{}\\' has started", &name));
        }
        MineResult::WrongName => { show_warning(web_view, "You can't mine this domain!"); }
        MineResult::WrongData => { show_warning(web_view, "You have an error in records!"); }
        MineResult::WrongKey => { show_warning(web_view, "You can't mine with current key!"); }
        MineResult::WrongZone => { show_warning(web_view, "You can't mine domain in this zone!"); }
        MineResult::NotOwned => { show_warning(web_view, "This domain is already taken, and it is not yours!"); }
        MineResult::Cooldown { time } => {
            event_info(web_view, &format!("You have cooldown, just {} more minutes!", time / 60));
            show_warning(web_view, &format!("You have cooldown, just {} more minutes!", time / 60));
        }
    }
}

fn action_create_zone(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, web_view: &mut WebView<()>, name: String, data: String) {
    if context.lock().unwrap().chain.is_waiting_signers() {
        show_warning(web_view, "Waiting for last full block to be signed. Try again later.");
        info!("Waiting for last full block to be signed. Try again later.");
        return;
    }

    let name = name.to_lowercase();
    if name.len() > ZONE_MAX_LENGTH || !check_domain(&name, false) || context.lock().unwrap().x_zones.has_zone(&name) {
        warn!("This zone is unavailable for mining!");
        show_warning(web_view, "This zone is unavailable for mining!");
        return;
    }
    let data = data.to_lowercase();
    let mut data = match serde_json::from_str::<ZoneData>(&data) {
        Ok(zone) => {
            if zone.difficulty < ZONE_MIN_DIFFICULTY {
                warn!("Zone difficulty cannot be lower than {}!", ZONE_MIN_DIFFICULTY);
                show_warning(web_view, &format!("Zone difficulty cannot be lower than {}!", ZONE_MIN_DIFFICULTY));
                return;
            }
            if name != zone.name {
                warn!("Something wrong with zone data!");
                show_warning(web_view, "Something wrong with zone data!");
                return;
            }
            zone
        }
        Err(_) => {
            warn!("Something wrong with zone data!");
            show_warning(web_view, "Something wrong with zone data!");
            return;
        }
    };
    let (keystore, transaction) = {
        let context = context.lock().unwrap();
        (context.get_keystore(), context.chain.get_domain_transaction(&name))
    };
    if let Some(keystore) = keystore {
        data.owners = if data.owners.is_empty() {
            vec!(keystore.get_public())
        } else {
            data.owners
        };
        let data = serde_json::to_string(&data).unwrap();
        match transaction {
            None => {
                create_zone(Arc::clone(&context), miner.clone(), CLASS_ZONE, &name, &data, ZONE_DIFFICULTY, &keystore);
                event_info(web_view, &format!("Mining of zone \\'{}\\' has started", &name));
            }
            Some(transaction) => {
                if transaction.pub_key == keystore.get_public() {
                    create_zone(Arc::clone(&context), miner.clone(), CLASS_ZONE, &name, &data, ZONE_DIFFICULTY, &keystore);
                    event_info(web_view, &format!("Mining of zone \\'{}\\' has started", &name));
                } else {
                    warn!("Tried to mine not owned domain!");
                    show_warning(web_view, "You cannot change domain that you don't own!");
                }
            }
        }
    } else {
        warn!("Can not mine without keys!");
        show_warning(web_view, "You don't have keys loaded!<br>Load or mine the keys and try again.");
    }
}

fn show_warning(web_view: &mut WebView<()>, text: &str) {
    let str = text.replace('\'', "\\'");
    match web_view.eval(&format!("showWarning('{}');", &str)) {
        Ok(_) => {}
        Err(_) => { warn!("Error showing warning!"); }
    }
}

#[allow(dead_code)]
fn show_success(web_view: &mut WebView<()>, text: &str) {
    let str = text.replace('\'', "\\'");
    match web_view.eval(&format!("showSuccess('{}');", &str)) {
        Ok(_) => {}
        Err(_) => { warn!("Error showing success!"); }
    }
}

#[allow(dead_code)]
fn event_info(web_view: &mut WebView<()>, message: &str) {
    let _ = web_view.eval(&format_event_now("info", message));
}

#[allow(dead_code)]
fn event_warn(web_view: &mut WebView<()>, message: &str) {
    let _ = web_view.eval(&format_event_now("warn", message));
}

#[allow(dead_code)]
fn event_fail(web_view: &mut WebView<()>, message: &str) {
    let _ = web_view.eval(&format_event_now("fail", message));
}

#[allow(dead_code)]
fn event_handle_info(handle: &Handle<()>, message: &str) {
    let message = message.to_owned();
    let _ = handle.dispatch(move |web_view|{
        web_view.eval(&format_event_now("info", &message))
    });
}

#[allow(dead_code)]
fn event_handle_warn(handle: &Handle<()>, message: &str) {
    let message = message.to_owned();
    let _ = handle.dispatch(move |web_view|{
        web_view.eval(&format_event_now("warn", &message))
    });
}

#[allow(dead_code)]
fn event_handle_fail(handle: &Handle<()>, message: &str) {
    let message = message.to_owned();
    let _ = handle.dispatch(move |web_view|{
        web_view.eval(&format_event_now("fail", &message))
    });
}

#[allow(dead_code)]
fn event_handle_luck(handle: &Handle<()>, message: &str) {
    let message = message.to_owned();
    let _ = handle.dispatch(move |web_view|{
        web_view.eval(&format_event_now("luck", &message))
    });
}

#[allow(dead_code)]
fn format_event(kind: &str, time: DateTime<Local>, message: &str) -> String {
    format!("addEvent('{}', '{}', '{}');", kind, time.format("%d.%m.%y %X"), message)
}

fn format_event_now(kind: &str, message: &str) -> String {
    let time = Local::now();
    format!("addEvent('{}', '{}', '{}');", kind, time.format("%d.%m.%y %X"), message)
}

fn create_zone(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, class: &str, name: &str, data: &str, difficulty: u32, keystore: &Keystore) {
    let name = name.to_owned();
    info!("Generating domain or zone {}", &name);
    if context.lock().unwrap().x_zones.has_zone(&name) {
        error!("Unable to mine IANA/OpenNIC/etc zone {}!", &name);
        return;
    }
    let transaction = Transaction::from_str(name, class.to_owned(), data.to_owned(), keystore.get_public().clone());
    let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default(), difficulty);
    miner.lock().unwrap().add_block(block, keystore.clone());
}

fn create_domain(_context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, class: &str, name: &str, mut data: DomainData, difficulty: u32, keystore: &Keystore) {
    let name = name.to_owned();
    let confirmation = hash_identity(&name, Some(&keystore.get_public()));
    data.domain = keystore.encrypt(name.as_bytes(), &confirmation.as_slice()[..12]);

    let data = serde_json::to_string(&data).unwrap();
    let transaction = Transaction::from_str(name, class.to_owned(), data, keystore.get_public().clone());
    let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default(), difficulty);
    miner.lock().unwrap().add_block(block, keystore.clone());
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
    MineDomain { name: String, data: String },
    TransferDomain { name: String, owner: String },
    StopMining,
    Open { link: String },
}

struct Status {
    pub mining: bool,
    pub syncing: bool,
    pub synced_blocks: u64,
    pub sync_height: u64,
    pub nodes_connected: usize,
    pub chain_height: u64,
    pub max_diff: u32,
    pub speed: Vec<u64>
}

impl Status {
    fn new(threads: usize) -> Self {
        let mut speed = Vec::with_capacity(threads);
        speed.resize(threads, 0u64);
        Status { mining: false, syncing: false, synced_blocks: 0, sync_height: 0, nodes_connected: 0, chain_height: 0, max_diff: 0, speed }
    }

    fn set_thread_speed(&mut self, thread: usize, speed: u64) {
        self.speed[thread] = speed;
    }

    fn get_speed(&self) -> u64 {
        self.speed.iter().sum()
    }
}

fn inline_style(s: &str) -> String {
    format!(r#"<style type="text/css">{}</style>"#, s)
}

fn inline_script(s: &str) -> String {
    format!(r#"<script type="text/javascript">{}</script>"#, s)
}
