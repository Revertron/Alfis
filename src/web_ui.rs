extern crate open;
extern crate serde;
extern crate serde_json;
extern crate tinyfiledialogs as tfd;
extern crate web_view;

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use alfis::blockchain::transaction::DomainData;
use alfis::blockchain::types::MineResult;
use alfis::commons::*;
use alfis::crypto::CryptoBox;
use alfis::dns::protocol::DnsRecord;
use alfis::event::Event;
use alfis::eventbus::{post, register};
use alfis::miner::Miner;
use alfis::{keystore, Block, Bytes, Context, Keystore, Transaction};
use chrono::{DateTime, Local};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use serde::{Deserialize, Serialize};
use web_view::Content;
use Cmd::*;

use self::web_view::{Handle, WebView};

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
                CreateKey => { keystore::create_key(Arc::clone(&context)); }
                SaveKey => { action_save_key(&context); }
                SelectKey { index } => { action_select_key(&context, web_view, index); }
                CheckRecord { data } => { action_check_record(web_view, data); }
                CheckDomain { name } => { action_check_domain(&context, web_view, name); }
                MineDomain { name, data, signing, encryption, renewal } => {
                    action_create_domain(Arc::clone(&context), Arc::clone(&miner), web_view, name, data, signing, encryption, renewal);
                }
                TransferDomain { .. } => {}
                StopMining => { post(Event::ActionStopMining); }
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

    run_interface_loop(&mut interface);
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
                post(Event::ActionQuit);
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

fn action_check_record(web_view: &mut WebView<()>, data: String) {
    match serde_json::from_str::<DnsRecord>(&data) {
        Ok(record) => {
            if let Some(string) = record.get_data() {
                if string.len() > MAX_DATA_LEN {
                    web_view.eval("recordOkay(false)").expect("Error evaluating!");
                } else {
                    web_view.eval("recordOkay(true)").expect("Error evaluating!");
                }
            }
        }
        Err(e) => {
            web_view.eval("recordOkay(false)").expect("Error evaluating!");
            dbg!(e);
        }
    }
}

fn action_check_domain(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>, name: String) {
    let c = context.lock().unwrap();
    if let Some(keystore) = c.get_keystore() {
        let name = name.to_lowercase();
        let available = c.get_chain().is_domain_available(c.get_chain().get_height(), &name, keystore);
        web_view.eval(&format!("domainAvailable({})", available)).expect("Error evaluating!");
    }
}

fn action_save_key(context: &Arc<Mutex<Context>>) {
    if !context.lock().unwrap().has_keys() {
        return;
    }
    let result = tfd::save_file_dialog_with_filter("Save keys file", "", &["*.toml"], "Key files (*.toml)");
    match result {
        None => {}
        Some(mut new_path) => {
            if !new_path.ends_with(".toml") {
                new_path.push_str(".toml");
            }
            let path = new_path.clone();
            if let Some(keystore) = context.lock().unwrap().get_keystore_mut() {
                let public = keystore.get_public().to_string();
                let hash = keystore.get_hash().to_string();
                keystore.save(&new_path, "");
                info!("Key file saved to {}", &path);
                post(Event::KeySaved { path, public, hash });
            }
        }
    }
}

fn action_select_key(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>, index: usize) {
    if context.lock().unwrap().select_key_by_index(index) {
        let (path, public, hash) = {
            let keystore = context.lock().unwrap().get_keystore().cloned().unwrap();
            let path = keystore.get_path().to_owned();
            let public = keystore.get_public().to_string();
            let hash = keystore.get_hash().to_string();
            (path, public, hash)
        };
        post(Event::KeyLoaded { path, public, hash });
        web_view.eval(&format!("keySelected({})", index)).expect("Error evaluating!");
    }
}

fn action_load_key(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>) {
    let result = tfd::open_file_dialog("Open keys file", "", Some((&["*.key", "*.toml"], "Key files")));
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
                    info!("Loaded keystore with keys: {:?}, {:?}", &keystore.get_public(), &keystore.get_encryption_public());
                    let path = keystore.get_path().to_owned();
                    let public = keystore.get_public().to_string();
                    let hash = keystore.get_hash().to_string();
                    post(Event::KeyLoaded { path, public, hash });

                    if !context.lock().unwrap().select_key_by_public(&keystore.get_public()) {
                        context.lock().unwrap().add_keystore(keystore);
                    } else {
                        warn!("This key is already loaded!");
                    }
                }
            }
        }
    }
}

fn action_loaded(context: &Arc<Mutex<Context>>, web_view: &mut WebView<()>) {
    info!("Interface loaded");
    web_view.eval("showMiningIndicator(false, false);").expect("Error evaluating!");
    let handle: Handle<()> = web_view.handle();
    let threads = context.lock().unwrap().settings.mining.threads;
    let threads = match threads {
        0 => num_cpus::get(),
        _ => threads
    };
    let status = Arc::new(Mutex::new(UiStatus::new(threads)));
    let context_copy = Arc::clone(context);
    let c = context.lock().unwrap();

    register(move |_uuid, e| {
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
                    send_keys_to_ui(&context, &handle);
                    event_handle_luck(&handle, "Key successfully created! Don\\'t forget to save it!");
                    let mut s = format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash);
                    s.push_str(" showSuccess('New key mined successfully! Save it to a safe place!')");
                    s
                }
                Event::KeyLoaded { path, public, hash } |
                Event::KeySaved { path, public, hash } => {
                    load_domains(&mut context, &handle);
                    send_keys_to_ui(&context, &handle);
                    format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash)
                }
                Event::MinerStarted | Event::KeyGeneratorStarted => {
                    status.mining = true;
                    status.max_diff = 0;
                    event_handle_info(&handle, "Mining started");
                    String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                }
                Event::MinerStopped { success, full } => {
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
                                load_domains(&mut context, &handle);
                                event_handle_luck(&handle, "Mining is successful!");
                                s.push_str(" showSuccess('Block successfully mined!')");
                            }
                            false => {
                                event_handle_info(&handle, "Mining finished without result.");
                                s.push_str(" showWarning('Mining unsuccessful, sorry.')");
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
                    if thread as usize == threads - 1 {
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
                    status.syncing = true;
                    status.synced_blocks = have;
                    if height != status.sync_height {
                        event_handle_info(&handle, "Syncing started...");
                        status.sync_height = height;
                    }
                    if status.mining {
                        String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                    } else {
                        format!("setLeftStatusBarText('Synchronizing {}/{}'); showMiningIndicator(true, true);", have, height)
                    }
                }
                Event::SyncFinished => {
                    load_domains(&mut context, &handle);
                    event_handle_info(&handle, "Syncing finished.");
                    status.syncing = false;
                    if status.mining {
                        String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                    } else {
                        String::from("setLeftStatusBarText('Idle'); showMiningIndicator(false, false);")
                    }
                }
                Event::NetworkStatus { blocks, domains, keys, nodes } => {
                    if status.mining || status.syncing || nodes < 3 {
                        format!("setStats({}, {}, {}, {});", blocks, domains, keys, nodes)
                    } else {
                        format!("setLeftStatusBarText('Idle'); setStats({}, {}, {}, {});", blocks, domains, keys, nodes)
                    }
                }
                Event::BlockchainChanged { index } => {
                    debug!("Current blockchain height is {}", index);
                    event_handle_info(&handle, &format!("Blockchain changed, current block count is {} now.", index));
                    String::new() // Nothing
                }
                Event::Error { text } => format!("showError('{}')", &text),
                _ => String::new()
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
        post(Event::KeyLoaded { path, public, hash });
    }
    let index = c.chain.get_height();
    if index > 0 {
        post(Event::BlockchainChanged { index });
    }
    let zones = c.chain.get_zones();
    info!("Loaded zones: {:?}", &zones);
    if let Ok(zones) = serde_json::to_string(&zones) {
        let _ = web_view.eval(&format!("zonesChanged('{}');", &zones));
    }
    send_keys_to_ui(&c, &web_view.handle());
    let command = format!("setStats({}, {}, {}, {});", c.chain.get_height(), c.chain.get_domains_count(), c.chain.get_users_count(), 0);
    if let Err(e) = web_view.eval(&command) {
        error!("Error evaluating stats: {}", e);
    }
    event_info(web_view, "Application loaded");
}

fn load_domains(context: &mut MutexGuard<Context>, handle: &Handle<()>) {
    let _ = handle.dispatch(move |web_view|{
        web_view.eval("clearMyDomains();")
    });
    let domains = context.chain.get_my_domains(context.get_keystore());
    //debug!("Domains: {:?}", &domains.values());
    for (_identity, (domain, timestamp, data)) in domains {
        let d = serde_json::to_string(&data).unwrap();
        let d = d.replace("'", "\\'");
        let command = format!("addMyDomain('{}', {}, {}, '{}');", &domain, timestamp, timestamp + DOMAIN_LIFETIME, &d);
        let _ = handle.dispatch(move |web_view|{
            web_view.eval(&command)
        });
    }
    let _ = handle.dispatch(move |web_view|{
        web_view.eval("refreshMyDomains();")
    });
}

fn send_keys_to_ui(context: &MutexGuard<Context>, handle: &Handle<()>) {
    let keys = {
        let mut keys = Vec::new();
        for key in context.get_keystores() {
            let path = key.get_path().replace("\\", "/");
            let parts: Vec<&str> = path.rsplitn(2, '/').collect();
            keys.push(KeysForJS { file_name: parts[0].to_owned(), public: key.get_public().to_string() });
        }
        keys
    };
    if !keys.is_empty() {
        let index = context.get_active_key_index();
        let _ = handle.dispatch(move |web_view| {
            let command = format!("keysChanged('{}'); keySelected({});", serde_json::to_string(&keys).unwrap(), index);
            web_view.eval(&command)
        });
    }
}

fn action_create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, web_view: &mut WebView<()>, name: String, data: String, signing: String, encryption: String, renewal: bool) {
    debug!("Creating domain with data: {}", &data);
    let c = Arc::clone(&context);
    let context = context.lock().unwrap();
    if !context.has_keys() {
        show_warning(web_view, "You don't have keys loaded!<br>Load or mine the keys and try again.");
        let _ = web_view.eval("domainMiningUnavailable();");
        return;
    }
    if context.chain.is_waiting_signers() {
        show_warning(web_view, "Waiting for last full block to be signed. Try again later.");
        let _ = web_view.eval("domainMiningUnavailable();");
        info!("Waiting for last full block to be signed. Try again later.");
        return;
    }
    let keystore = context.get_keystore().unwrap().clone();
    let pub_key = keystore.get_public();
    let data = match serde_json::from_str::<DomainData>(&data) {
        Ok(data) => data,
        Err(e) => {
            show_warning(web_view, "Something wrong with domain data. I cannot mine it.");
            let _ = web_view.eval("domainMiningUnavailable();");
            warn!("Error parsing data: {}", e);
            return;
        }
    };
    info!("Parsed domain data:\n{:#?}", &data);
    if data.records.len() > MAX_RECORDS {
        show_warning(web_view, "Too many records. Mining more than 30 records not allowed.");
        let _ = web_view.eval("domainMiningUnavailable();");
        return;
    }
    // Check if yggdrasil only quality of zone is not violated
    let zones = context.chain.get_zones();
    for z in zones {
        if z.name == data.zone && z.yggdrasil {
            for record in &data.records {
                if !is_yggdrasil_record(record) {
                    show_warning(web_view, &format!("Zone {} is Yggdrasil only, you cannot use IPs from clearnet!", &data.zone));
                    let _ = web_view.eval("domainMiningUnavailable();");
                    return;
                }
            }
        }
    }
    let (signing, encryption) = if signing.is_empty() || encryption.is_empty() {
        (keystore.get_public(), keystore.get_encryption_public())
    } else {
        (Bytes::new(from_hex(&signing).unwrap()), Bytes::new(from_hex(&encryption).unwrap()))
    };
    match context.chain.can_mine_domain(context.chain.get_height(), &name, &pub_key) {
        MineResult::Fine => {
            std::mem::drop(context);
            create_domain(c, miner, CLASS_DOMAIN, &name, data, DOMAIN_DIFFICULTY, &keystore, signing, encryption, renewal);
            let _ = web_view.eval("domainMiningStarted();");
            event_info(web_view, &format!("Mining of domain \\'{}\\' has started", &name));
        }
        MineResult::WrongName => {
            show_warning(web_view, "You can't mine this domain!");
            let _ = web_view.eval("domainMiningUnavailable();");
        }
        MineResult::WrongData => {
            show_warning(web_view, "You have an error in records!");
            let _ = web_view.eval("domainMiningUnavailable();");
        }
        MineResult::WrongKey => {
            show_warning(web_view, "You can't mine with current key!");
            let _ = web_view.eval("domainMiningUnavailable();");
        }
        MineResult::WrongZone => {
            show_warning(web_view, "You can't mine domain in this zone!");
            let _ = web_view.eval("domainMiningUnavailable();");
        }
        MineResult::NotOwned => {
            show_warning(web_view, "This domain is already taken, and it is not yours!");
            let _ = web_view.eval("domainMiningUnavailable();");
        }
        MineResult::Cooldown { time } => {
            event_info(web_view, &format!("You have cooldown {}!", format_cooldown(time)));
            show_warning(web_view, &format!("You have cooldown {}!", format_cooldown(time)));
            let _ = web_view.eval("domainMiningUnavailable();");
        }
    }
}

fn format_cooldown(time: i64) -> String {
    if time <= 60 {
        return format!("{} seconds", time);
    }
    let minutes = time / 60;
    if minutes <= 60 {
        return format!("{} minutes", minutes);
    }
    format!("{} hours", minutes / 60)
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

#[allow(clippy::too_many_arguments)]
fn create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, class: &str, name: &str, mut data: DomainData, difficulty: u32, keystore: &Keystore, signing: Bytes, encryption: Bytes, renewal: bool) {
    let name = name.to_owned();
    let encrypted = CryptoBox::encrypt(encryption.as_slice(), name.as_bytes()).expect("Error encrypting domain name!");
    data.encrypted = Bytes::from_bytes(&encrypted);

    let data = serde_json::to_string(&data).unwrap();
    let (signing, encryption) = if signing.is_empty() || encryption.is_empty() {
        (keystore.get_public(), keystore.get_encryption_public())
    } else {
        (signing, encryption)
    };
    let transaction = Transaction::from_str(name, class.to_owned(), data, signing, encryption);
    // If this domain is already in blockchain we approve slightly smaller difficulty
    let discount = context.lock().unwrap().chain.get_identity_discount(&transaction.identity, renewal);
    let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default(), difficulty - discount);
    miner.lock().unwrap().add_block(block, keystore.clone());
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
pub enum Cmd {
    Loaded,
    LoadKey,
    CreateKey,
    SaveKey,
    SelectKey { index: usize },
    CheckRecord { data: String },
    CheckDomain { name: String },
    MineDomain { name: String, data: String, signing: String, encryption: String, renewal: bool },
    TransferDomain { name: String, owner: String },
    StopMining,
    Open { link: String }
}

struct UiStatus {
    pub mining: bool,
    pub syncing: bool,
    pub synced_blocks: u64,
    pub sync_height: u64,
    pub max_diff: u32,
    pub speed: Vec<u64>
}

impl UiStatus {
    fn new(threads: usize) -> Self {
        let speed =vec![0; threads];
        UiStatus { mining: false, syncing: false, synced_blocks: 0, sync_height: 0, max_diff: 0, speed }
    }

    fn set_thread_speed(&mut self, thread: u32, speed: u64) {
        self.speed[thread as usize] = speed;
    }

    fn get_speed(&self) -> u64 {
        self.speed.iter().sum()
    }
}

#[derive(Serialize)]
struct KeysForJS {
    file_name: String,
    public: String
}

fn inline_style(s: &str) -> String {
    format!(r#"<style type="text/css">{}</style>"#, s)
}

fn inline_script(s: &str) -> String {
    format!(r#"<script type="text/javascript">{}</script>"#, s)
}