extern crate open;
extern crate serde;
extern crate serde_json;
extern crate tinyfiledialogs as tfd;

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use alfis::blockchain::transaction::DomainData;
use alfis::blockchain::types::MineResult;
use alfis::commons::*;
use alfis::crypto::CryptoBox;
use alfis::dns::protocol::DnsRecord;
use alfis::event::Event;
use alfis::eventbus::{post, register};
use alfis::miner::Miner;
use alfis::{keystore, Block, Bytes, Context, Keystore, Transaction};
use chrono::{Local, Utc};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use serde::{Deserialize, Serialize};
use Cmd::*;

use tao::{
    event::{Event as TaoEvent, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::WindowBuilder,
};
use tao::dpi::PhysicalPosition;
use wry::WebViewBuilder;

pub fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>) {
    let file_content = include_str!("webview/index.html");
    let mut styles = inline_style(include_str!("webview/bulma.css"));
    styles.push_str(&inline_style(include_str!("webview/styles.css")));
    styles.push_str(&inline_style(include_str!("webview/busy_indicator.css")));
    let scripts = inline_script(include_str!("webview/scripts.js"));

    let html = file_content.to_owned().replace("{styles}", &styles).replace("{scripts}", &scripts);
    let title = format!("ALFIS {}", env!("CARGO_PKG_VERSION"));

    // Create event loop and window
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // Get primary monitor and calculate center position
    let primary_monitor = event_loop.primary_monitor().unwrap();
    let monitor_size = primary_monitor.size();
    let monitor_position = primary_monitor.position();

    let window_size = tao::dpi::LogicalSize::new(1024, 720);
    let scaled = window_size.to_physical::<i32>(primary_monitor.scale_factor());
    let center_x = monitor_position.x + (monitor_size.width as i32 - scaled.width) / 2;
    let center_y = monitor_position.y + (monitor_size.height as i32 - scaled.height) / 2;

    let window = WindowBuilder::new()
        .with_title(&title)
        .with_inner_size(window_size)
        .with_min_inner_size(tao::dpi::LogicalSize::new(773, 350))
        .with_position(PhysicalPosition::new(center_x, center_y))
        .with_resizable(true)
        .with_visible(true)
        .build(&event_loop)
        .expect("Failed to create the window");

    #[cfg(windows)]
    {
        use winapi::um::shellscalingapi::SetProcessDpiAwareness;
        unsafe {
            SetProcessDpiAwareness(2);
        }
        use tao::platform::windows::IconExtWindows;
        use tao::window::Icon;
        let icon = Icon::from_resource(1, None).unwrap();
        window.set_window_icon(Some(icon));
    }

    // Clone for the IPC handler
    let context_ipc = Arc::clone(&context);
    let miner_ipc = Arc::clone(&miner);
    let proxy_ipc = proxy.clone();

    // Create webview
    let builder = WebViewBuilder::new()
        .with_transparent(false)
        .with_visible(true)
        .with_devtools(true)
        .with_html(html)  // Using test HTML to verify wry works
        .with_ipc_handler(move |request| {
            let body = request.body();
            debug!("Command {}", body);

            match serde_json::from_str(body) {
                Ok(cmd) => {
                    match cmd {
                        Loaded => {
                            let _ = proxy_ipc.send_event(UserEvent::Loaded);
                        }
                        LoadKey => {
                            action_load_key(&context_ipc, &proxy_ipc);
                        }
                        CreateKey => {
                            keystore::create_key(Arc::clone(&context_ipc));
                        }
                        SaveKey => {
                            action_save_key(&context_ipc);
                        }
                        SelectKey { index } => {
                            action_select_key(&context_ipc, &proxy_ipc, index);
                        }
                        CheckRecord { data } => {
                            let result = check_record(&data);
                            let _ = proxy_ipc.send_event(UserEvent::EvalJs(format!("recordOkay({})", result)));
                        }
                        CheckDomain { name } => {
                            let available = check_domain_available(&context_ipc, &name);
                            let _ = proxy_ipc.send_event(UserEvent::EvalJs(format!("domainAvailable({})", available)));
                        }
                        MineDomain { name, data, signing, encryption, renewal } => {
                            action_create_domain(Arc::clone(&context_ipc), Arc::clone(&miner_ipc), &proxy_ipc, name, data, signing, encryption, renewal);
                        }
                        TransferDomain { name, owner } => {
                            info!("Transferring '{name}' to '{owner}'");
                        }
                        StopMining => {
                            post(Event::ActionStopMining);
                        }
                        Open { link } => {
                            if open::that(&link).is_err() {
                                let _ = proxy_ipc.send_event(UserEvent::ShowWarning("Something wrong, I can't open the link 😢".to_string()));
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error parsing command: {}", e);
                }
            }
        });

    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).unwrap();
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window.default_vbox().unwrap();
        builder.build_gtk(vbox).expect("Failed to build webview gtk object")
    };

    let webview = Arc::new(Mutex::new(webview));
    let webview_clone = Arc::clone(&webview);

    // Setup event bus listener
    let proxy_events = proxy.clone();
    let threads = context.lock().unwrap().settings.mining.threads;
    let threads = match threads {
        0 => num_cpus::get(),
        _ => threads
    };
    let status = Arc::new(Mutex::new(UiStatus::new(threads)));

    register(move |_uuid, e| {
        let status = Arc::clone(&status);
        let proxy = proxy_events.clone();

        thread::Builder::new().name(String::from("webui")).spawn(move || {
            let mut status = status.lock().unwrap();
            let eval = match e {
                Event::KeyCreated { path, public, hash } => {
                    let _ = proxy.send_event(UserEvent::LoadDomains);
                    let _ = proxy.send_event(UserEvent::SendKeysToUi);
                    let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('luck', '{}', 'Key successfully created! Don\\'t forget to save it!');", Local::now().format("%d.%m.%y %X"))));
                    let mut s = format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash);
                    s.push_str(" showSuccess('New key mined successfully! Save it to a safe place!')");
                    s
                }
                Event::KeyLoaded { path, public, hash } |
                Event::KeySaved { path, public, hash } => {
                    let _ = proxy.send_event(UserEvent::LoadDomains);
                    let _ = proxy.send_event(UserEvent::SendKeysToUi);
                    format!("keystoreChanged('{}', '{}', '{}');", &path, &public, &hash)
                }
                Event::MinerStarted | Event::KeyGeneratorStarted => {
                    status.mining = true;
                    status.max_diff = 0;
                    let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'Mining started');", Local::now().format("%d.%m.%y %X"))));
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
                                let _ = proxy.send_event(UserEvent::LoadDomains);
                                let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('luck', '{}', 'Mining is successful!');", Local::now().format("%d.%m.%y %X"))));
                                s.push_str(" showSuccess('Block successfully mined!')");
                            }
                            false => {
                                let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'Mining finished without result.');", Local::now().format("%d.%m.%y %X"))));
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
                        let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'Syncing started...');", Local::now().format("%d.%m.%y %X"))));
                        status.sync_height = height;
                    }
                    if status.mining {
                        String::from("setLeftStatusBarText('Mining...'); showMiningIndicator(true, false);")
                    } else {
                        format!("setLeftStatusBarText('Synchronizing {}/{}'); showMiningIndicator(true, true);", have, height)
                    }
                }
                Event::SyncFinished => {
                    let _ = proxy.send_event(UserEvent::LoadDomains);
                    let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'Syncing finished.');", Local::now().format("%d.%m.%y %X"))));
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
                    let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'Blockchain changed, current block count is {} now.');", Local::now().format("%d.%m.%y %X"), index)));
                    String::new()
                }
                Event::Error { text } => format!("showError('{}')", &text),
                _ => String::new()
            };

            if !eval.is_empty() {
                let _ = proxy.send_event(UserEvent::EvalJs(eval));
            }
        }).ok();
        true
    });

    // Run event loop
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            TaoEvent::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                info!("Interface closed, exiting");
                post(Event::ActionQuit);
                thread::sleep(Duration::from_millis(100));
                *control_flow = ControlFlow::Exit;
            }
            TaoEvent::UserEvent(user_event) => {
                let wv = webview_clone.lock().unwrap();
                match user_event {
                    UserEvent::EvalJs(js) => {
                        let js_escaped = js.replace("\\", "\\\\");
                        if let Err(e) = wv.evaluate_script(&js_escaped) {
                            error!("Error evaluating JavaScript: {}", e);
                        }
                    }
                    UserEvent::Loaded => {
                        action_loaded(&context, &wv, &proxy);
                    }
                    UserEvent::LoadDomains => {
                        load_domains(&mut context.lock().unwrap(), &wv);
                    }
                    UserEvent::SendKeysToUi => {
                        send_keys_to_ui(&context.lock().unwrap(), &wv);
                    }
                    UserEvent::ShowWarning(text) => {
                        show_warning(&wv, &text);
                    }
                }
            }
            _ => {}
        }
    });
}

#[derive(Debug)]
enum UserEvent {
    EvalJs(String),
    Loaded,
    LoadDomains,
    SendKeysToUi,
    ShowWarning(String),
}

fn check_record(data: &str) -> bool {
    match serde_json::from_str::<DnsRecord>(data) {
        Ok(record) => {
            if let Some(string) = record.get_data() {
                string.len() <= MAX_DATA_LEN
            } else {
                false
            }
        }
        Err(_) => false
    }
}

fn check_domain_available(context: &Arc<Mutex<Context>>, name: &str) -> bool {
    let c = context.lock().unwrap();
    if let Some(keystore) = c.get_keystore() {
        let name = name.to_lowercase();
        matches!(c.chain.can_mine_domain(c.chain.get_height(), &name, &keystore.get_public()), MineResult::Fine)
    } else {
        false
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

fn action_select_key(context: &Arc<Mutex<Context>>, proxy: &EventLoopProxy<UserEvent>, index: usize) {
    if context.lock().unwrap().select_key_by_index(index) {
        let (path, public, hash) = {
            let keystore = context.lock().unwrap().get_keystore().cloned().unwrap();
            let path = keystore.get_path().to_owned();
            let public = keystore.get_public().to_string();
            let hash = keystore.get_hash().to_string();
            (path, public, hash)
        };
        post(Event::KeyLoaded { path, public, hash });
        let _ = proxy.send_event(UserEvent::EvalJs(format!("keySelected({})", index)));
    }
}

fn action_load_key(context: &Arc<Mutex<Context>>, proxy: &EventLoopProxy<UserEvent>) {
    let result = tfd::open_file_dialog("Open keys file", "", Some((&["*.key", "*.toml"], "Key files")));
    match result {
        None => {}
        Some(file_name) => {
            match Keystore::from_file(&file_name, "") {
                None => {
                    error!("Error loading keystore '{}'!", &file_name);
                    let _ = proxy.send_event(UserEvent::ShowWarning("Error loading key!<br>Key cannot be loaded or its difficulty is not enough.".to_string()));
                    let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('fail', '{}', 'Error loading key from \\\\'{}\\\\!');", Local::now().format("%d.%m.%y %X"), &file_name)));
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

fn action_loaded(context: &Arc<Mutex<Context>>, webview: &wry::WebView, proxy: &EventLoopProxy<UserEvent>) {
    info!("Interface loaded");
    let _ = webview.evaluate_script("showMiningIndicator(false, false);");

    let c = context.lock().unwrap();

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
        let _ = webview.evaluate_script(&format!("zonesChanged('{}');", &zones));
    }

    drop(c);
    let _ = proxy.send_event(UserEvent::SendKeysToUi);

    let c = context.lock().unwrap();
    let command = format!("setStats({}, {}, {}, {});", c.chain.get_height(), c.chain.get_domains_count(), c.chain.get_users_count(), 0);
    if let Err(e) = webview.evaluate_script(&command) {
        error!("Error evaluating stats: {}", e);
    }
    let _ = webview.evaluate_script(&format!("addEvent('info', '{}', 'Application loaded');", Local::now().format("%d.%m.%y %X")));
}

fn load_domains(context: &mut MutexGuard<Context>, webview: &wry::WebView) {
    let _ = webview.evaluate_script("clearMyDomains();");
    let domains = context.chain.get_my_domains(context.get_keystore());
    let mut domains = domains.iter().map(|(_, d)| d).collect::<Vec<_>>();
    domains.sort_by(|a, b| a.0.cmp(&b.0));
    for (domain, timestamp, data) in domains {
        let d = serde_json::to_string(&data).unwrap();
        let d = d.replace("'", "\\'").replace("\\n", "\\\\n").replace("\"", "\\\"");
        let command = format!("addMyDomain('{}', {}, {}, '{}');", &domain, timestamp, timestamp + DOMAIN_LIFETIME, &d);
        let _ = webview.evaluate_script(&command);
    }
    let _ = webview.evaluate_script("refreshMyDomains();");
}

fn send_keys_to_ui(context: &MutexGuard<Context>, webview: &wry::WebView) {
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
        let command = format!("keysChanged('{}'); keySelected({});", serde_json::to_string(&keys).unwrap(), index);
        let _ = webview.evaluate_script(&command);
    }
}

fn action_create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, proxy: &EventLoopProxy<UserEvent>, name: String, data: String, signing: String, encryption: String, renewal: bool) {
    debug!("Creating domain with data: {}", &data);
    let c = Arc::clone(&context);
    let context_guard = context.lock().unwrap();

    if !context_guard.has_keys() {
        let _ = proxy.send_event(UserEvent::ShowWarning("You don't have keys loaded!<br>Load or mine the keys and try again.".to_string()));
        let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        return;
    }

    if context_guard.chain.is_waiting_signers() {
        let _ = proxy.send_event(UserEvent::ShowWarning("Waiting for last full block to be signed. Try again later.".to_string()));
        let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        info!("Waiting for last full block to be signed. Try again later.");
        return;
    }

    let keystore = context_guard.get_keystore().unwrap().clone();
    let pub_key = keystore.get_public();
    let data = match serde_json::from_str::<DomainData>(&data) {
        Ok(data) => data,
        Err(e) => {
            let _ = proxy.send_event(UserEvent::ShowWarning("Something wrong with domain data. I cannot mine it.".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
            warn!("Error parsing data: {}", e);
            return;
        }
    };

    info!("Parsed domain data:\n{:#?}", &data);

    if data.records.len() > MAX_RECORDS {
        let _ = proxy.send_event(UserEvent::ShowWarning("Too many records. Mining more than 30 records not allowed.".to_string()));
        let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        return;
    }

    // Check if yggdrasil only quality of zone is not violated
    let zones = context_guard.chain.get_zones();
    for z in zones {
        if z.name == data.zone && z.yggdrasil {
            for record in &data.records {
                if !is_yggdrasil_record(record) {
                    let _ = proxy.send_event(UserEvent::ShowWarning(format!("Zone {} is Yggdrasil only, you cannot use IPs from clearnet!", &data.zone)));
                    let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
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

    match context_guard.chain.can_mine_domain(context_guard.chain.get_height(), &name, &pub_key) {
        MineResult::Fine => {
            drop(context_guard);
            create_domain(c, miner, CLASS_DOMAIN, &name, data, DOMAIN_DIFFICULTY, &keystore, signing, encryption, renewal);
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningStarted();".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'Mining of domain \\\\'{}\\\\' has started');", Local::now().format("%d.%m.%y %X"), &name)));
        }
        MineResult::WrongName => {
            let _ = proxy.send_event(UserEvent::ShowWarning("You can't mine this domain!".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        }
        MineResult::WrongData => {
            let _ = proxy.send_event(UserEvent::ShowWarning("You have an error in records!".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        }
        MineResult::WrongKey => {
            let _ = proxy.send_event(UserEvent::ShowWarning("You can't mine with current key!".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        }
        MineResult::WrongZone => {
            let _ = proxy.send_event(UserEvent::ShowWarning("You can't mine domain in this zone!".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        }
        MineResult::NotOwned => {
            let _ = proxy.send_event(UserEvent::ShowWarning("This domain is already taken, and it is not yours!".to_string()));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
        }
        MineResult::Cooldown { time } => {
            let cooldown = format_cooldown(time);
            let _ = proxy.send_event(UserEvent::EvalJs(format!("addEvent('info', '{}', 'You have cooldown {}!');", Local::now().format("%d.%m.%y %X"), &cooldown)));
            let _ = proxy.send_event(UserEvent::ShowWarning(format!("You have cooldown {}!", cooldown)));
            let _ = proxy.send_event(UserEvent::EvalJs("domainMiningUnavailable();".to_string()));
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

fn show_warning(webview: &wry::WebView, text: &str) {
    let str = text.replace('\'', "\\'");
    if let Err(e) = webview.evaluate_script(&format!("showWarning('{}');", &str)) {
        warn!("Error showing warning: {}", e);
    }
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
    let height = context.lock().unwrap().chain.get_height();
    let discount = context.lock().unwrap().chain.get_identity_discount(&transaction.identity, renewal, height, Utc::now().timestamp());
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
        let speed = vec![0; threads];
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