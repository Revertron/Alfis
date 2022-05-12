// With the default subsystem, 'console', windows creates an additional console window for the program.
// This is silently ignored on non-windows systems.
// See https://msdn.microsoft.com/en-us/library/4cc7ya5b.aspx for more details.
#![windows_subsystem = "windows"]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, thread};

use getopts::{Matches, Options};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, format_description, LevelPadding, TerminalMode, TermLogger, WriteLogger};
#[cfg(windows)]
use winapi::um::wincon::{AttachConsole, FreeConsole, ATTACH_PARENT_PROCESS};
extern crate lazy_static;

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

use alfis::event::Event;
use alfis::eventbus::{post, register};
use alfis::keystore::create_key;
use alfis::{dns_utils, Block, Bytes, Chain, Context, Keystore, Miner, Network, Settings, Transaction, ALFIS_DEBUG, ALFIS_TRACE, DB_NAME, ORIGIN_DIFFICULTY};

#[cfg(feature = "webgui")]
mod web_ui;

const SETTINGS_FILENAME: &str = "alfis.toml";
const LOG_TARGET_MAIN: &str = "alfis::Main";

fn main() {
    #[allow(unused_assignments, unused_mut)]
    let mut console_attached = true;
    // When linked with the windows subsystem windows won't automatically attach
    // to the console of the parent process, so we do it explicitly. This fails silently if the parent has no console.
    #[cfg(windows)]
    unsafe {
        console_attached = AttachConsole(ATTACH_PARENT_PROCESS) != 0;
        #[cfg(feature = "webgui")]
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu");
    opts.optflag("n", "nogui", "Run without graphic user interface (default for no gui builds)");
    opts.optflag("v", "version", "Print version and exit");
    opts.optflag("d", "debug", "Show debug messages, more than usual");
    opts.optflag("t", "trace", "Show trace messages, more than debug");
    opts.optflag("b", "blocks", "List blocks from DB and exit");
    opts.optflag("g", "generate", "Generate new config file. Generated config will be printed to console.");
    opts.optopt("k", "gen-key", "Generate new keys and save them to file.", "FILE");
    opts.optopt("l", "log", "Write log to file", "FILE");
    opts.optopt("s", "status", "Write status to file", "FILE");
    opts.optopt("c", "config", "Path to config file", "FILE");
    opts.optopt("w", "work-dir", "Path to working directory", "DIRECTORY");
    opts.optopt("u", "upgrade", "Path to config file that you want to upgrade. Upgraded config will be printed to console.", "FILE");

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string())
    };

    if opt_matches.opt_present("h") {
        let brief = format!("Usage: {} [options]", program);
        println!("{}", opts.usage(&brief));
        exit(0);
    }

    if opt_matches.opt_present("v") {
        println!("ALFIS v{}", env!("CARGO_PKG_VERSION"));
        exit(0);
    }

    if opt_matches.opt_present("g") {
        println!("{}", include_str!("../alfis.toml"));
        exit(0);
    }

    match opt_matches.opt_str("u") {
        None => {}
        Some(path) => {
            if let Some(settings) = Settings::load(&path) {
                let string = toml::to_string(&settings).unwrap();
                println!("{}", &string);
            } else {
                println!("Error loading config for upgrade!");
            }
            return;
        }
    };

    #[cfg(feature = "webgui")]
    let no_gui = opt_matches.opt_present("n");
    #[cfg(not(feature = "webgui"))]
    let no_gui = true;

    if let Some(path) = opt_matches.opt_str("w") {
        env::set_current_dir(Path::new(&path)).unwrap_or_else(|_| panic!("Unable to change working directory to '{}'", &path));
    }
    let config_name = match opt_matches.opt_str("c") {
        None => SETTINGS_FILENAME.to_owned(),
        Some(path) => path
    };

    setup_logger(&opt_matches, console_attached);
    if let Some(status) = opt_matches.opt_str("s") {
        register(move |_, event| {
            // TODO optimize for same data
            if let Event::NetworkStatus { blocks, domains, keys, nodes } = event {
                match File::create(Path::new(&status)) {
                    Ok(mut f) => {
                        let data = format!("{{ \"blocks\":{}, \"domains\":{}, \"keys\":{}, \"nodes\":{} }}", blocks, domains, keys, nodes);
                        f.write_all(data.as_bytes()).expect("Error writing status file!");
                        let _ = f.flush();
                    }
                    Err(_) => { error!("Error writing status file!"); }
                }
            }
            true
        });
    }

    info!(target: LOG_TARGET_MAIN, "Starting ALFIS {}", env!("CARGO_PKG_VERSION"));

    let settings = Settings::load(&config_name).unwrap_or_else(|| panic!("Cannot load settings from {}!", &config_name));
    debug!(target: LOG_TARGET_MAIN, "Loaded settings: {:?}", &settings);
    let chain: Chain = Chain::new(&settings, DB_NAME);
    if opt_matches.opt_present("b") {
        for i in 1..(chain.get_height() + 1) {
            if let Some(block) = chain.get_block(i) {
                info!(target: LOG_TARGET_MAIN, "{:?}", &block);
            }
        }
        return;
    }
    info!("Blocks count: {}, domains count: {}, users count: {}", chain.get_height(), chain.get_domains_count(), chain.get_users_count());
    let settings_copy = settings.clone();
    let mut keys = Vec::new();
    if !settings.key_files.is_empty() {
        for name in &settings.key_files {
            match Keystore::from_file(name, "") {
                None => {
                    warn!("Error loading keyfile from {}", name);
                }
                Some(keystore) => {
                    info!("Successfully loaded keyfile {}", name);
                    keys.push(keystore);
                }
            }
        }
    }
    let context = Context::new(env!("CARGO_PKG_VERSION").to_owned(), settings, keys, chain);
    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(context));

    // If we just need to generate keys
    if let Some(filename) = opt_matches.opt_str("k") {
        info!(target: LOG_TARGET_MAIN, "Generating keys...");
        let mining = Arc::new(AtomicBool::new(true));
        let mining_copy = Arc::clone(&mining);
        let context_copy = Arc::clone(&context);
        // Register key-mined event listener
        register(move |_uuid, e| {
            if matches!(e, Event::KeyCreated { .. }) {
                let context_copy = Arc::clone(&context_copy);
                let mining_copy = Arc::clone(&mining_copy);
                let filename = filename.clone();
                thread::spawn(move || {
                    if let Some(keystore) = context_copy.lock().unwrap().get_keystore_mut() {
                        keystore.save(&filename, "");
                        mining_copy.store(false, Ordering::Relaxed);
                    }
                });
                false
            } else {
                true
            }
        });
        // Start key mining
        create_key(context);

        let delay = Duration::from_secs(1);
        while mining.load(Ordering::Relaxed) {
            thread::sleep(delay);
        }
        exit(0);
    }

    if let Ok(mut context) = context.lock() {
        context.chain.check_chain(settings_copy.check_blocks);
        match context.chain.get_block(1) {
            None => {
                info!(target: LOG_TARGET_MAIN, "No blocks found in DB");
            }
            Some(block) => {
                trace!(target: LOG_TARGET_MAIN, "Loaded DB with origin {:?}", &block.hash);
            }
        }
    }

    let dns_server_ok = if settings_copy.dns.threads > 0 {
        dns_utils::start_dns_server(&context, &settings_copy)
    } else {
        true
    };

    let mut miner_obj = Miner::new(Arc::clone(&context));
    miner_obj.start_mining_thread();
    let miner: Arc<Mutex<Miner>> = Arc::new(Mutex::new(miner_obj));

    let mut network = Network::new(Arc::clone(&context));
    let network = thread::Builder::new().name(String::from("Network")).spawn(move || {
        // Give UI some time to appear :)
        thread::sleep(Duration::from_millis(1000));
        network.start();
    }).expect("Could not start network thread!");

    create_genesis_if_needed(&context, &miner);
    if no_gui {
        print_my_domains(&context);
        let _ = network.join();
    } else {
        if !dns_server_ok {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(500));
                post(Event::Error { text: String::from("Error starting DNS-server. Please, check that it&rsquo;s port is not busy.") });
            });
        }
        #[cfg(feature = "webgui")]
        web_ui::run_interface(Arc::clone(&context), miner);
    }

    // Without explicitly detaching the console cmd won't redraw it's prompt.
    #[cfg(windows)]
    unsafe {
        FreeConsole();
    }
}

/// Sets up logger in accordance with command line options
fn setup_logger(opt_matches: &Matches, console_attached: bool) {
    let mut level = LevelFilter::Info;
    if opt_matches.opt_present("d") || env::var(ALFIS_DEBUG).is_ok() {
        level = LevelFilter::Debug;
    }
    if opt_matches.opt_present("t") || env::var(ALFIS_TRACE).is_ok() {
        level = LevelFilter::Trace;
    }
    let mut builder = ConfigBuilder::new();
    builder.add_filter_ignore_str("mio::poll")
        .add_filter_ignore_str("rustls::client")
        .add_filter_ignore_str("ureq::")
        .set_thread_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Off)
        .set_target_level(LevelFilter::Error)
        .set_level_padding(LevelPadding::Right)
        .set_time_level(LevelFilter::Error)
        .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond digits:3]"));
    let config = match builder.set_time_offset_to_local() {
        Ok(config) => config,
        Err(config) => config
    };
    let config = config.build();
    match opt_matches.opt_str("l") {
        None => {
            if console_attached {
                if let Err(e) = TermLogger::init(level, config, TerminalMode::Stdout, ColorChoice::Auto) {
                    println!("Unable to initialize logger!\n{}", e);
                }
            }
        }
        Some(path) => {
            let file = match OpenOptions::new().write(true).create(true).open(&path) {
                Ok(mut file) => {
                    file.seek(SeekFrom::End(0)).unwrap();
                    file
                }
                Err(e) => {
                    println!("Could not open log file '{}' for writing!\n{}", &path, e);
                    exit(1);
                }
            };
            if console_attached {
                CombinedLogger::init(vec![
                    TermLogger::new(level, config.clone(), TerminalMode::Stdout, ColorChoice::Auto),
                    WriteLogger::new(level, config, file),
                ])
                .unwrap();
            } else if let Err(e) = WriteLogger::init(level, config, file) {
                println!("Unable to initialize logger!\n{}", e);
            }
        }
    }
}

/// Gets own domains by current loaded keystore and writes them to log
fn print_my_domains(context: &Arc<Mutex<Context>>) {
    let context = context.lock().unwrap();
    let domains = context.chain.get_my_domains(context.get_keystore());
    debug!("Domains: {:?}", &domains);
}

/// Creates genesis (origin) block if `origin` is empty in config and we don't have any blocks in DB
fn create_genesis_if_needed(context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>) {
    // If there is no origin in settings and no blockchain in DB, generate genesis block
    let context = context.lock().unwrap();
    let last_block = context.get_chain().last_block();
    let origin = context.settings.origin.clone();
    if origin.is_empty() && last_block.is_none() {
        if let Some(keystore) = context.get_keystore() {
            // If blockchain is empty, we are going to mine a Genesis block
            let transaction = Transaction::origin(Chain::get_zones_hash(), keystore.get_public(), keystore.get_encryption_public());
            let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default(), ORIGIN_DIFFICULTY);
            miner.lock().unwrap().add_block(block, keystore.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use alfis::dns::protocol::{DnsRecord, TransientTtl};

    #[test]
    fn record_to_string() {
        let record = DnsRecord::A {
            domain: "google.com".to_string(),
            addr: "127.0.0.1".parse().unwrap(),
            ttl: TransientTtl(300)
        };
        println!("Record is {:?}", &record);
        println!("Record in JSON is {}", serde_json::to_string(&record).unwrap());
    }
}