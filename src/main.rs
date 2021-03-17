// With the default subsystem, 'console', windows creates an additional console window for the program.
// This is silently ignored on non-windows systems.
// See https://msdn.microsoft.com/en-us/library/4cc7ya5b.aspx for more details.
#![windows_subsystem = "windows"]

use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use getopts::Options;
#[allow(unused_imports)]
use log::{debug, error, info, LevelFilter, trace, warn};
use simple_logger::SimpleLogger;
#[cfg(windows)]
use winapi::um::wincon::{ATTACH_PARENT_PROCESS, AttachConsole, FreeConsole};

use alfis::{Block, Bytes, Chain, Miner, Context, Network, Settings, dns_utils, Keystore};
use alfis::blockchain::BLOCK_DIFFICULTY;

mod web_ui;

const SETTINGS_FILENAME: &str = "alfis.toml";
const LOG_TARGET_MAIN: &str = "alfis::Main";

fn main() {
    // When linked with the windows subsystem windows won't automatically attach
    // to the console of the parent process, so we do it explicitly. This fails silently if the parent has no console.
    #[cfg(windows)]
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu");
    opts.optflag("n", "nogui", "Run without graphic user interface");
    opts.optflag("v", "verbose", "Show more debug messages");
    opts.optflag("d", "debug", "Show trace messages, more than debug");
    opts.optflag("l", "list", "List blocks from DB and exit");
    opts.optopt("c", "config", "Path to config file", "");

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    if opt_matches.opt_present("h") {
        let brief = format!("Usage: {} [options]", program);
        print!("{}", opts.usage(&brief));
        return;
    }

    let no_gui = opt_matches.opt_present("n");

    let mut level = LevelFilter::Info;
    if opt_matches.opt_present("v") {
        level = LevelFilter::Debug;
    }
    if opt_matches.opt_present("d") {
        level = LevelFilter::Trace;
    }
    let config_name = match opt_matches.opt_str("c") {
        None => { SETTINGS_FILENAME.to_owned() }
        Some(path) => { path }
    };
    SimpleLogger::new().with_level(level).init().unwrap();
    info!(target: LOG_TARGET_MAIN, "Starting ALFIS {}", env!("CARGO_PKG_VERSION"));

    let settings = Settings::load(&config_name);
    info!(target: LOG_TARGET_MAIN, "Loaded settings: {:?}", &settings);
    let keystore: Keystore = match Keystore::from_file(&settings.key_file, "") {
        None => {
            warn!(target: LOG_TARGET_MAIN, "Generated temporary keystore. Please, generate full-privileged keys.");
            Keystore::new()
        }
        Some(keystore) => { keystore }
    };
    let chain: Chain = Chain::new(&settings);
    if opt_matches.opt_present("l") {
        for i in 1..(chain.height() + 1) {
            if let Some(block) = chain.get_block(i) {
                info!(target: LOG_TARGET_MAIN, "{:?}", &block);
            }
        }
        return;
    }

    match chain.get_block(1) {
        None => { info!(target: LOG_TARGET_MAIN, "No blocks found in DB"); }
        Some(block) => { trace!(target: LOG_TARGET_MAIN, "Loaded DB with origin {:?}", &block.hash); }
    }
    let settings_copy = settings.clone();
    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(Context::new(settings, keystore, chain)));
    dns_utils::start_dns_server(&context, &settings_copy);

    let mut miner_obj = Miner::new(context.clone());
    miner_obj.start_mining_thread();
    let miner: Arc<Mutex<Miner>> = Arc::new(Mutex::new(miner_obj));

    let mut network = Network::new(context.clone());
    network.start().expect("Error starting network component");

    create_genesis_if_needed(&context, &miner);
    if no_gui {
        let sleep = Duration::from_millis(1000);
        loop {
            thread::sleep(sleep);
        }
    } else {
        web_ui::run_interface(context.clone(), miner.clone());
    }

    // Without explicitly detaching the console cmd won't redraw it's prompt.
    #[cfg(windows)]
    unsafe {
        FreeConsole();
    }
}

fn create_genesis_if_needed(context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>) {
    // If there is no origin in settings and no blockchain in DB, generate genesis block
    let context = context.lock().unwrap();
    let last_block = context.get_chain().last_block();
    let origin = context.settings.origin.clone();
    if origin.eq("") && last_block.is_none() {
        // If blockchain is empty, we are going to mine a Genesis block
        let block = Block::new(None, context.get_keystore().get_public(), Bytes::default(), BLOCK_DIFFICULTY);
        miner.lock().unwrap().add_block(block);
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