use alfis::commons::constants::*;
use alfis::{Bytes, Chain, Settings};
use sqlite::State;

/// Audits RFC-0003 ban crystallization against a real blockchain.db (read-only usage,
/// unless `check` is given — re-validation truncates on a bad block, use a scratch copy).
///
/// Usage:
///   ban_check [db_path]         - defaults to blockchain.db
///   ban_check <db_path> check   - also re-validate the last 500 blocks like node startup does
fn main() {
    init_logger();
    let path = std::env::args().nth(1).unwrap_or_else(|| "blockchain.db".to_string());
    println!("Opening {}", &path);
    let mut chain = Chain::new(&Settings::default(), &path);
    if std::env::args().nth(2).as_deref() == Some("check") {
        let height = chain.get_height();
        chain.check_chain(500);
        println!("Re-validation of the last 500 blocks: height {} -> {} (must be equal)", height, chain.get_height());
        assert_eq!(height, chain.get_height(), "Re-validation truncated the chain!");
    }
    let height = chain.get_height();
    println!("Chain height: {}", height);
    println!("BAN_ACTIVATION_HEIGHT: {}, BAN_POOL_FLOOR: {}, BAN_DRAW_MIN: {}", BAN_ACTIVATION_HEIGHT, BAN_POOL_FLOOR, BAN_DRAW_MIN);
    println!();

    let db = sqlite::open(&path).expect("Unable to open DB");
    let stats = |key: &Bytes| -> (i64, u64, i64) {
        let mut statement = db.prepare("SELECT COUNT(*), MAX(id), MAX(timestamp) FROM blocks WHERE pub_key = ?;").unwrap();
        statement.bind((1, key.as_slice())).unwrap();
        if let State::Row = statement.next().unwrap() {
            return (statement.read::<i64, usize>(0).unwrap(), statement.read::<i64, usize>(1).unwrap() as u64, statement.read::<i64, usize>(2).unwrap());
        }
        (0, 0, 0)
    };

    // Crystallized bans as of the tip
    let bans = chain.get_banned_keys(height);
    println!("=== Crystallized bans as of height {} ===", height);
    if bans.is_empty() {
        println!("(none)");
    }
    for key in &bans {
        let (count, last_index, last_time) = stats(key);
        println!("  {:?}: {} blocks, last authored block {} at {}", key, count, last_index, last_time);
    }
    println!();

    // Eligible population with and without the bans
    let minimum = if height < 855 { 1i64 } else { height as i64 / 100 };
    let mut statement = db.prepare("SELECT COUNT(*) FROM (SELECT pub_key FROM blocks WHERE id < ? GROUP BY pub_key HAVING COUNT(*) >= ?);").unwrap();
    statement.bind((1, height as i64)).unwrap();
    statement.bind((2, minimum)).unwrap();
    statement.next().unwrap();
    let eligible = statement.read::<i64, usize>(0).unwrap() as usize;
    let banned_eligible = bans.iter().filter(|key| stats(key).0 >= minimum).count();
    println!("Eligibility threshold at tip: {} blocks", minimum);
    println!("Eligible keys: {}, of them banned: {}, remaining drawable: {}", eligible, banned_eligible, eligible - banned_eligible);
    if eligible - banned_eligible < BAN_DRAW_MIN {
        println!("!!! Below BAN_DRAW_MIN — draws will re-admit banned keys");
    }
    println!();

    // The currently open window: who is on the hook if it heals
    let full = chain.get_last_full_block(u64::MAX, None).expect("No full block");
    println!("=== Open window of full block {} ({}) ===", full.index, full.timestamp);
    let drawn = chain.get_block_signers(&full);
    let signed = |key: &Bytes| -> bool {
        (full.index + 1..=height).any(|i| &chain.get_block(i).unwrap().pub_key == key)
    };
    for key in &drawn {
        let (count, last_index, _) = stats(key);
        let status = if signed(key) { "signed this window" } else { "SILENT — banned if this window heals" };
        println!("  drawn {:?}: {} blocks, last authored {}, {}", key, count, last_index, status);
    }
    println!("is_locked: {}", chain.is_locked(&full));
    println!();

    // The standby pool a hypothetical next full block would see (bans applied)
    let mut fake = alfis::Block::new(None, Bytes::default(), Bytes::default(), SIGNER_DIFFICULTY);
    fake.index = height + 1;
    fake.timestamp = full.timestamp;
    let pool = chain.get_healing_pool(&fake);
    println!("=== Standby pool for the next full block (index {}) ===", fake.index);
    println!("Anchors: {:?}", &pool.anchors);
    println!("Recent:  {:?}", &pool.recent);
}

fn init_logger() {
    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};
    let _ = TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Stdout, ColorChoice::Auto);
}
