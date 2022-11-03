use std::time::Duration;

pub const DB_VERSION: u32 = 0;
pub const CHAIN_VERSION: u32 = 1;

pub const ORIGIN_DIFFICULTY: u32 = 28;
pub const DOMAIN_DIFFICULTY: u32 = 24;
pub const SIGNER_DIFFICULTY: u32 = 16;
pub const KEYSTORE_DIFFICULTY: u32 = 23;
pub const BLOCKS_WITHOUT_DISCOUNT: u64 = 4999;

/// Blocks start to be signed starting from this index
pub const BLOCK_SIGNERS_START: u64 = 35;

/// How many signers are chosen for signing
pub const BLOCK_SIGNERS_ALL: u64 = 7;

/// Minimal signatures needed
pub const BLOCK_SIGNERS_MIN: u64 = 4;

/// Limited Confidence depth
/// https://en.bitcoinwiki.org/wiki/Limited_Confidence_Proof-of-Activity
pub const LIMITED_CONFIDENCE_DEPTH: u64 = 4;

/// We start mining signing blocks after random delay, this is the max delay
pub const BLOCK_SIGNERS_START_RANDOM: i64 = 90;

pub const NEW_DOMAINS_INTERVAL: i64 = 86400; // One day in seconds
pub const ONE_WEEK: i64 = 86400 * 7; // One week in seconds
pub const DOMAIN_LIFETIME: i64 = 86400 * 365; // One year
/// Time for the owner to remine his domain and not to loose it
pub const DOMAIN_RENEW_TIME: i64 = 86400 * 30; // One month
pub const MAX_RECORDS: usize = 30;
pub const MAX_DATA_LEN: usize = 255;

pub const DB_NAME: &str = "blockchain.db";
pub const CLASS_ORIGIN: &str = "origin";
pub const CLASS_DOMAIN: &str = "domain";
pub const ALFIS_DEBUG: &str = "ALFIS_DEBUG";
pub const ALFIS_TRACE: &str = "ALFIS_TRACE";

/// Public nodes listen port
pub const LISTEN_PORT: u16 = 4244;
pub const UI_REFRESH_DELAY_MS: u128 = 500;
pub const LOG_REFRESH_DELAY_SEC: u64 = 60;

pub const POLL_TIMEOUT: Option<Duration> = Some(Duration::from_millis(200));
pub const WAIT_FOR_INTERNET: Duration = Duration::from_secs(10);
/// We start syncing blocks only when we got 4 and more connected nodes
pub const MIN_CONNECTED_NODES_START_SYNC: usize = 4;
pub const MAX_READ_BLOCK_TIME: u128 = 100;
pub const MAX_RECONNECTS: u32 = 5;
pub const MAX_IDLE_SECONDS: u64 = 180;
pub const MAX_NODES: usize = 15;
