use std::time::Duration;

pub const DB_VERSION: u32 = 0;
pub const CHAIN_VERSION: u32 = 0;

pub const ZONE_DIFFICULTY: u32 = 28;
pub const ZONE_MIN_DIFFICULTY: u32 = 22;
pub const SIGNER_DIFFICULTY: u32 = 16;
pub const KEYSTORE_DIFFICULTY: u32 = 23;

/// Blocks start to be signed starting from this index
pub const BLOCK_SIGNERS_START: u64 = 35;

/// How many signers are chosen for signing
pub const BLOCK_SIGNERS_ALL: u64 = 7;

/// Minimal signatures needed
pub const BLOCK_SIGNERS_MIN: u64 = 4;

/// Signers have 30 minutes to sign, after that time any owner of first 1000 block can add needed signature
pub const BLOCK_SIGNERS_TIME: i64 = 1800;

/// Limited Confidence depth
/// https://en.bitcoinwiki.org/wiki/Limited_Confidence_Proof-of-Activity
pub const LIMITED_CONFIDENCE_DEPTH: u64 = 4;

/// We start mining signing blocks after random delay, this is the max delay
pub const BLOCK_SIGNERS_START_RANDOM: i64 = 180;

/// Maximum zones in blockchain
pub const MAXIMUM_ZONES: usize = 10;

pub const NEW_DOMAINS_INTERVAL: i64 = 86400; // One day in seconds
pub const DOMAIN_LIFETIME: i64 = 86400 * 365; // One year

pub const ZONE_MAX_LENGTH: usize = 10;
pub const MAX_RECONNECTS: u32 = 5;

pub const DB_NAME: &str = "blockchain.db";
pub const CLASS_ZONE: &str = "zone";
pub const CLASS_DOMAIN: &str = "domain";
pub const ALFIS_DEBUG: &str = "ALFIS_DEBUG";

/// Public nodes listen port
pub const LISTEN_PORT: u16 = 4244;
pub const UI_REFRESH_DELAY_MS: u128 = 250;
pub const LOG_REFRESH_DELAY_SEC: u64 = 60;

pub const POLL_TIMEOUT: Option<Duration> = Some(Duration::from_millis(250));
pub const MAX_PACKET_SIZE: usize = 1 * 1024 * 1024; // 1 Mb
pub const MAX_READ_BLOCK_TIME: u128 = 500;
pub const MAX_IDLE_SECONDS: u64 = 180;
pub const MAX_NODES: usize = 15;
