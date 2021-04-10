pub const DB_VERSION: u32 = 0;
pub const CHAIN_VERSION: u32 = 0;

pub const ZONE_DIFFICULTY: u32 = 28;
pub const ZONE_MIN_DIFFICULTY: u32 = 22;
pub const LOCKER_DIFFICULTY: u32 = 16;
pub const KEYSTORE_DIFFICULTY: u32 = 23;

pub const LOCKER_BLOCK_START: u64 = 35;
pub const LOCKER_BLOCK_LOCKERS: u64 = 7;
pub const LOCKER_BLOCK_SIGNS: u64 = 4;
pub const LOCKER_BLOCK_TIME: i64 = 300;
pub const LOCKER_BLOCK_INTERVAL: u64 = 50;

pub const NEW_DOMAINS_INTERVAL: i64 = 86400; // One day in seconds
pub const DOMAIN_LIFETIME: i64 = 86400 * 365; // One year

pub const ZONE_MAX_LENGTH: usize = 10;
pub const MAX_RECONNECTS: u32 = 5;

pub const CLASS_ZONE: &str = "zone";
pub const CLASS_DOMAIN: &str = "domain";