#[derive(Clone, PartialEq, Debug)]
pub enum Event {
    MinerStarted,
    MinerStopped { success: bool, full: bool },
    MinerStats { thread: u32, speed: u64, max_diff: u32, target_diff: u32 },
    KeyGeneratorStarted,
    KeyGeneratorStopped,
    KeyCreated { path: String, public: String, hash: String },
    KeyLoaded { path: String, public: String, hash: String },
    KeySaved { path: String, public: String, hash: String },
    NewBlockReceived,
    BlockchainChanged { index: u64 },
    ActionStopMining,
    ActionQuit,
    NetworkStatus { blocks: u64, domains: i64, keys: i64, nodes: usize },
    /// Somebody serves a chain forked beyond LIMITED_CONFIDENCE_DEPTH (RFC-0002, section 3.7)
    ForkDetected { index: u64, hash: String },
    /// Dead drawn signers of a healed window were banned from future draws (RFC-0003, section 3.7)
    KeysBanned { window: u64, keys: String },
    Syncing { have: u64, height: u64 },
    SyncFinished,
    Error { text: String }
}
