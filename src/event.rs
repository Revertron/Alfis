#[derive(Clone, PartialEq, Debug)]
pub enum Event {
    MinerStarted,
    MinerStopped { success: bool, full: bool },
    MinerStats { thread: usize, speed: u64, max_diff: u32, target_diff: u32 },
    KeyGeneratorStarted,
    KeyGeneratorStopped,
    KeyCreated { path: String, public: String, hash: String },
    KeyLoaded { path: String, public: String, hash: String },
    KeySaved { path: String, public: String, hash: String },
    ZonesChanged,
    NewBlockReceived,
    BlockchainChanged { index: u64 },
    ActionStopMining,
    ActionQuit,
    NetworkStatus { nodes: usize, blocks: u64 },
    Syncing { have: u64, height: u64 },
    SyncFinished,
}
