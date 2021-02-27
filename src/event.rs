#[derive(Clone, PartialEq, Debug)]
pub enum Event {
    MinerStarted,
    MinerStopped,
    KeyGeneratorStarted,
    KeyGeneratorStopped,
    KeyCreated { path: String, public: String },
    KeyLoaded { path: String, public: String },
    KeySaved { path: String, public: String },
    NewBlockReceived,
    BlockchainChanged,
    ActionStopMining,
    StatsCount { nodes: usize, blocks: u64 },
    SyncStarted { have: u64, height: u64 },
    ActionIdle,
}
