use crate::Bytes;

#[derive(Clone, PartialEq, Debug)]
pub enum Event {
    MinerStarted,
    MinerStopped,
    KeyGeneratorStarted,
    KeyGeneratorStopped,
    KeyCreated { path: String, public: String, hash: String },
    KeyLoaded { path: String, public: String, hash: String },
    KeySaved { path: String, public: String, hash: String },
    NewBlockReceived,
    BlockchainChanged { index: u64 },
    ActionStopMining,
    ActionMineLocker { index: u64, hash: Bytes },
    NetworkStatus { nodes: usize, blocks: u64 },
    Syncing { have: u64, height: u64 },
    SyncFinished,
}
