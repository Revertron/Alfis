#[derive(Clone, PartialEq, Debug)]
pub enum Event {
    MinerStarted,
    MinerStopped,
    KeyGeneratorStarted,
    KeyGeneratorStopped,
    KeyCreated {path: String, public: String},
    KeyLoaded {path: String, public: String},
    KeySaved {path: String, public: String},
    NewBlockReceived,
    BlockchainChanged,
    ActionStopMining,
}
