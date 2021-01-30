#[derive(Clone, PartialEq, Debug)]
pub enum Event {
    MinerStarted,
    MinerStopped,
    KeyGeneratorStarted,
    KeyGeneratorStopped,
    NewBlockReceived,
    BlockchainChanged,
    ActionStopMining,
}
