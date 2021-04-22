/// Represents a result of block check on block's arrival
#[derive(PartialEq)]
pub enum BlockQuality {
    Good,
    Twin,
    Future,
    Rewind,
    Bad,
    Fork,
}

#[derive(Debug)]
pub enum MineResult {
    Fine,
    WrongName,
    WrongData,
    WrongKey,
    WrongZone,
    NotOwned,
    Cooldown { time: i64 },
}

#[derive(Debug)]
pub struct Options {
    pub origin: String,
    pub version: u32,
}

impl Options {
    pub fn new(origin: String, version: u32) -> Self {
        Options { origin, version }
    }

    pub fn empty() -> Self {
        Options { origin: String::new(), version: 0 }
    }
}