/// Represents a result of block check on block's arrival
#[derive(PartialEq)]
pub enum BlockQuality {
    Good,
    Twin,
    Future,
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
    Cooldown { time: i64 }
}