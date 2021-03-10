/// Represents a result of block check on block's arrival
#[derive(PartialEq)]
pub enum BlockQuality {
    Good,
    Twin,
    Future,
    Bad,
    Fork,
}
