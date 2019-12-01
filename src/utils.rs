
/// Convert bytes array to HEX format
pub fn to_hex(buf: &[u8]) -> String {
    let mut result = String::new();
    for x in buf.iter() {
        result.push_str(&format!("{:01$X}", x, 2));
    }
    result
}

/// There is no default PartialEq implementation for arrays > 32 in size
pub fn same_hash(left: &[u8], right: &[u8]) -> bool {
    for (x, y) in left.iter().zip(right) {
        if x != y {
            return false;
        }
    }
    true
}