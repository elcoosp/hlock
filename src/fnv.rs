const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

#[must_use]
pub fn calculate(data: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in data.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        assert_eq!(calculate(""), 14_695_981_039_346_656_037);
    }

    #[test]
    fn test_known_string() {
        assert_eq!(calculate("lodash@4.17.21"), 12_882_612_609_629_450_877);
    }
}
