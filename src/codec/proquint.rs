//! Proquint IPv6 codec for the `.q6` zone.
//!
//! Names in `.q6` are not registered on the blockchain — they ARE the address:
//! each hextet is one standard proquint (Wilkerson's PRO-nounceable
//! QUINT-uplets): five letters in consonant-vowel-consonant-vowel-consonant
//! form encoding 16 bits (`lusab` <-> `7f00`). Eight proquints make an
//! address; hyphens between them are cosmetic — any token whose length is a
//! multiple of five is read as a run of proquints.
//!
//! A token between hyphens is a gap — the `::` analog — when it is NOT a
//! clean run of proquints: wrong length, letters outside the tables, digits,
//! anything. It stands for a run of zero hextets whose length is derived,
//! never spelled (`bamag-dohah-null-babad` and `bamag-dohah-x-babad` are the
//! same address). At most one gap per name. [`GAP_WORDS`] lists the synonyms
//! the encoder picks from.
//!
//! Reverse (PTR/`ip6.arpa`) mapping is out of scope.

use std::net::Ipv6Addr;

use derive_more::{Display, Error};
use rand::RngExt;

/// WIRE FORMAT — never reorder, never change. The standard proquint
/// alphabet: 16 consonants carrying 4 bits each.
const CONSONANTS: [u8; 16] = *b"bdfghjklmnprstvz";
/// WIRE FORMAT — never reorder, never change. 4 vowels carrying 2 bits each.
const VOWELS: [u8; 4] = *b"aiou";

/// Interchangeable synonyms for a collapsed run of zero hextets. Decoding
/// does not need this list — any non-proquint token is a gap — but none of
/// these may ever become a valid proquint run (the `.v6` list's "nihil" is
/// excluded exactly because n-i-h-i-l IS one; enforced by
/// `gap_words_are_not_valid_proquints` test).
pub const GAP_WORDS: [&str; 7] = ["abyss", "blank", "empty", "hollow", "null", "ygg", "zilch"];

fn consonant_index(letter: u8) -> Option<u16> {
    CONSONANTS.iter().position(|c| *c == letter).map(|i| i as u16)
}

fn vowel_index(letter: u8) -> Option<u16> {
    VOWELS.iter().position(|v| *v == letter).map(|i| i as u16)
}

/// One CVCVC chunk as a hextet, `None` when it is not a proquint.
fn chunk_to_hextet(chunk: &[u8]) -> Option<u16> {
    let c1 = consonant_index(chunk[0])?;
    let v1 = vowel_index(chunk[1])?;
    let c2 = consonant_index(chunk[2])?;
    let v2 = vowel_index(chunk[3])?;
    let c3 = consonant_index(chunk[4])?;
    Some((c1 << 12) | (v1 << 10) | (c2 << 6) | (v2 << 4) | c3)
}

/// A whole token as a run of hextets, `None` when it is not a clean run of
/// proquints — which makes it a gap.
fn token_to_hextets(token: &str) -> Option<Vec<u16>> {
    let bytes = token.as_bytes();
    if bytes.len() % 5 != 0 {
        return None;
    }
    bytes.chunks_exact(5).map(chunk_to_hextet).collect()
}

/// Five letters for hextet `group` (0-7) of an address.
fn group_str(segments: &[u16; 8], group: usize) -> String {
    let hextet = segments[group];
    let letters = [
        CONSONANTS[(hextet >> 12) as usize & 0xF],
        VOWELS[(hextet >> 10) as usize & 0x3],
        CONSONANTS[(hextet >> 6) as usize & 0xF],
        VOWELS[(hextet >> 4) as usize & 0x3],
        CONSONANTS[hextet as usize & 0xF]
    ];
    String::from_utf8(letters.to_vec()).unwrap()
}

#[derive(Debug, Display, Error, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    Empty,
    InvalidChar,
    EmptyToken,
    MultipleGaps,
    BadLength
}

/// Decodes a `.q6` name (without the zone suffix) into an IPv6 address.
pub fn decode(input: &str) -> Result<Ipv6Addr, DecodeError> {
    let name = input.to_ascii_lowercase();
    if name.is_empty() {
        return Err(DecodeError::Empty);
    }
    if !name.bytes().all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err(DecodeError::InvalidChar);
    }
    let mut before: Vec<u16> = Vec::with_capacity(8);
    let mut after: Vec<u16> = Vec::with_capacity(8);
    let mut seen_gap = false;
    for token in name.split('-') {
        if token.is_empty() {
            return Err(DecodeError::EmptyToken);
        }
        // Any token that is not a clean run of proquints is a gap
        match token_to_hextets(token) {
            Some(hextets) => {
                let groups = if seen_gap { &mut after } else { &mut before };
                groups.extend(hextets);
                if before.len() + after.len() > 8 {
                    return Err(DecodeError::BadLength);
                }
            }
            None => {
                if seen_gap {
                    return Err(DecodeError::MultipleGaps);
                }
                seen_gap = true;
            }
        }
    }
    let mut segments = [0u16; 8];
    if seen_gap {
        // A gap must collapse at least one hextet
        if before.len() + after.len() > 7 {
            return Err(DecodeError::BadLength);
        }
        segments[..before.len()].copy_from_slice(&before);
        segments[8 - after.len()..].copy_from_slice(&after);
    } else {
        if before.len() != 8 {
            return Err(DecodeError::BadLength);
        }
        segments.copy_from_slice(&before);
    }
    Ok(Ipv6Addr::from(segments))
}

/// Canonical form: 8 proquints joined by hyphens.
pub fn encode(addr: &Ipv6Addr) -> String {
    let segments = addr.segments();
    let groups: Vec<String> = (0..8).map(|i| group_str(&segments, i)).collect();
    groups.join("-")
}

/// Like [`encode`], but the longest run of zero hextets (leftmost on tie,
/// RFC 5952 style) is collapsed into a randomly chosen synonym from
/// [`GAP_WORDS`] — they all decode identically. A run of a single hextet is
/// not collapsed — a gap word is not shorter than one proquint.
pub fn encode_with_gap(addr: &Ipv6Addr) -> String {
    let segments = addr.segments();
    let mut best_start = 0;
    let mut best_len = 0;
    let mut run_start = 0;
    let mut run_len = 0;
    for (i, segment) in segments.iter().enumerate() {
        if *segment == 0 {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len > best_len {
                best_start = run_start;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    if best_len < 2 {
        return encode(addr);
    }
    let word = GAP_WORDS[rand::rng().random_range(0..GAP_WORDS.len())];
    let mut parts: Vec<String> = (0..best_start).map(|i| group_str(&segments, i)).collect();
    parts.push(String::from(word));
    parts.extend((best_start + best_len..8).map(|i| group_str(&segments, i)));
    parts.join("-")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    fn addr(s: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(s).unwrap()
    }

    fn hextet_str(hextet: u16) -> String {
        let mut segments = [0u16; 8];
        segments[0] = hextet;
        group_str(&segments, 0)
    }

    #[test]
    fn all_hextets_roundtrip_uniquely() {
        let mut seen = HashSet::new();
        for hextet in 0..=u16::MAX {
            let word = hextet_str(hextet);
            assert!(seen.insert(word.clone()), "Duplicate proquint '{}'", word);
            assert_eq!(token_to_hextets(&word), Some(vec![hextet]));
        }
    }

    #[test]
    fn golden_anchors() {
        // These pin the wire format to Wilkerson's reference proquints:
        // if any of them fails, the alphabet or bit layout changed
        assert_eq!(hextet_str(0x0000), "babab");
        assert_eq!(hextet_str(0x0001), "babad");
        assert_eq!(hextet_str(0x7F00), "lusab"); // 127.0.0.1 == "lusab-babad"
        assert_eq!(hextet_str(0x3F54), "gutih"); // 63.84.220.193 == "gutih-tugad"
        assert_eq!(hextet_str(0xDCC1), "tugad");
        assert_eq!(hextet_str(0x0200), "bamab"); // the Yggdrasil prefix
        assert_eq!(hextet_str(0xFFFF), "zuzuz");
    }

    #[test]
    fn gap_words_are_not_valid_proquints() {
        let mut seen = HashSet::new();
        for word in GAP_WORDS {
            assert!(word.bytes().all(|b| b.is_ascii_lowercase()), "Non-letter in '{}'", word);
            assert!(seen.insert(word), "Duplicate gap word '{}'", word);
            assert_eq!(token_to_hextets(word), None, "Gap word '{}' reads as proquints", word);
        }
        // The .v6 synonym "nihil" is excluded from this list for a reason
        assert_eq!(token_to_hextets("nihil"), Some(vec![0x9517]));
    }

    /// Splits a gapped encoding into (tokens, index of the gap word).
    fn gap_split(encoded: &str) -> (Vec<&str>, usize) {
        let tokens: Vec<&str> = encoded.split('-').collect();
        let gap_at = tokens.iter().position(|t| GAP_WORDS.contains(t))
            .unwrap_or_else(|| panic!("No gap word in '{}'", encoded));
        (tokens, gap_at)
    }

    #[test]
    fn roundtrip_all_zeros() {
        let zero = addr("::");
        assert_eq!(encode(&zero), "babab-babab-babab-babab-babab-babab-babab-babab");
        // The whole address collapses into a single gap word
        assert!(GAP_WORDS.contains(&encode_with_gap(&zero).as_str()));
        assert_eq!(decode(&encode(&zero)), Ok(zero));
        assert_eq!(decode("ygg"), Ok(zero));
    }

    #[test]
    fn roundtrip_all_ones() {
        let ones = Ipv6Addr::from([0xffu8; 16]);
        assert_eq!(encode(&ones), "zuzuz-zuzuz-zuzuz-zuzuz-zuzuz-zuzuz-zuzuz-zuzuz");
        assert_eq!(encode_with_gap(&ones), encode(&ones));
        assert_eq!(decode(&encode(&ones)), Ok(ones));
    }

    #[test]
    fn roundtrip_yggdrasil() {
        let ygg = addr("203:1904::1");
        assert_eq!(encode(&ygg), "bamag-dohah-babab-babab-babab-babab-babab-babad");
        let gapped = encode_with_gap(&ygg);
        let (tokens, gap_at) = gap_split(&gapped);
        assert_eq!((tokens.len(), gap_at), (4, 2));
        assert_eq!((tokens[0], tokens[1], tokens[3]), ("bamag", "dohah", "babad"));
        assert_eq!(decode(&encode(&ygg)), Ok(ygg));
        assert_eq!(decode(&encode_with_gap(&ygg)), Ok(ygg));

        let real = addr("200:6fc8:7a9c:d4b0:1122:3344:5566:7788");
        assert_eq!(decode(&encode(&real)), Ok(real));
        assert_eq!(decode(&encode_with_gap(&real)), Ok(real));
    }

    #[test]
    fn roundtrip_edge_runs() {
        // Leading run: the gap word comes first
        let leading = encode_with_gap(&addr("::1"));
        let (tokens, gap_at) = gap_split(&leading);
        assert_eq!((tokens.len(), gap_at, tokens[1]), (2, 0, "babad"));
        assert_eq!(decode("ygg-babad"), Ok(addr("::1")));
        // Trailing run: the gap word comes last
        let trailing = encode_with_gap(&addr("1::"));
        let (tokens, gap_at) = gap_split(&trailing);
        assert_eq!((tokens.len(), gap_at, tokens[0]), (2, 1, "babad"));
        assert_eq!(decode("babad-ygg"), Ok(addr("1::")));
        let interior = addr("1:2::3:4");
        assert_eq!(decode(&encode_with_gap(&interior)), Ok(interior));
    }

    #[test]
    fn hyphen_insensitivity() {
        // Hyphens are cosmetic as long as they fall between proquints
        let tail = "-babab-babab-babab-babab-babab-babab";
        let expected = decode(&format!("bamag-dohah{}", tail)).unwrap();
        for name in [
            format!("bamagdohah{}", tail),
            format!("bamag-dohahbabab{}", "-babab".repeat(5)),
        ] {
            assert_eq!(decode(&name), Ok(expected), "Spelling '{}' diverged", name);
        }
        // Fully hyphen-free 40-letter run
        let stripped: String = format!("bamag-dohah{}", tail).chars().filter(|c| *c != '-').collect();
        assert_eq!(decode(&stripped), Ok(expected));
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(decode("BAMAG-DOHAH-YGG-BABAD"), decode("bamag-dohah-ygg-babad"));
        assert_eq!(decode("BaMaG-Dohah-Ygg-Babad"), Ok(addr("203:1904::1")));
    }

    #[test]
    fn any_non_proquint_token_is_a_gap() {
        let expected = decode("bamag-dohah-ygg-babad").unwrap();
        // All list synonyms...
        for gap in GAP_WORDS {
            assert_eq!(decode(&format!("bamag-dohah-{}-babad", gap)), Ok(expected), "Gap '{}' diverged", gap);
        }
        // ...too short, too long, right length but not CVCVC, digits
        for gap in ["x", "bab", "babababab", "zzzzz", "aabab", "1234a", "77777", "notaproquint"] {
            assert_eq!(decode(&format!("bamag-dohah-{}-babad", gap)), Ok(expected), "Gap '{}' diverged", gap);
        }
        // A lone gap token is a gap of all eight groups
        assert_eq!(decode("abyss"), Ok(addr("::")));
        assert_eq!(decode("null"), Ok(addr("::")));
    }

    #[test]
    fn gap_positions() {
        // Leading, interior, trailing
        assert_eq!(decode("ygg-babad-babad"), Ok(addr("::1:1")));
        assert_eq!(decode("babad-ygg-babad"), Ok(addr("1::1")));
        assert_eq!(decode("babad-babad-ygg"), Ok(addr("1:1::")));
        // N == 1 is accepted when decoding
        assert_eq!(decode("babad-babab-babab-babab-babab-babab-babab-ygg"), Ok(addr("1::")));
    }

    #[test]
    fn single_zero_group_not_collapsed() {
        let one_zero = addr("1:0:1:1:1:1:1:1");
        assert_eq!(encode_with_gap(&one_zero), encode(&one_zero));
        assert!(encode_with_gap(&one_zero).contains("babab"));
    }

    #[test]
    fn leftmost_longest_run_wins() {
        // Second run is longer — it gets collapsed
        let interior = encode_with_gap(&addr("0:0:1:0:0:0:1:1"));
        let (tokens, gap_at) = gap_split(&interior);
        assert_eq!((tokens.len(), gap_at), (6, 3));
        // Equal runs — the leftmost one wins
        let tied = encode_with_gap(&addr("0:0:1:0:0:1:1:1"));
        let (tokens, gap_at) = gap_split(&tied);
        assert_eq!((tokens.len(), gap_at), (7, 0));
    }

    #[test]
    fn gap_word_is_randomized() {
        // 100 draws from 7 synonyms: all-identical is (1/7)^99 — never happens
        let zero = addr("::");
        let seen: HashSet<String> = (0..100).map(|_| encode_with_gap(&zero)).collect();
        assert!(seen.len() > 1, "encode_with_gap always picked '{}'", seen.iter().next().unwrap());
        assert!(seen.iter().all(|w| GAP_WORDS.contains(&w.as_str())));
    }

    #[test]
    fn rejects() {
        let full = "babab-babab-babab-babab-babab-babab-babab-babab";
        assert_eq!(decode(""), Err(DecodeError::Empty));
        assert_eq!(decode(&format!("-{}", full)), Err(DecodeError::EmptyToken));
        assert_eq!(decode(&format!("{}-", full)), Err(DecodeError::EmptyToken));
        assert_eq!(decode("babab--babab"), Err(DecodeError::EmptyToken));
        assert_eq!(decode("babab.babab"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("bаbаb"), Err(DecodeError::InvalidChar)); // Cyrillic lookalikes
        assert_eq!(decode("ygg-babab-ygg"), Err(DecodeError::MultipleGaps));
        assert_eq!(decode("ygg-cat"), Err(DecodeError::MultipleGaps));
        assert_eq!(decode("null-babab-hollow"), Err(DecodeError::MultipleGaps));
        assert_eq!(decode(&format!("{}-ygg", full)), Err(DecodeError::BadLength)); // N < 1
        assert_eq!(decode("babab"), Err(DecodeError::BadLength)); // Too short, no gap
        assert_eq!(decode(&"babab".repeat(9)), Err(DecodeError::BadLength)); // Too long
        assert_eq!(decode(&vec!["babab"; 7].join("-")), Err(DecodeError::BadLength)); // 7 groups, no gap
    }

    #[test]
    fn fuzz_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0xA1F15);
        for _ in 0..10_000 {
            let mut bytes = [0u8; 16];
            rng.fill(&mut bytes);
            // Zero out a random span of hextets on half the samples to exercise the gap
            if rng.random_bool(0.5) {
                let start = rng.random_range(0..8usize);
                let len = rng.random_range(0..=8 - start);
                bytes[start * 2..(start + len) * 2].fill(0);
            }
            let a = Ipv6Addr::from(bytes);
            assert_eq!(decode(&encode(&a)), Ok(a));
            assert_eq!(decode(&encode_with_gap(&a)), Ok(a));
            // Hyphens are cosmetic between proquints: strip them all, then
            // put one back at a random proquint boundary
            let stripped: String = encode(&a).chars().filter(|c| *c != '-').collect();
            assert_eq!(decode(&stripped), Ok(a));
            let mut spelling = stripped.clone();
            spelling.insert(rng.random_range(1..8) * 5, '-');
            assert_eq!(decode(&spelling), Ok(a));
        }
    }
}
