//! Syllabic IPv6 codec for the `.v6` zone.
//!
//! Names in `.v6` are not registered on the blockchain — they ARE the address:
//! 16 bytes -> 16 two-letter syllables -> 32 letters, where two syllables form
//! one hextet, mirroring IPv6 groups (`ygpo-napu` <-> `0203:1904`). Hyphens
//! between syllables are purely cosmetic and may fall anywhere between bytes.
//!
//! A token between hyphens is a gap — the `::` analog — when it is one of the
//! `GAP_WORDS` synonyms or has ODD length: it stands for a run of zero hextets
//! whose length is derived, never spelled (`ygpo-napu-ygg-pape`,
//! `ygpo-napu-null-pape` and `ygpo-napu-x-pape` are the same address). At most
//! one gap per name.
//!
//! A two-letter chunk containing a digit is read as a hex byte, so plain hex
//! spelling works too: `2001-0db8-85a3-0000-0000-8a2e-0370-7334` — and mixes
//! with syllables freely. Pure-letter chunks are ALWAYS syllables: `fe` is the
//! syllable "fe", not the byte 0xFE.
//!
//! Reverse (PTR/`ip6.arpa`) mapping is out of scope.

use std::net::Ipv6Addr;

use derive_more::{Display, Error};
use lazy_static::lazy_static;
use rand::RngExt;

/// WIRE FORMAT — never reorder, never change. Together with `VOWELS`,
/// `CLUSTERS` and `OVERRIDES` this list defines the byte <-> syllable bijection.
const CONSONANTS: [u8; 21] = *b"ptksmnlrdbgfvhjwyzcqx";
/// WIRE FORMAT — never reorder, never change.
const VOWELS: [u8; 5] = *b"aeiou";
/// WIRE FORMAT — never reorder, never change. Exactly 46 two-consonant clusters
/// filling syllable indices 210-255.
const CLUSTERS: [[u8; 2]; 46] = [
    *b"bl", *b"br", *b"ch", *b"ck", *b"cl", *b"cr", *b"ct", *b"dr", *b"fl", *b"fr",
    *b"gl", *b"gr", *b"ft", *b"kl", *b"kr", *b"ld", *b"lf", *b"lk", *b"lm", *b"lp",
    *b"lt", *b"mp", *b"nd", *b"ng", *b"nk", *b"nt", *b"pl", *b"pr", *b"pt", *b"rd",
    *b"rk", *b"rm", *b"rn", *b"rt", *b"sh", *b"sk", *b"sl", *b"sm", *b"sn", *b"sp",
    *b"st", *b"sw", *b"th", *b"tr", *b"tw", *b"wh"
];
/// WIRE FORMAT — never change. Hand-tuned swaps applied after the formula
/// blocks: Yggdrasil branding (0200::/7 names start with "yg", 0224:... reads
/// "yggd..."), with the displaced formula syllables re-housed at cluster slots.
const OVERRIDES: [(u8, [u8; 2]); 4] = [
    (0x02, *b"yg"), // was "pi", every 02xx Yggdrasil name now starts with "yg"
    (0x24, *b"gd"), // was "re"
    (216, *b"pi"),  // was "ct"
    (222, *b"re")   // was "ft"
];

/// WIRE FORMAT — never change. Interchangeable synonyms for a collapsed run of
/// zero hextets. Odd-length words are gaps anyway; the even-length ones only
/// work through this table and must not decompose entirely into valid
/// syllables (enforced by `gap_words_do_not_decompose` test).
pub const GAP_WORDS: [&str; 8] = ["abyss", "blank", "empty", "hollow", "nihil", "null", "ygg", "zilch"];

lazy_static! {
    /// Index == byte value: CV block (0-104), VC block (105-209), CC block (210-255),
    /// then `OVERRIDES` on top.
    static ref SYLLABLES: [[u8; 2]; 256] = build_syllables();
    /// Reverse lookup indexed by `(first - b'a', second - b'a')`.
    static ref REVERSE: [[Option<u8>; 26]; 26] = {
        let mut table = [[None; 26]; 26];
        for (index, syllable) in SYLLABLES.iter().enumerate() {
            table[(syllable[0] - b'a') as usize][(syllable[1] - b'a') as usize] = Some(index as u8);
        }
        table
    };
}

fn build_syllables() -> [[u8; 2]; 256] {
    let mut table = [[0u8; 2]; 256];
    let mut index = 0;
    for c in CONSONANTS {
        for v in VOWELS {
            table[index] = [c, v];
            index += 1;
        }
    }
    for v in VOWELS {
        for c in CONSONANTS {
            table[index] = [v, c];
            index += 1;
        }
    }
    for cluster in CLUSTERS {
        table[index] = cluster;
        index += 1;
    }
    for (index, syllable) in OVERRIDES {
        table[index as usize] = syllable;
    }
    table
}

fn syllable_to_byte(first: u8, second: u8) -> Option<u8> {
    REVERSE[(first - b'a') as usize][(second - b'a') as usize]
}

fn hex_value(letter: u8) -> Option<u8> {
    match letter {
        b'0'..=b'9' => Some(letter - b'0'),
        b'a'..=b'f' => Some(letter - b'a' + 10),
        _ => None
    }
}

/// Four letters for hextet `group` (0-7) of an address.
fn group_str(octets: &[u8; 16], group: usize) -> String {
    let first = SYLLABLES[octets[group * 2] as usize];
    let second = SYLLABLES[octets[group * 2 + 1] as usize];
    String::from_utf8(vec![first[0], first[1], second[0], second[1]]).unwrap()
}

#[derive(Debug, Display, Error, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    Empty,
    InvalidChar,
    EmptyToken,
    UnknownSyllable,
    BadHex,
    MultipleGaps,
    GapNotOnGroupBoundary,
    BadLength
}

/// Decodes a `.v6` name (without the zone suffix) into an IPv6 address.
pub fn decode(input: &str) -> Result<Ipv6Addr, DecodeError> {
    let name = input.to_ascii_lowercase();
    if name.is_empty() {
        return Err(DecodeError::Empty);
    }
    if !name.bytes().all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err(DecodeError::InvalidChar);
    }
    let mut before: Vec<u8> = Vec::with_capacity(16);
    let mut after: Vec<u8> = Vec::with_capacity(16);
    let mut seen_gap = false;
    for token in name.split('-') {
        if token.is_empty() {
            return Err(DecodeError::EmptyToken);
        }
        // Gap words match whole tokens only, and any odd-length token is a gap too
        if GAP_WORDS.contains(&token) || token.len() % 2 != 0 {
            if seen_gap {
                return Err(DecodeError::MultipleGaps);
            }
            seen_gap = true;
            continue;
        }
        let bytes = if seen_gap { &mut after } else { &mut before };
        for pair in token.as_bytes().chunks_exact(2) {
            // A chunk with a digit is a hex byte, pure letters are a syllable
            let byte = if pair[0].is_ascii_digit() || pair[1].is_ascii_digit() {
                match (hex_value(pair[0]), hex_value(pair[1])) {
                    (Some(high), Some(low)) => (high << 4) | low,
                    _ => return Err(DecodeError::BadHex)
                }
            } else {
                match syllable_to_byte(pair[0], pair[1]) {
                    Some(byte) => byte,
                    None => return Err(DecodeError::UnknownSyllable)
                }
            };
            bytes.push(byte);
        }
        if before.len() + after.len() > 16 {
            return Err(DecodeError::BadLength);
        }
    }
    let mut octets = [0u8; 16];
    if seen_gap {
        // The collapsed run consists of whole hextets, so each side must hold whole hextets too
        if before.len() % 2 != 0 || after.len() % 2 != 0 {
            return Err(DecodeError::GapNotOnGroupBoundary);
        }
        // A gap must collapse at least one hextet
        if before.len() + after.len() > 14 {
            return Err(DecodeError::BadLength);
        }
        octets[..before.len()].copy_from_slice(&before);
        octets[16 - after.len()..].copy_from_slice(&after);
    } else {
        if before.len() != 16 {
            return Err(DecodeError::BadLength);
        }
        octets.copy_from_slice(&before);
    }
    Ok(Ipv6Addr::from(octets))
}

/// Canonical form: 16 syllables, hyphens on hextet boundaries.
pub fn encode(addr: &Ipv6Addr) -> String {
    let octets = addr.octets();
    let groups: Vec<String> = (0..8).map(|i| group_str(&octets, i)).collect();
    groups.join("-")
}

/// Like [`encode`], but the longest run of zero hextets (leftmost on tie,
/// RFC 5952 style) is collapsed into a randomly chosen synonym from
/// [`GAP_WORDS`] — they all decode identically. A run of a single hextet is
/// not collapsed — a gap word is not shorter than one group.
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
    let octets = addr.octets();
    let word = GAP_WORDS[rand::rng().random_range(0..GAP_WORDS.len())];
    let mut parts: Vec<String> = (0..best_start).map(|i| group_str(&octets, i)).collect();
    parts.push(String::from(word));
    parts.extend((best_start + best_len..8).map(|i| group_str(&octets, i)));
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

    #[test]
    fn table_has_256_unique_two_letter_syllables() {
        let mut seen = HashSet::new();
        for syllable in SYLLABLES.iter() {
            assert!(syllable.iter().all(|b| b.is_ascii_lowercase()), "Non-letter in {:?}", syllable);
            assert!(seen.insert(*syllable), "Duplicate syllable {:?}", syllable);
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn reverse_table_consistent() {
        for (index, syllable) in SYLLABLES.iter().enumerate() {
            assert_eq!(syllable_to_byte(syllable[0], syllable[1]), Some(index as u8));
        }
    }

    #[test]
    fn golden_anchors() {
        // These pin the wire format: if any of them fails, the table was reordered
        assert_eq!(&SYLLABLES[0x00], b"pa");
        assert_eq!(&SYLLABLES[0x02], b"yg"); // Yggdrasil branding override
        assert_eq!(&SYLLABLES[0x03], b"po");
        assert_eq!(&SYLLABLES[0x19], b"na");
        assert_eq!(&SYLLABLES[0x24], b"gd"); // 0224:... reads "yggd..."
        assert_eq!(&SYLLABLES[104], b"xu");
        assert_eq!(&SYLLABLES[105], b"ap");
        assert_eq!(&SYLLABLES[209], b"ux");
        assert_eq!(&SYLLABLES[210], b"bl");
        assert_eq!(&SYLLABLES[216], b"pi"); // re-housed by the overrides
        assert_eq!(&SYLLABLES[222], b"re"); // re-housed by the overrides
        assert_eq!(&SYLLABLES[255], b"wh");
    }

    #[test]
    fn gap_words_do_not_decompose() {
        let mut seen = HashSet::new();
        for word in GAP_WORDS {
            assert!(word.bytes().all(|b| b.is_ascii_lowercase()), "Non-letter in '{}'", word);
            assert!(seen.insert(word), "Duplicate gap word '{}'", word);
            // Odd-length words are gaps by length, even-length ones must not read as syllables
            let bytes = word.as_bytes();
            let decomposes = bytes.len() % 2 == 0
                && bytes.chunks_exact(2).all(|pair| syllable_to_byte(pair[0], pair[1]).is_some());
            assert!(!decomposes, "Gap word '{}' decomposes into syllables", word);
        }
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
        assert_eq!(encode(&zero), "papa-papa-papa-papa-papa-papa-papa-papa");
        // The whole address collapses into a single gap word
        assert!(GAP_WORDS.contains(&encode_with_gap(&zero).as_str()));
        assert_eq!(decode(&encode(&zero)), Ok(zero));
        assert_eq!(decode("ygg"), Ok(zero));
    }

    #[test]
    fn roundtrip_all_ones() {
        let ones = Ipv6Addr::from([0xffu8; 16]);
        assert_eq!(encode(&ones), "whwh-whwh-whwh-whwh-whwh-whwh-whwh-whwh");
        assert_eq!(encode_with_gap(&ones), encode(&ones));
        assert_eq!(decode(&encode(&ones)), Ok(ones));
    }

    #[test]
    fn roundtrip_yggdrasil() {
        let ygg = addr("203:1904::1");
        assert_eq!(encode(&ygg), "ygpo-napu-papa-papa-papa-papa-papa-pape");
        let gapped = encode_with_gap(&ygg);
        let (tokens, gap_at) = gap_split(&gapped);
        assert_eq!((tokens.len(), gap_at), (4, 2));
        assert_eq!((tokens[0], tokens[1], tokens[3]), ("ygpo", "napu", "pape"));
        assert_eq!(decode(&encode(&ygg)), Ok(ygg));
        assert_eq!(decode(&encode_with_gap(&ygg)), Ok(ygg));
        // 0224:... names read "yggd..."
        assert!(encode(&addr("224::1")).starts_with("yggd"));

        let real = addr("200:6fc8:7a9c:d4b0:1122:3344:5566:7788");
        assert_eq!(decode(&encode(&real)), Ok(real));
        assert_eq!(decode(&encode_with_gap(&real)), Ok(real));
    }

    #[test]
    fn roundtrip_edge_runs() {
        // Leading run: the gap word comes first
        let leading = encode_with_gap(&addr("::1"));
        let (tokens, gap_at) = gap_split(&leading);
        assert_eq!((tokens.len(), gap_at, tokens[1]), (2, 0, "pape"));
        assert_eq!(decode("ygg-pape"), Ok(addr("::1")));
        // Trailing run: the gap word comes last
        let trailing = encode_with_gap(&addr("1::"));
        let (tokens, gap_at) = gap_split(&trailing);
        assert_eq!((tokens.len(), gap_at, tokens[0]), (2, 1, "pape"));
        assert_eq!(decode("pape-ygg"), Ok(addr("1::")));
        let interior = addr("1:2::3:4");
        assert_eq!(decode(&encode_with_gap(&interior)), Ok(interior));
    }

    #[test]
    fn hyphen_insensitivity() {
        let tail = "-papa-papa-papa-papa-papa-papa";
        let expected = decode(&format!("pona-dero{}", tail)).unwrap();
        for name in [
            format!("ponadero{}", tail),
            format!("po-na-de-ro{}", tail),
            format!("po-nadero{}", tail),
            // Hyphen inside a hextet, between its two syllables
            format!("pona-de-ro{}", tail),
        ] {
            assert_eq!(decode(&name), Ok(expected), "Spelling '{}' diverged", name);
        }
        // Fully hyphen-free 32-letter run
        let stripped: String = format!("pona-dero{}", tail).chars().filter(|c| *c != '-').collect();
        assert_eq!(decode(&stripped), Ok(expected));
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(decode("YGPO-NAPU-YGG-PAPE"), decode("ygpo-napu-ygg-pape"));
        assert_eq!(decode("YgPo-Napu-Ygg-Pape"), Ok(addr("203:1904::1")));
    }

    #[test]
    fn hex_chunks() {
        // A full hex spelling, four hex digits per group, decodes as-is
        let doc = addr("2001:db8:85a3::8a2e:370:7334");
        assert_eq!(decode("2001-0db8-85a3-0000-0000-8a2e-0370-7334"), Ok(doc));
        // Hex and syllables mix freely, even inside one token
        assert_eq!(decode("ygpo-napu-ygg-0001"), Ok(addr("203:1904::1")));
        assert_eq!(decode("0203napu-ygg-pape"), Ok(addr("203:1904::1")));
        // Pretty numbers
        assert_eq!(decode("7777-7777-ygg"), Ok(addr("7777:7777::")));
        // Pure-letter chunks are ALWAYS syllables: "fe" is a syllable, not 0xFE
        let sylfe = decode(&format!("fefe{}", "pa".repeat(14))).unwrap();
        assert_ne!(sylfe.octets()[0], 0xfe);
    }

    #[test]
    fn any_odd_token_or_gap_word_is_a_gap() {
        let expected = decode("ygpo-napu-ygg-pape").unwrap();
        // All table synonyms (even-length ones only work through the table)...
        for gap in GAP_WORDS {
            assert_eq!(decode(&format!("ygpo-napu-{}-pape", gap)), Ok(expected), "Gap '{}' diverged", gap);
        }
        // ...and any odd-length token, digits included
        for gap in ["x", "cat", "zzzzz", "777", "0"] {
            assert_eq!(decode(&format!("ygpo-napu-{}-pape", gap)), Ok(expected), "Gap '{}' diverged", gap);
        }
        // A lone gap token is a gap of all eight groups
        assert_eq!(decode("abyss"), Ok(addr("::")));
        assert_eq!(decode("null"), Ok(addr("::")));
    }

    #[test]
    fn hyphen_free_run_never_gap_scanned() {
        // "anullp" = an|ul|lp, contains "null" inside — must decode as syllables
        let name = format!("anullp{}", "pa".repeat(13));
        let hyphenated = format!("an-ul-lp-{}", vec!["pa"; 13].join("-"));
        assert!(decode(&name).is_ok());
        assert_eq!(decode(&name), decode(&hyphenated));
        // An even-length run is never a gap even when it starts with one ("gp" is not a syllable)
        assert_eq!(decode(&format!("yggp{}", "pa".repeat(14))), Err(DecodeError::UnknownSyllable));
    }

    #[test]
    fn gap_positions() {
        // Leading, interior, trailing
        assert_eq!(decode("ygg-pape-pape"), Ok(addr("::1:1")));
        assert_eq!(decode("pape-ygg-pape"), Ok(addr("1::1")));
        assert_eq!(decode("pape-pape-ygg"), Ok(addr("1:1::")));
        // N == 1 is accepted when decoding
        assert_eq!(decode("pape-papa-papa-papa-papa-papa-papa-ygg"), Ok(addr("1::")));
    }

    #[test]
    fn single_zero_group_not_collapsed() {
        let one_zero = addr("1:0:1:1:1:1:1:1");
        assert_eq!(encode_with_gap(&one_zero), encode(&one_zero));
        assert!(encode_with_gap(&one_zero).contains("papa"));
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
        // 100 draws from 8 synonyms: all-identical is (1/8)^99 — never happens
        let zero = addr("::");
        let seen: HashSet<String> = (0..100).map(|_| encode_with_gap(&zero)).collect();
        assert!(seen.len() > 1, "encode_with_gap always picked '{}'", seen.iter().next().unwrap());
        assert!(seen.iter().all(|w| GAP_WORDS.contains(&w.as_str())));
    }

    #[test]
    fn rejects() {
        let full = "papa-papa-papa-papa-papa-papa-papa-papa";
        assert_eq!(decode(""), Err(DecodeError::Empty));
        assert_eq!(decode(&format!("-{}", full)), Err(DecodeError::EmptyToken));
        assert_eq!(decode(&format!("{}-", full)), Err(DecodeError::EmptyToken));
        assert_eq!(decode("papa--papa"), Err(DecodeError::EmptyToken));
        assert_eq!(decode("aa"), Err(DecodeError::UnknownSyllable));
        assert_eq!(decode("qq"), Err(DecodeError::UnknownSyllable));
        assert_eq!(decode("7z"), Err(DecodeError::BadHex));
        assert_eq!(decode("z7"), Err(DecodeError::BadHex));
        assert_eq!(decode("papa.papa"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("pапа"), Err(DecodeError::InvalidChar)); // Cyrillic lookalikes
        assert_eq!(decode("ygg-papa-ygg"), Err(DecodeError::MultipleGaps));
        assert_eq!(decode("ygg-cat"), Err(DecodeError::MultipleGaps));
        assert_eq!(decode("null-papa-hollow"), Err(DecodeError::MultipleGaps));
        assert_eq!(decode(&format!("{}-ygg", full)), Err(DecodeError::BadLength)); // N < 1
        assert_eq!(decode("papa"), Err(DecodeError::BadLength)); // Too short, no gap
        assert_eq!(decode(&"pa".repeat(17)), Err(DecodeError::BadLength)); // Too long
        assert_eq!(decode("papapa-ygg-pape"), Err(DecodeError::GapNotOnGroupBoundary));
        assert_eq!(decode("pape-ygg-papapa"), Err(DecodeError::GapNotOnGroupBoundary));
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
            // Hyphens are cosmetic: strip them all, then insert one at a random byte boundary
            let stripped: String = encode(&a).chars().filter(|c| *c != '-').collect();
            assert_eq!(decode(&stripped), Ok(a));
            let mut spelling = stripped.clone();
            spelling.insert(rng.random_range(1..16) * 2, '-');
            assert_eq!(decode(&spelling), Ok(a));
            // Hex round-trip: spell the same address as raw hex groups. Only valid when
            // every byte's hex form contains a digit — pure-letter chunks (e.g. "ca")
            // are syllables by the spec, not hex
            let all_hex_chunks_have_digit = a.octets().iter()
                .all(|b| format!("{:02x}", b).bytes().any(|c| c.is_ascii_digit()));
            if all_hex_chunks_have_digit {
                let hex: Vec<String> = (0..8).map(|i| format!("{:04x}", a.segments()[i])).collect();
                assert_eq!(decode(&hex.join("-")), Ok(a));
            }
        }
    }
}
