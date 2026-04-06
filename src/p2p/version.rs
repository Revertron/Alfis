use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Version {
    pub fn parse(s: &str) -> Version {
        let parts: Vec<&str> = s.split('.').collect();
        Version {
            major: parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0),
            minor: parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
            patch: parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0),
        }
    }
}

impl Default for Version {
    fn default() -> Self {
        Version { major: 0, minor: 0, patch: 0 }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major.cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(Version::parse("0.8.9") >= Version::parse("0.8.9"));
        assert!(Version::parse("0.8.10") > Version::parse("0.8.9"));
        assert!(Version::parse("0.8.8") < Version::parse("0.8.9"));
        assert!(Version::parse("0.9.0") > Version::parse("0.8.99"));
        assert!(Version::parse("1.0.0") > Version::parse("0.99.99"));
    }
}
