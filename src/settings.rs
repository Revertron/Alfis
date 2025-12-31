use std::fs::File;
use std::io::Read;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use serde::{Deserialize, Serialize};

use crate::Bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub origin: String,
    #[serde(default = "default_key_files")]
    pub key_files: Vec<String>,
    #[serde(default = "default_check_blocks")]
    pub check_blocks: u64,
    #[serde(default)]
    pub net: Net,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default)]
    pub mining: Mining
}

impl Settings {
    pub fn load(filename: &str) -> Option<Settings> {
        match File::open(filename) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                if let Ok(mut settings) = toml::from_str::<Settings>(&text) {
                    // Migrate incorrect test port 42440 to correct port 4244 for public nodes
                    if settings.net.public && settings.net.listen.contains(":42440") {
                        warn!("Migrating incorrect port 42440 to 4244 in net.listen configuration");

                        // Update the in-memory settings
                        settings.net.listen = settings.net.listen.replace(":42440", ":4244");

                        // Try to save the corrected configuration back to file
                        if let Err(e) = Self::save_migration(filename, &text) {
                            warn!("Could not save migrated config to {}: {}", filename, e);
                            info!("Please manually update net.listen from :42440 to :4244 in your config");
                        } else {
                            info!("Successfully migrated config file {} (port 42440 → 4244)", filename);
                        }
                    }
                    return Some(settings);
                }
                None
            }
            Err(..) => None
        }
    }

    fn save_migration(filename: &str, original_text: &str) -> Result<(), std::io::Error> {
        use std::io::Write;
        // Simple text replacement preserves all comments and formatting
        let migrated_text = original_text.replace(":42440", ":4244");
        let mut file = File::create(filename)?;
        file.write_all(migrated_text.as_bytes())?;
        Ok(())
    }

    pub fn get_origin(&self) -> Bytes {
        if self.origin.eq("") {
            return Bytes::zero32();
        }
        let origin = crate::from_hex(&self.origin).expect("Wrong origin in settings");
        Bytes::from_bytes(origin.as_slice())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            origin: String::from("0000001D2A77D63477172678502E51DE7F346061FF7EB188A2445ECA3FC0780E"),
            key_files: default_key_files(),
            check_blocks: default_check_blocks(),
            net: Net::default(),
            dns: Default::default(),
            mining: Mining::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dns {
    #[serde(default = "default_listen_dns")]
    pub listen: String,
    #[serde(default = "default_threads")]
    pub threads: usize,
    pub forwarders: Vec<String>,
    #[serde(default = "default_dns_bootstraps")]
    pub bootstraps: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Enable DNS 0x20 encoding (random case) for additional security against cache poisoning
    #[serde(default = "default_dns_0x20")]
    pub enable_0x20: bool,
    /// Maximum memory for DNS cache in megabytes (default: 100 MB)
    #[serde(default = "default_cache_max_memory_mb")]
    pub cache_max_memory_mb: u64,
    /// Interval for periodic cache cleanup in seconds (default: 300 seconds)
    #[serde(default = "default_cache_cleanup_interval_sec")]
    pub cache_cleanup_interval_sec: u64,
    /// Maximum queue size for TCP server per worker thread (default: 1000)
    #[serde(default = "default_tcp_queue_size")]
    pub tcp_queue_size: usize,
    /// Maximum queue size for UDP server (default: 5000)
    #[serde(default = "default_udp_queue_size")]
    pub udp_queue_size: usize
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            listen: default_listen_dns(),
            threads: 10,
            forwarders: vec![String::from("94.140.14.14:53"), String::from("94.140.15.15:53")],
            bootstraps: default_dns_bootstraps(),
            hosts: Vec::new(),
            enable_0x20: default_dns_0x20(),
            cache_max_memory_mb: default_cache_max_memory_mb(),
            cache_cleanup_interval_sec: default_cache_cleanup_interval_sec(),
            tcp_queue_size: default_tcp_queue_size(),
            udp_queue_size: default_udp_queue_size()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Mining {
    #[serde(default)]
    pub threads: usize,
    #[serde(default)]
    pub lower: bool
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Net {
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub yggdrasil_only: bool,
    /// Maximum number of new peer addresses in queue to prevent memory leak (default: 1000)
    #[serde(default = "default_max_new_peers")]
    pub max_new_peers: usize
}

impl Default for Net {
    fn default() -> Self {
        Net {
            peers: vec![String::from("peer-v4.alfis.name:4244"), String::from("peer-v6.alfis.name:4244")],
            listen: String::from("[::]:4244"),
            public: true,
            yggdrasil_only: false,
            max_new_peers: default_max_new_peers()
        }
    }
}

fn default_listen() -> String {
    String::from("[::]:4244")
}

fn default_listen_dns() -> String {
    String::from("127.0.0.3:53")
}

fn default_threads() -> usize {
    10
}

fn default_check_blocks() -> u64 {
    8
}

fn default_key_files() -> Vec<String> {
    vec![
        String::from("key1.toml"),
        String::from("key2.toml"),
        String::from("key3.toml"),
        String::from("key4.toml"),
        String::from("key5.toml"),
    ]
}

fn default_dns_bootstraps() -> Vec<String> {
    vec![String::from("9.9.9.9:53"), String::from("94.140.14.14:53")]
}

fn default_dns_0x20() -> bool {
    true
}

fn default_cache_max_memory_mb() -> u64 {
    100
}

fn default_cache_cleanup_interval_sec() -> u64 {
    300
}

fn default_max_new_peers() -> usize {
    1000
}

fn default_tcp_queue_size() -> usize {
    1000
}

fn default_udp_queue_size() -> usize {
    5000
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_port_migration_for_public_nodes() {
        // Create a temporary config file with incorrect port
        let test_file = "test_migration_unit.toml";
        let config_content = r#"
origin = "0000001D2A77D63477172678502E51DE7F346061FF7EB188A2445ECA3FC0780E"
key_files = ["key1.toml"]

[net]
# Comment should be preserved
listen = "[::]:42440"
public = true
"#;

        // Write test config
        let mut file = File::create(test_file).unwrap();
        file.write_all(config_content.as_bytes()).unwrap();
        drop(file);

        // Load the config (should trigger migration)
        let settings = Settings::load(test_file).unwrap();

        // Verify the setting in memory is correct
        assert_eq!(settings.net.listen, "[::]:4244");

        // Read the file to verify it was actually modified
        let mut file = File::open(test_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        // Verify file was migrated
        assert!(content.contains(":4244"));
        assert!(!content.contains(":42440"));
        // Verify comment was preserved
        assert!(content.contains("# Comment should be preserved"));

        // Cleanup
        std::fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_no_migration_for_private_nodes() {
        // Create a temporary config file with incorrect port but public = false
        let test_file = "test_no_migration_unit.toml";
        let config_content = r#"
origin = "0000001D2A77D63477172678502E51DE7F346061FF7EB188A2445ECA3FC0780E"
key_files = ["key1.toml"]

[net]
listen = "[::]:42440"
public = false
"#;

        // Write test config
        let mut file = File::create(test_file).unwrap();
        file.write_all(config_content.as_bytes()).unwrap();
        drop(file);

        // Load the config (should NOT trigger migration because public = false)
        let settings = Settings::load(test_file).unwrap();

        // Verify the setting remains unchanged
        assert_eq!(settings.net.listen, "[::]:42440");

        // Read the file to verify it was NOT modified
        let mut file = File::open(test_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        // Verify file was NOT migrated (still has 42440)
        assert!(content.contains(":42440"));

        // Cleanup
        std::fs::remove_file(test_file).ok();
    }
}