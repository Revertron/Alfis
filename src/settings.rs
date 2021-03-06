use std::fs::File;
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::Bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub origin: String,
    pub key_file: String,
    pub listen: String,
    pub public: bool,
    pub peers: Vec<String>,
    #[serde(default)]
    pub dns: Dns
}

impl Settings {
    pub fn new<S: Into<String>>(settings: S) -> serde_json::Result<Settings> {
        serde_json::from_str(&settings.into())
    }

    pub fn load(file_name: &str) -> Option<Settings> {
        match File::open(file_name) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                if let Ok(settings) = toml::from_str(&text) {
                    return Some(settings);
                }
                None
            },
            Err(..) => None
        }
    }

    pub fn get_origin(&self) -> Bytes {
        if self.origin.eq("") {
            return Bytes::zero32();
        }
        let origin = crate::from_hex(&self.origin).expect("Wrong origin in settings");
        Bytes::from_bytes(origin.as_slice())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dns {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_threads")]
    pub threads: usize,
    pub forwarders: Vec<String>
}

impl Default for Dns {
    fn default() -> Self {
        Dns { listen: String::from("0.0.0.0:53"), threads: 20, forwarders: Vec::new() }
    }
}

fn default_listen() -> String {
    String::from("0.0.0.0:53")
}

fn default_threads() -> usize {
    20
}