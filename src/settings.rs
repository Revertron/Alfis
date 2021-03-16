use std::fs::File;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use log::{debug, error, info, LevelFilter, trace, warn};

use crate::Bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub dns: Dns,
}

impl Settings {
    pub fn new<S: Into<String>>(settings: S) -> serde_json::Result<Settings> {
        serde_json::from_str(&settings.into())
    }

    pub fn load(filename: &str) -> Settings {
        match File::open(filename) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                if let Ok(settings) = toml::from_str(&text) {
                    return settings;
                }
                Settings::default()
            }
            Err(..) => {
                let settings = Settings::default();
                let string = toml::to_string(&settings).unwrap();
                match File::create(filename) {
                    Ok(mut f) => {
                        f.write_all(string.as_bytes()).expect("Error saving settings!");
                    }
                    Err(_) => { error!("Error saving settings file!"); }
                }
                settings
            }
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

impl Default for Settings {
    fn default() -> Self {
        Self {
            origin: "".to_string(),
            key_file: "".to_string(),
            listen: String::from("[::]:4244"),
            public: false,
            peers: vec![],
            dns: Default::default()
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
}

impl Default for Dns {
    fn default() -> Self {
        Dns { listen: String::from("0.0.0.0:53"), threads: 20, forwarders: vec!["94.140.14.14:53".to_owned(), "94.140.15.15:53".to_owned()] }
    }
}

fn default_listen() -> String {
    String::from("[::]:4244")
}

fn default_listen_dns() -> String {
    String::from("0.0.0.0:53")
}

fn default_threads() -> usize {
    20
}