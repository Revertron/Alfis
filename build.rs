extern crate winres;

use std::fs::File;
use std::fs::read_to_string;
use std::path::Path;
use std::io::Write;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

const IANA_FILE: &'static str = "iana-tlds.txt";
const IANA_HASHES: &'static str = "iana-hashes.txt";
const IANA_ZONES_URL: &'static str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";

fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("img/logo/alfis.ico");
        res.compile().unwrap();
    }

    download_iana_zones(IANA_FILE, IANA_HASHES);
}

fn download_iana_zones(zones_name: &str, hashes_name: &str) {
    let response = match read_to_string(Path::new(IANA_FILE)) {
        Ok(string) => { string }
        Err(_) => {
            let response = minreq::get(IANA_ZONES_URL).send().expect("Could not make request!");
            response.as_str().expect("Response is not a valid UTF-8!").to_lowercase()
        }
    };

    let list: Vec<_> = response.split("\n").collect();
    let mut zones = String::new();
    let mut hashes = String::new();
    for string in list {
        if !string.starts_with("#") && !string.is_empty() {
            zones.push_str(string);
            zones.push('\n');

            hashes.push_str(&hash_identity(string));
            hashes.push('\n');
        }
    }

    match File::create(Path::new(zones_name)) {
        Ok(mut file) => {
            file.write_all(zones.trim().as_bytes()).expect("Error saving TLDs file!");
        }
        Err(e) => { panic!("Error opening TLDs file!\n{}", e); }
    }

    match File::create(Path::new(hashes_name)) {
        Ok(mut file) => {
            file.write_all(hashes.trim().as_bytes()).expect("Error saving TLD-hashes file!");
        }
        Err(e) => { panic!("Error opening TLD-hashes file!\n{}", e); }
    }
}

fn hash_identity(identity: &str) -> String {
    let mut buf: [u8; 32] = [0; 32];
    let mut digest = Sha256::new();
    digest.input_str(identity);
    digest.result(&mut buf);
    to_hex(&buf)
}

/// Convert bytes array to HEX format
pub fn to_hex(buf: &[u8]) -> String {
    let mut result = String::new();
    for x in buf.iter() {
        result.push_str(&format!("{:01$X}", x, 2));
    }
    result
}