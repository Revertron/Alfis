//! User actions shared by the desktop GUI and the web UI. These functions
//! are view-independent: they work only with `Context`, `Miner` and the
//! event bus, and report problems as `Result`/`bool` for the caller to show.

use std::sync::{Arc, Mutex};

use chrono::{Local, TimeZone, Utc};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use crate::blockchain::transaction::DomainData;
use crate::blockchain::types::MineResult;
use crate::commons::{from_hex, is_yggdrasil_record, CLASS_DOMAIN, DOMAIN_DIFFICULTY, MAX_DATA_LEN, MAX_RECORDS};
use crate::crypto::CryptoBox;
use crate::dns::protocol::DnsRecord;
use crate::event::Event;
use crate::eventbus::post;
use crate::miner::Miner;
use crate::{Block, Bytes, Context, Keystore, Transaction};

/// Switches the active keystore by index and announces it on the bus.
pub fn action_select_key(context: &Arc<Mutex<Context>>, index: usize) {
    if context.lock().unwrap().select_key_by_index(index) {
        let (path, public, hash) = {
            let keystore = context.lock().unwrap().get_keystore().cloned().unwrap();
            (keystore.get_path().to_owned(), keystore.get_public().to_string(), keystore.get_hash().to_string())
        };
        post(Event::KeyLoaded { path, public, hash });
    }
}

/// Whether the (full) domain name can be mined with the active keystore.
pub fn check_domain_available(context: &Arc<Mutex<Context>>, name: &str) -> bool {
    let c = context.lock().unwrap();
    if let Some(keystore) = c.get_keystore() {
        let name = name.to_lowercase();
        matches!(c.chain.can_mine_domain(c.chain.get_height(), &name, &keystore.get_public()), MineResult::Fine)
    } else {
        false
    }
}

/// Checks that a single DNS record is valid and fits size limits.
pub fn check_record(data: &str) -> bool {
    match serde_json::from_str::<DnsRecord>(data) {
        Ok(record) => {
            if let Some(string) = record.get_data() {
                string.len() <= MAX_DATA_LEN
            } else {
                false
            }
        }
        Err(_) => false
    }
}

/// Validates a domain-mining request and starts mining. Returns a
/// user-readable error message when mining cannot start.
pub fn action_create_domain(context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>, name: &str,
                            data: DomainData, signing: &str, encryption: &str, renewal: bool) -> Result<(), String> {
    let context_guard = context.lock().unwrap();

    if !context_guard.has_keys() {
        return Err(String::from("You don't have keys loaded!\nLoad or mine the keys and try again."));
    }
    if context_guard.chain.is_waiting_signers() {
        info!("Waiting for last full block to be signed. Try again later.");
        return Err(String::from("Waiting for last full block to be signed. Try again later."));
    }

    let keystore = context_guard.get_keystore().unwrap().clone();
    let pub_key = keystore.get_public();
    info!("Mining domain with data:\n{:#?}", &data);

    if data.records.len() > MAX_RECORDS {
        return Err(String::from("Too many records. Mining more than 30 records not allowed."));
    }

    // Check that the yggdrasil-only quality of the zone is not violated
    let zones = context_guard.chain.get_zones().clone();
    for z in zones {
        if z.name == data.zone && z.yggdrasil {
            for record in &data.records {
                if !is_yggdrasil_record(record) {
                    return Err(format!("Zone {} is Yggdrasil only, you cannot use IPs from clearnet!", &data.zone));
                }
            }
        }
    }

    let (signing, encryption) = if signing.is_empty() || encryption.is_empty() {
        (keystore.get_public(), keystore.get_encryption_public())
    } else {
        match (from_hex(signing), from_hex(encryption)) {
            (Ok(s), Ok(e)) => (Bytes::new(s), Bytes::new(e)),
            _ => return Err(String::from("Wrong owner keys!"))
        }
    };

    match context_guard.chain.can_mine_domain(context_guard.chain.get_height(), name, &pub_key) {
        MineResult::Fine => {
            drop(context_guard);
            create_domain(Arc::clone(context), Arc::clone(miner), CLASS_DOMAIN, name, data, DOMAIN_DIFFICULTY, &keystore, signing, encryption, renewal);
            Ok(())
        }
        MineResult::WrongName => Err(String::from("You can't mine this domain!")),
        MineResult::WrongData => Err(String::from("You have an error in records!")),
        MineResult::WrongKey => Err(String::from("You can't mine with current key!")),
        MineResult::WrongZone => Err(String::from("You can't mine domain in this zone!")),
        MineResult::NotOwned => Err(String::from("This domain is already taken, and it is not yours!")),
        MineResult::Cooldown { time } => Err(format!("You have cooldown {}!", format_cooldown(time)))
    }
}

#[allow(clippy::too_many_arguments)]
fn create_domain(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, class: &str, name: &str, mut data: DomainData,
                 difficulty: u32, keystore: &Keystore, signing: Bytes, encryption: Bytes, renewal: bool) {
    let name = name.to_owned();
    let encrypted = CryptoBox::encrypt(encryption.as_slice(), name.as_bytes()).expect("Error encrypting domain name!");
    data.encrypted = Bytes::from_bytes(&encrypted);

    let data = serde_json::to_string(&data).unwrap();
    let (signing, encryption) = if signing.is_empty() || encryption.is_empty() {
        (keystore.get_public(), keystore.get_encryption_public())
    } else {
        (signing, encryption)
    };
    let transaction = Transaction::from_str(name, class.to_owned(), data, signing, encryption);
    // If this domain is already in blockchain we approve slightly smaller difficulty
    let height = context.lock().unwrap().chain.get_height();
    let discount = context.lock().unwrap().chain.get_identity_discount(&transaction.identity, renewal, height, Utc::now().timestamp());
    let block = Block::new(Some(transaction), keystore.get_public(), Bytes::default(), difficulty - discount);
    miner.lock().unwrap().add_block(block, keystore.clone());
}

pub fn format_cooldown(time: i64) -> String {
    if time <= 60 {
        return format!("{} seconds", time);
    }
    let minutes = time / 60;
    if minutes <= 60 {
        return format!("{} minutes", minutes);
    }
    format!("{} hours", minutes / 60)
}

pub fn format_date(timestamp: i64) -> String {
    Local.timestamp_opt(timestamp, 0).single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The file name part of a keystore path, like the UIs show in the keys
/// dropdown. An empty path means an unsaved, in-memory key.
pub fn file_name(path: &str) -> String {
    if path.is_empty() {
        return String::from("In memory");
    }
    let path = path.replace('\\', "/");
    path.rsplit('/').next().unwrap_or(&path).to_string()
}
