//! User actions and view refreshers, ported from the old webview UI
//! (`web_ui.rs`). These run on the UI thread (from button handlers or
//! closures marshaled via `UiHandle`).

use std::sync::{Arc, Mutex};

use alfis::blockchain::transaction::DomainData;
use alfis::blockchain::types::MineResult;
use alfis::commons::{from_hex, is_yggdrasil_record, CLASS_DOMAIN, DOMAIN_DIFFICULTY, DOMAIN_LIFETIME, MAX_RECORDS};
use alfis::crypto::CryptoBox;
use alfis::event::Event;
use alfis::eventbus::post;
use alfis::miner::Miner;
use alfis::{Block, Bytes, Context, Keystore, Transaction};
use chrono::{Local, TimeZone, Utc};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use lumio::prelude::*;

use super::tfd;
use super::toasts::{add_event_row, show_toast, Severity};

/// Refreshes everything that depends on the active keystore: the keys
/// dropdown, the public-key field and the Save button.
pub fn keystore_changed(ui: &mut UI, context: &Arc<Mutex<Context>>) {
    let (names, active, public, has_keys) = {
        let c = context.lock().unwrap();
        let names: Vec<String> = c.get_keystores().iter()
            .map(|k| file_name(k.get_path()))
            .collect();
        let active = c.get_active_key_index();
        let public = c.get_keystore().map(|k| k.get_public().to_string());
        (names, active, public, c.has_keys())
    };

    if let Some(view) = ui.get_view("keys_combo") {
        if let Some(combo) = view.borrow().downcast_ref::<ComboBox>() {
            combo.clear_items();
            for name in &names {
                combo.add_item(name);
            }
            if !names.is_empty() {
                combo.set_selected(active);
            }
        }
    }
    if let Some(view) = ui.get_view("public_key") {
        if let Some(edit) = view.borrow().downcast_ref::<Edit>() {
            edit.set_text(public.as_deref().unwrap_or(""));
        }
    }
    if let Some(view) = ui.get_view("btn_save_key") {
        view.borrow_mut().set_enabled(has_keys);
    }
    ui.relayout();
}

/// Reloads the Domains tab table from the blockchain for the active keystore.
pub fn load_domains(ui: &mut UI, context: &Arc<Mutex<Context>>) {
    let rows = {
        let c = context.lock().unwrap();
        let domains = c.chain.get_my_domains(c.get_keystore());
        let mut domains = domains.values().collect::<Vec<_>>();
        domains.sort_by(|a, b| a.0.cmp(&b.0));
        domains.iter().map(|(domain, timestamp, data)| {
            let records = data.records.iter()
                .filter_map(|r| r.get_domain())
                .map(|d| if d.is_empty() { String::from("@") } else { d })
                .collect::<Vec<_>>()
                .join(", ");
            vec![domain.clone(), records, format_date(*timestamp), format_date(*timestamp + DOMAIN_LIFETIME)]
        }).collect::<Vec<_>>()
    };

    if let Some(view) = ui.get_view("domains_table") {
        if let Some(table) = view.borrow().downcast_ref::<TableView>() {
            table.clear_rows();
            for row in rows {
                table.add_row_text(row);
            }
        }
    }
    ui.relayout();
}

/// Updates the four statistics tiles on the Credentials tab.
pub fn set_stats(ui: &UI, blocks: u64, domains: i64, keys: i64, nodes: usize) {
    super::set_label(ui, "stat_blocks", &blocks.to_string());
    super::set_label(ui, "stat_domains", &domains.to_string());
    super::set_label(ui, "stat_keys", &keys.to_string());
    super::set_label(ui, "stat_nodes", &nodes.to_string());
}

/// "Load key" button: shows a file dialog and loads the chosen keystore.
pub fn action_load_key(ui: &mut UI, context: &Arc<Mutex<Context>>) {
    let result = tfd::open_file_dialog("Open keys file", "", Some((&["*.key", "*.toml"], "Key files")));
    let Some(file_name) = result else { return; };
    match Keystore::from_file(&file_name, "") {
        None => {
            error!("Error loading keystore '{}'!", &file_name);
            show_toast(ui, Severity::Warn, "Error loading key!\nKey cannot be loaded or its difficulty is not enough.");
            add_event_row(ui, Severity::Fail, &format!("Error loading key from '{}'!", &file_name));
        }
        Some(keystore) => {
            info!("Loaded keystore with keys: {:?}, {:?}", &keystore.get_public(), &keystore.get_encryption_public());
            let path = keystore.get_path().to_owned();
            let public = keystore.get_public().to_string();
            let hash = keystore.get_hash().to_string();
            {
                let mut c = context.lock().unwrap();
                if !c.select_key_by_public(&keystore.get_public()) {
                    c.add_keystore(keystore);
                } else {
                    warn!("This key is already loaded!");
                }
            }
            post(Event::KeyLoaded { path, public, hash });
        }
    }
}

/// "Save key" button: shows a save dialog and persists the active keystore.
pub fn action_save_key(context: &Arc<Mutex<Context>>) {
    if !context.lock().unwrap().has_keys() {
        return;
    }
    let result = tfd::save_file_dialog_with_filter("Save keys file", "", &["*.toml"], "Key files (*.toml)");
    let Some(mut new_path) = result else { return; };
    if !new_path.ends_with(".toml") {
        new_path.push_str(".toml");
    }
    let path = new_path.clone();
    if let Some(keystore) = context.lock().unwrap().get_keystore_mut() {
        let public = keystore.get_public().to_string();
        let hash = keystore.get_hash().to_string();
        keystore.save(&new_path, "");
        info!("Key file saved to {}", &path);
        post(Event::KeySaved { path, public, hash });
    }
}

/// Keys dropdown: switches the active keystore.
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

/// Validates a domain-mining request and starts mining. Returns a
/// user-readable error message when mining cannot start — the port of the
/// `domainMiningUnavailable` paths of the old web UI.
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

fn format_date(timestamp: i64) -> String {
    Local.timestamp_opt(timestamp, 0).single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The file name part of a keystore path, like the old UI showed in the
/// keys dropdown. An empty path means an unsaved, in-memory key.
fn file_name(path: &str) -> String {
    if path.is_empty() {
        return String::from("In memory");
    }
    let path = path.replace('\\', "/");
    path.rsplit('/').next().unwrap_or(&path).to_string()
}
