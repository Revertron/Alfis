//! GUI-side user actions and view refreshers. The view-independent logic
//! (domain mining, key selection, availability checks) lives in
//! `alfis::actions` and is shared with the web UI; this module keeps only
//! what needs Lumio views or desktop file dialogs.

use std::sync::{Arc, Mutex};

use alfis::actions::{file_name, format_date};
use alfis::commons::DOMAIN_LIFETIME;
use alfis::event::Event;
use alfis::eventbus::post;
use alfis::{Context, Keystore};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use lumio::prelude::*;

pub use alfis::actions::{action_create_domain, action_select_key, check_domain_available};

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
        if keystore.save(&new_path, "") {
            info!("Key file saved to {}", &path);
            post(Event::KeySaved { path, public, hash });
        } else {
            post(Event::Error { text: format!("Could not save key to '{}'!", &path) });
        }
    }
}
