//! JSON API handlers of the web UI. All of them are thin wrappers over
//! `Context`/`Miner` and the shared actions in `alfis::actions`.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use alfis::actions::{action_create_domain, action_select_key, check_domain_available, check_record, file_name};
use alfis::blockchain::transaction::DomainData;
use alfis::commons::DOMAIN_LIFETIME;
use alfis::event::Event;
use alfis::eventbus::post;
use alfis::keystore::create_key;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use serde::Deserialize;
use serde_json::json;
use tiny_http::Request;

use super::{read_json, respond_json, WebState};

pub fn status(state: &Arc<WebState>, request: Request) {
    let (version, blocks, domains, keys) = {
        let c = state.context.lock().unwrap();
        (c.app_version.clone(), c.chain.get_height(), c.chain.get_domains_count(), c.chain.get_users_count())
    };
    let body = {
        let status = state.status.lock().unwrap();
        json!({
            "version": version,
            "blocks": blocks,
            "domains": domains,
            "keys": keys,
            "nodes": state.nodes.load(Ordering::SeqCst),
            "mining": status.mining,
            "syncing": status.syncing,
            "synced_blocks": status.synced_blocks,
            "sync_height": status.sync_height,
            "speed": status.get_speed()
        })
    };
    respond_json(request, 200, &body);
}

pub fn keys(state: &Arc<WebState>, request: Request) {
    let body = {
        let c = state.context.lock().unwrap();
        let keys = c.get_keystores().iter().map(|k| json!({
            "file_name": file_name(k.get_path()),
            "public": k.get_public().to_string(),
            "hash": k.get_hash().to_string()
        })).collect::<Vec<_>>();
        json!({"keys": keys, "active": c.get_active_key_index()})
    };
    respond_json(request, 200, &body);
}

#[derive(Deserialize)]
struct SelectKeyRequest {
    index: usize
}

pub fn keys_select(state: &Arc<WebState>, request: Request) {
    let Some((request, select)) = read_json::<SelectKeyRequest>(request) else { return; };
    if select.index >= state.context.lock().unwrap().get_keystores().len() {
        return respond_json(request, 400, &json!({"error": "No key with this index"}));
    }
    action_select_key(&state.context, select.index);
    respond_json(request, 200, &json!({}));
}

#[derive(Deserialize)]
struct CreateKeyRequest {
    filename: String
}

pub fn keys_create(state: &Arc<WebState>, request: Request) {
    let Some((request, create)) = read_json::<CreateKeyRequest>(request) else { return; };
    let filename = match sanitize_key_filename(&create.filename) {
        Ok(filename) => filename,
        Err(e) => return respond_json(request, 400, &json!({"error": e}))
    };
    {
        let mut pending = state.pending_key_file.lock().unwrap();
        if pending.is_some() {
            return respond_json(request, 409, &json!({"error": "Already mining a key"}));
        }
        *pending = Some(filename);
    }
    create_key(Arc::clone(&state.context));
    respond_json(request, 200, &json!({}));
}

/// Only plain file names are allowed — the key is saved in the working
/// directory, next to the other key files.
fn sanitize_key_filename(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(String::from("Enter a file name for the new key"));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") || name.starts_with('.') || name.contains(':') {
        return Err(String::from("Enter a plain file name, without a path"));
    }
    // On Windows names like NUL or COM1 are devices: File::create "succeeds"
    // and the key silently goes nowhere.
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit());
    if device {
        return Err(String::from("This file name is reserved by Windows, choose another one"));
    }
    let mut name = name.to_owned();
    if !name.ends_with(".toml") {
        name.push_str(".toml");
    }
    if Path::new(&name).exists() {
        return Err(format!("File '{}' already exists, choose another name", &name));
    }
    Ok(name)
}

pub fn domains(state: &Arc<WebState>, request: Request) {
    let body = {
        let c = state.context.lock().unwrap();
        let domains = c.chain.get_my_domains(c.get_keystore());
        let mut domains = domains.values().collect::<Vec<_>>();
        domains.sort_by(|a, b| a.0.cmp(&b.0));
        let domains = domains.iter().map(|(name, timestamp, data)| json!({
            "name": name,
            "timestamp": timestamp,
            "expire": timestamp + DOMAIN_LIFETIME,
            "data": data
        })).collect::<Vec<_>>();
        json!({"domains": domains})
    };
    respond_json(request, 200, &body);
}

pub fn zones(state: &Arc<WebState>, request: Request) {
    let zones = state.context.lock().unwrap().chain.get_zones().clone();
    respond_json(request, 200, &json!({"zones": zones}));
}

pub fn domains_check(state: &Arc<WebState>, request: Request, url: &str) {
    let Some(name) = query_param(url, "name") else {
        return respond_json(request, 400, &json!({"error": "No 'name' parameter"}));
    };
    let available = check_domain_available(&state.context, &name);
    respond_json(request, 200, &json!({"available": available}));
}

#[derive(Deserialize)]
struct MineDomainRequest {
    name: String,
    data: DomainData,
    #[serde(default)]
    signing: String,
    #[serde(default)]
    encryption: String,
    #[serde(default)]
    renewal: bool
}

pub fn domains_create(state: &Arc<WebState>, request: Request) {
    let Some((request, mine)) = read_json::<MineDomainRequest>(request) else { return; };
    let name = mine.name.to_lowercase();
    match action_create_domain(&state.context, &state.miner, &name, mine.data, &mine.signing, &mine.encryption, mine.renewal) {
        Ok(()) => respond_json(request, 200, &json!({})),
        Err(e) => respond_json(request, 400, &json!({"error": e}))
    }
}

pub fn records_check(_state: &Arc<WebState>, mut request: Request) {
    let Some(body) = super::read_body(&mut request) else {
        return respond_json(request, 400, &json!({"error": "Cannot read request body"}));
    };
    respond_json(request, 200, &json!({"ok": check_record(&body)}));
}

pub fn mining_stop(_state: &Arc<WebState>, request: Request) {
    info!(target: super::LOG_TARGET, "Stopping mining by web UI request");
    post(Event::ActionStopMining);
    respond_json(request, 200, &json!({}));
}

pub fn events_log(state: &Arc<WebState>, request: Request) {
    let events = state.events_log.lock().unwrap().iter().cloned().collect::<Vec<_>>();
    respond_json(request, 200, &json!({"events": events}));
}

/// Extracts and percent-decodes one query-string parameter.
fn query_param(url: &str, param: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == param {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let value = value.replace('+', " ");
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{percent_decode, query_param, sanitize_key_filename};

    #[test]
    fn test_sanitize_key_filename() {
        assert_eq!(sanitize_key_filename("newkey"), Ok(String::from("newkey.toml")));
        assert_eq!(sanitize_key_filename(" mykey.toml "), Ok(String::from("mykey.toml")));
        assert!(sanitize_key_filename("").is_err());
        assert!(sanitize_key_filename("   ").is_err());
        assert!(sanitize_key_filename("../evil").is_err());
        assert!(sanitize_key_filename("dir/key").is_err());
        assert!(sanitize_key_filename("dir\\key").is_err());
        assert!(sanitize_key_filename("C:key").is_err());
        assert!(sanitize_key_filename(".hidden").is_err());
        assert!(sanitize_key_filename("nul").is_err());
        assert!(sanitize_key_filename("NUL.toml").is_err());
        assert!(sanitize_key_filename("con").is_err());
        assert!(sanitize_key_filename("Com5").is_err());
        assert!(sanitize_key_filename("lpt9.toml").is_err());
        assert_eq!(sanitize_key_filename("common"), Ok(String::from("common.toml")));
        assert_eq!(sanitize_key_filename("nullish"), Ok(String::from("nullish.toml")));
    }

    #[test]
    fn test_query_param() {
        assert_eq!(query_param("/api/domains/check?name=test.ygg", "name"), Some(String::from("test.ygg")));
        assert_eq!(query_param("/api/domains/check?a=b&name=x%2Eygg", "name"), Some(String::from("x.ygg")));
        assert_eq!(query_param("/api/domains/check", "name"), None);
        assert_eq!(query_param("/api/domains/check?other=1", "name"), None);
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("abc"), "abc");
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%D0%B4%D0%BE%D0%BC"), "дом");
        assert_eq!(percent_decode("bad%2"), "bad%2");
    }
}
