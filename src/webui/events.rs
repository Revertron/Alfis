//! Event-bus to browser marshaling. The listener runs on whatever thread
//! posts the event (miner, network, keystore), so it must stay cheap and
//! must never lock `Context` — some events are posted with it held.
//!
//! Events are translated to small JSON frames and pushed to every connected
//! browser over a Server-Sent Events stream. Event rows are also kept in a
//! ring buffer so the Events tab survives page reloads.

use std::io::{self, Write};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use alfis::event::Event;
use alfis::eventbus::{post, register};
use chrono::Local;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use serde_json::{json, Value};
use tiny_http::Request;

use super::{respond_json, WebState, MAX_SSE_CLIENTS};

/// How many event rows to keep for the Events tab.
const EVENTS_LOG_LIMIT: usize = 200;
/// SSE keep-alive comment period; also lets dead connections get detected.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

fn now() -> String {
    Local::now().format("%d.%m.%y %X").to_string()
}

fn status_frame(text: &str, busy: bool, blue: bool) -> Value {
    json!({"type": "status", "text": text, "busy": busy, "blue": blue})
}

fn event_frame(severity: &str, text: &str) -> Value {
    json!({"type": "event", "severity": severity, "time": now(), "text": text})
}

fn toast_frame(severity: &str, text: &str) -> Value {
    json!({"type": "toast", "severity": severity, "text": text})
}

pub fn register_bus_listener(state: Arc<WebState>, threads: usize) {
    register(move |_uuid, e| {
        let mut frames: Vec<Value> = Vec::new();
        {
            let mut status = state.status.lock().unwrap();
            match e {
                Event::KeyCreated { public, .. } => {
                    // The poster may hold the Context lock, so saving (which
                    // needs that lock) has to happen on another thread.
                    if let Some(filename) = state.pending_key_file.lock().unwrap().take() {
                        save_new_key(Arc::clone(&state), filename, public);
                    }
                    frames.push(json!({"type": "keys_changed"}));
                    frames.push(json!({"type": "domains_changed"}));
                    frames.push(event_frame("luck", "Key successfully created!"));
                    frames.push(toast_frame("luck", "New key mined successfully!"));
                }
                Event::KeyLoaded { .. } | Event::KeySaved { .. } => {
                    frames.push(json!({"type": "keys_changed"}));
                    frames.push(json!({"type": "domains_changed"}));
                }
                Event::MinerStarted | Event::KeyGeneratorStarted => {
                    status.mining = true;
                    status.max_diff = 0;
                    frames.push(event_frame("info", "Mining started"));
                    frames.push(status_frame("Mining...", true, false));
                }
                Event::MinerStopped { success, full } => {
                    status.mining = false;
                    status.max_diff = 0;
                    if status.syncing {
                        frames.push(status_frame("Syncing...", true, true));
                    } else {
                        frames.push(status_frame("Idle", false, false));
                    }
                    if full {
                        if success {
                            frames.push(json!({"type": "domains_changed"}));
                            frames.push(event_frame("luck", "Mining is successful!"));
                            frames.push(toast_frame("luck", "Block successfully mined!"));
                        } else {
                            frames.push(event_frame("info", "Mining finished without result."));
                            frames.push(toast_frame("warn", "Mining unsuccessful, sorry."));
                        }
                    }
                }
                Event::MinerStats { thread, speed, max_diff, target_diff } => {
                    if status.max_diff < max_diff {
                        status.max_diff = max_diff;
                    }
                    status.set_thread_speed(thread, speed);
                    if thread as usize == threads - 1 {
                        let text = format!("Mining speed {} H/s, max found difficulty {}/{}.", status.get_speed(), status.max_diff, target_diff);
                        frames.push(status_frame(&text, true, false));
                    }
                }
                Event::KeyGeneratorStopped => {
                    // If mining was canceled before a key was found, forget
                    // the file name it would have been saved to.
                    state.pending_key_file.lock().unwrap().take();
                    status.mining = false;
                    if status.syncing {
                        frames.push(status_frame("Syncing...", true, true));
                    } else {
                        frames.push(status_frame("Idle", false, false));
                    }
                }
                Event::Syncing { have, height } => {
                    status.syncing = true;
                    status.synced_blocks = have;
                    if height != status.sync_height {
                        status.sync_height = height;
                        frames.push(event_frame("info", "Syncing started..."));
                    }
                    // While mining, the MinerStats speed line owns the status
                    // text — don't overwrite it with sync progress.
                    if !status.mining {
                        frames.push(status_frame(&format!("Synchronizing {}/{}", have, height), true, true));
                    }
                }
                Event::SyncFinished => {
                    // Posted periodically by the network loop, so emit
                    // frames only when a real sync has just finished.
                    let finished = status.syncing;
                    status.syncing = false;
                    if finished {
                        frames.push(json!({"type": "domains_changed"}));
                        frames.push(event_frame("info", "Syncing finished."));
                        if status.mining {
                            frames.push(status_frame("Mining...", true, false));
                        } else {
                            frames.push(status_frame("Idle", false, false));
                        }
                    }
                }
                Event::NetworkStatus { blocks, domains, keys, nodes } => {
                    state.nodes.store(nodes, std::sync::atomic::Ordering::SeqCst);
                    if !status.mining && !status.syncing && nodes >= 3 {
                        frames.push(status_frame("Idle", false, false));
                    }
                    frames.push(json!({"type": "stats", "blocks": blocks, "domains": domains, "keys": keys, "nodes": nodes}));
                }
                Event::BlockchainChanged { index } => {
                    frames.push(event_frame("info", &format!("Blockchain changed, current block count is {} now.", index)));
                }
                Event::Error { text } => {
                    frames.push(toast_frame("fail", &text));
                }
                Event::ForkDetected { index, hash } => {
                    let text = format!("Deep fork detected at block {} (hash {})! Some node's chain has diverged beyond repair.", index, hash);
                    frames.push(event_frame("fail", &text));
                    frames.push(toast_frame("fail", &text));
                }
                Event::KeysBanned { window, keys } => {
                    let text = format!("Dead signers of healed window {} are banned from future draws: {}", window, keys);
                    frames.push(event_frame("warn", &text));
                    frames.push(toast_frame("warn", &text));
                }
                _ => {}
            }
        }
        if !frames.is_empty() {
            deliver(&state, frames);
        }
        true
    });
}

/// Saves the freshly mined key under the name requested via the API. The
/// key is found by the public key from the `KeyCreated` event — the *active*
/// keystore may have changed by the time this thread gets the lock.
fn save_new_key(state: Arc<WebState>, filename: String, public: String) {
    thread::spawn(move || {
        let saved = {
            let mut c = state.context.lock().unwrap();
            match c.keystores.iter_mut().find(|k| k.get_public().to_string() == public) {
                Some(keystore) => {
                    if keystore.save(&filename, "") {
                        Some(keystore.get_hash().to_string())
                    } else {
                        None
                    }
                }
                None => None
            }
        };
        match saved {
            Some(hash) => {
                info!(target: super::LOG_TARGET, "Key file saved to {}", &filename);
                post(Event::KeySaved { path: filename, public, hash });
            }
            None => {
                error!(target: super::LOG_TARGET, "Could not save mined key to {}", &filename);
                post(Event::Error { text: format!("Could not save mined key to '{}'! Save it manually from the config directory.", &filename) });
            }
        }
    });
}

/// Appends event rows to the log and fans all frames out to SSE clients.
fn deliver(state: &WebState, frames: Vec<Value>) {
    {
        let mut log = state.events_log.lock().unwrap();
        for frame in &frames {
            if frame["type"] == "event" {
                log.push_back(frame.clone());
                while log.len() > EVENTS_LOG_LIMIT {
                    log.pop_front();
                }
            }
        }
    }
    let mut clients = state.clients.lock().unwrap();
    clients.retain(|tx| frames.iter().all(|frame| tx.send(frame.to_string()).is_ok()));
}

/// `GET /api/events`: the Server-Sent Events stream. Holds this worker
/// thread for as long as the browser stays connected.
///
/// The response is written by hand through `Request::into_writer` because
/// `respond()` only flushes its internal `BufWriter` when the whole body is
/// done — which never happens for an endless stream. With the raw writer we
/// can flush after every event.
pub fn serve_sse(state: &Arc<WebState>, request: Request) {
    let (tx, rx) = channel::<String>();
    {
        let mut clients = state.clients.lock().unwrap();
        if clients.len() >= MAX_SSE_CLIENTS {
            drop(clients);
            return respond_json(request, 503, &json!({"error": "Too many event stream clients"}));
        }
        clients.push(tx);
    }
    let mut writer = request.into_writer();
    // The body ends when the connection closes, which is fine for SSE:
    // EventSource reconnects by itself (after the `retry` interval below).
    let head = "HTTP/1.1 200 OK\r\n\
                Content-Type: text/event-stream\r\n\
                Cache-Control: no-store\r\n\
                X-Accel-Buffering: no\r\n\
                Connection: close\r\n\
                \r\n\
                retry: 3000\n\n";
    if send(&mut writer, head.as_bytes()).is_err() {
        return;
    }
    loop {
        let result = match rx.recv_timeout(KEEP_ALIVE) {
            Ok(message) => send(&mut writer, format!("data: {}\n\n", message).as_bytes()),
            Err(RecvTimeoutError::Timeout) => send(&mut writer, b": keep-alive\n\n"),
            Err(RecvTimeoutError::Disconnected) => break
        };
        if result.is_err() {
            break;
        }
    }
    // Dropping `rx` here makes the bus listener drop our sender on its
    // next broadcast.
}

fn send(writer: &mut Box<dyn Write + Send>, data: &[u8]) -> io::Result<()> {
    writer.write_all(data)?;
    writer.flush()
}
