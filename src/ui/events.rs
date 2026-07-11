//! Event-bus to UI-thread marshaling. The listener runs on whatever thread
//! posts the event (miner, network, keystore), so it must stay cheap and
//! must never lock `Context` — all heavier work is queued to the UI thread
//! via `UiHandle::run_on_ui_thread`.

use std::sync::{Arc, Mutex};

use alfis::event::Event;
use alfis::eventbus::register;
use alfis::Context;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use lumio::prelude::UiHandle;

use super::actions::{keystore_changed, load_domains, set_stats};
use super::state::UiStatus;
use super::toasts::{add_event_row, show_toast, Severity};
use super::{set_label, set_visible};

pub fn register_bus_listener(handle: UiHandle, context: Arc<Mutex<Context>>, status: Arc<Mutex<UiStatus>>, threads: usize) {
    register(move |_uuid, e| {
        let handle = handle.clone();
        let context = Arc::clone(&context);
        let mut status = status.lock().unwrap();
        match e {
            Event::KeyCreated { .. } => {
                handle.run_on_ui_thread(move |ui| {
                    keystore_changed(ui, &context);
                    load_domains(ui, &context);
                    add_event_row(ui, Severity::Luck, "Key successfully created! Don't forget to save it!");
                    show_toast(ui, Severity::Luck, "New key mined successfully! Save it to a safe place!");
                });
            }
            Event::KeyLoaded { .. } | Event::KeySaved { .. } => {
                handle.run_on_ui_thread(move |ui| {
                    keystore_changed(ui, &context);
                    load_domains(ui, &context);
                });
            }
            Event::MinerStarted | Event::KeyGeneratorStarted => {
                status.mining = true;
                status.max_diff = 0;
                handle.run_on_ui_thread(|ui| {
                    add_event_row(ui, Severity::Info, "Mining started");
                    set_label(ui, "status_text", "Mining...");
                    set_visible(ui, "busy_box", true);
                });
            }
            Event::MinerStopped { success, full } => {
                status.mining = false;
                status.max_diff = 0;
                let syncing = status.syncing;
                handle.run_on_ui_thread(move |ui| {
                    if syncing {
                        set_label(ui, "status_text", "Syncing...");
                        set_visible(ui, "busy_box", true);
                    } else {
                        set_label(ui, "status_text", "Idle");
                        set_visible(ui, "busy_box", false);
                    }
                    if full {
                        if success {
                            load_domains(ui, &context);
                            add_event_row(ui, Severity::Luck, "Mining is successful!");
                            show_toast(ui, Severity::Luck, "Block successfully mined!");
                        } else {
                            add_event_row(ui, Severity::Info, "Mining finished without result.");
                            show_toast(ui, Severity::Warn, "Mining unsuccessful, sorry.");
                        }
                    }
                });
            }
            Event::MinerStats { thread, speed, max_diff, target_diff } => {
                if status.max_diff < max_diff {
                    status.max_diff = max_diff;
                }
                status.set_thread_speed(thread, speed);
                if thread as usize == threads - 1 {
                    let text = format!("Mining speed {} H/s, max found difficulty {}/{}.", status.get_speed(), status.max_diff, target_diff);
                    handle.run_on_ui_thread(move |ui| {
                        set_label(ui, "status_text", &text);
                        set_visible(ui, "busy_box", true);
                    });
                }
            }
            Event::KeyGeneratorStopped => {
                status.mining = false;
                let syncing = status.syncing;
                handle.run_on_ui_thread(move |ui| {
                    if syncing {
                        set_label(ui, "status_text", "Syncing...");
                        set_visible(ui, "busy_box", true);
                    } else {
                        set_label(ui, "status_text", "Idle");
                        set_visible(ui, "busy_box", false);
                    }
                });
            }
            Event::Syncing { have, height } => {
                status.syncing = true;
                status.synced_blocks = have;
                let started = height != status.sync_height;
                if started {
                    status.sync_height = height;
                }
                let mining = status.mining;
                handle.run_on_ui_thread(move |ui| {
                    if started {
                        add_event_row(ui, Severity::Info, "Syncing started...");
                    }
                    // While mining, the MinerStats speed line owns the status
                    // text — don't overwrite it with sync progress.
                    if !mining {
                        set_label(ui, "status_text", &format!("Synchronizing {}/{}", have, height));
                    }
                    set_visible(ui, "busy_box", true);
                });
            }
            Event::SyncFinished => {
                let finished = status.syncing;
                status.syncing = false;
                let mining = status.mining;
                handle.run_on_ui_thread(move |ui| {
                    if finished {
                        load_domains(ui, &context);
                        add_event_row(ui, Severity::Info, "Syncing finished.");
                    }
                    // While mining, the MinerStats speed line owns the status text.
                    if mining {
                        set_visible(ui, "busy_box", true);
                    } else if finished {
                        set_label(ui, "status_text", "Idle");
                        set_visible(ui, "busy_box", false);
                    }
                });
            }
            Event::NetworkStatus { blocks, domains, keys, nodes } => {
                let idle = !status.mining && !status.syncing && nodes >= 3;
                handle.run_on_ui_thread(move |ui| {
                    if idle {
                        set_label(ui, "status_text", "Idle");
                    }
                    set_stats(ui, blocks, domains, keys, nodes);
                });
            }
            Event::BlockchainChanged { index } => {
                debug!("Current blockchain height is {}", index);
                handle.run_on_ui_thread(move |ui| {
                    add_event_row(ui, Severity::Info, &format!("Blockchain changed, current block count is {} now.", index));
                });
            }
            Event::Error { text } => {
                handle.run_on_ui_thread(move |ui| {
                    show_toast(ui, Severity::Fail, &text);
                });
            }
            _ => {}
        }
        true
    });
}
