//! Lumio-based GUI for ALFIS. Replaces the former wry/tao webview UI.
//!
//! NOTE — system tray support was dropped in the webview-to-Lumio migration.
//! The old behavior, recorded here for future restoration:
//!   - tray icon with tooltip "ALFIS {version}\nConnected: {nodes}"
//!     (node count refreshed on tray-icon mouse Enter)
//!   - left double-click on the icon: show + focus the window
//!   - menu: "Show Window", "Quit" (Quit posted Event::ActionQuit, slept
//!     100 ms, then exited the event loop)
//!   - closing the window hid it instead of quitting when a tray was
//!     available; `--hide` started with the window hidden
//! Currently: closing the window quits the app (posts Event::ActionQuit),
//! and `--hide` is ignored.

extern crate open;
extern crate tinyfiledialogs as tfd;

mod actions;
mod dialogs;
mod events;
mod state;
mod toasts;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use alfis::event::Event;
use alfis::eventbus::post;
use alfis::keystore;
use alfis::miner::Miner;
use alfis::Context;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use lumio::prelude::*;
use lumio::speedy2d::dimen::Vector2;
use lumio::speedy2d::window::{WindowCreationOptions, WindowPosition, WindowSize};
use lumio::speedy2d::Window;

use actions::{action_load_key, action_save_key, action_select_key};
use state::UiStatus;
use toasts::{add_event_row, Severity};

const WIDTH: u32 = 1024;
const HEIGHT: u32 = 720;

pub fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, hide: bool) {
    if hide {
        warn!("The --hide option is not supported anymore (tray support removed), showing the window");
    }
    let title = format!("ALFIS {}", env!("CARGO_PKG_VERSION"));

    let mut ui = UI::from_xml(include_str!("main.xml"), WIDTH, HEIGHT, Classic::typeface(), 1.0)
        .expect("Failed to parse main UI layout");

    let threads = match context.lock().unwrap().settings.mining.threads {
        0 => num_cpus::get(),
        t => t
    };
    let status = Arc::new(Mutex::new(UiStatus::new(threads)));

    wire_main_window(&mut ui, &context, &miner, &status);
    events::register_bus_listener(ui.handle(), Arc::clone(&context), Arc::clone(&status), threads);
    populate_initial_state(&mut ui, &context);

    ui.set_on_close(|| {
        info!("Interface closed, exiting");
        post(Event::ActionQuit);
        // Give the network and miner threads a moment to wind down.
        thread::sleep(Duration::from_millis(100));
    });

    let dark_theme = context.lock().unwrap().settings.dark_theme;

    // Scaled (logical) pixels: matches the old webview sizing on HiDPI displays.
    let window_size = WindowSize::ScaledPixels(Vector2::new(WIDTH as f32, HEIGHT as f32));
    let options = WindowCreationOptions::new_windowed(window_size, Some(WindowPosition::Center));
    let window: Window<WinEvent> = Window::new_with_user_events(&title, options)
        .expect("Failed to create the window");
    let sender = window.create_user_event_sender();
    let mut win = Win::new(ui, sender);
    if dark_theme {
        win.set_palette(Palette::dark());
    }
    window.run_loop(win);
}

fn wire_main_window(ui: &mut UI, context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>, status: &Arc<Mutex<UiStatus>>) {
    if let Some(view) = ui.get_view("btn_new_domain") {
        let context = Arc::clone(context);
        let miner = Arc::clone(miner);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |ui, _view, _data| {
            let handle = ui.handle();
            dialogs::show_domain_dialog(ui, &context, &miner, handle, None);
            true
        }));
    }
    if let Some(view) = ui.get_view("domains_table") {
        let context = Arc::clone(context);
        let miner = Arc::clone(miner);
        view.borrow_mut().on_event(EventType::DoubleClick, Box::new(move |ui, view, _data| {
            // Rows are inserted sorted by name (see actions::load_domains), so
            // the raw row index maps to the same position in a fresh sorted fetch.
            let selected = view.as_any().downcast_ref::<TableView>().and_then(|t| t.selected_row());
            if let Some(index) = selected {
                let domain = {
                    let c = context.lock().unwrap();
                    let domains = c.chain.get_my_domains(c.get_keystore());
                    let mut domains = domains.values().cloned().collect::<Vec<_>>();
                    domains.sort_by(|a, b| a.0.cmp(&b.0));
                    domains.get(index).cloned()
                };
                if let Some((name, _timestamp, data)) = domain {
                    let handle = ui.handle();
                    dialogs::show_domain_dialog(ui, &context, &miner, handle, Some((name, data)));
                }
            }
            true
        }));
    }
    if let Some(view) = ui.get_view("btn_load_key") {
        let context = Arc::clone(context);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |ui, _view, _data| {
            action_load_key(ui, &context);
            true
        }));
    }
    if let Some(view) = ui.get_view("btn_save_key") {
        let context = Arc::clone(context);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |_ui, _view, _data| {
            action_save_key(&context);
            true
        }));
    }
    if let Some(view) = ui.get_view("btn_create_key") {
        let context = Arc::clone(context);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |_ui, _view, _data| {
            keystore::create_key(Arc::clone(&context));
            true
        }));
    }
    if let Some(view) = ui.get_view("keys_combo") {
        let context = Arc::clone(context);
        view.borrow_mut().on_event(EventType::SelectionChanged, Box::new(move |_ui, _view, data| {
            if let EventData::Selected(index) = data {
                action_select_key(&context, *index);
            }
            true
        }));
    }
    if let Some(view) = ui.get_view("busy") {
        let status = Arc::clone(status);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |ui, _view, _data| {
            // Only mining can be canceled by the user; syncing cannot.
            if status.lock().unwrap().mining {
                ui.show_confirm("Stop mining", "Do you want to stop all mining tasks?", |_ui, ok| {
                    if ok {
                        post(Event::ActionStopMining);
                    }
                });
            }
            true
        }));
    }
    if let Some(view) = ui.get_view("help_link") {
        view.borrow_mut().on_event(EventType::Click, Box::new(|_ui, _view, _data| {
            if open::that("https://github.com/Revertron/Alfis").is_err() {
                warn!("Could not open the link in browser");
            }
            false
        }));
    }
    // Ctrl+1..4 switch tabs, like browser tab shortcuts.
    for (index, key) in ["Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4"].iter().enumerate() {
        ui.add_shortcut(key, Box::new(move |ui| {
            if let Some(view) = ui.get_view("tabs") {
                if let Some(tabs) = view.borrow().downcast_ref::<TabView>() {
                    tabs.set_active_tab(index);
                }
            }
            ui.relayout();
            true
        }));
    }
}

/// Fills the UI with the state known before the window opens — the old
/// webview did this in `action_loaded` after a `Loaded` round-trip.
fn populate_initial_state(ui: &mut UI, context: &Arc<Mutex<Context>>) {
    actions::keystore_changed(ui, context);
    actions::load_domains(ui, context);
    set_label(ui, "status_text", "No connection");

    let (height, domains, users, keystore_event) = {
        let c = context.lock().unwrap();
        let keystore_event = c.get_keystore().map(|keystore| Event::KeyLoaded {
            path: keystore.get_path().to_owned(),
            public: keystore.get_public().to_string(),
            hash: keystore.get_hash().to_string()
        });
        (c.chain.get_height(), c.chain.get_domains_count(), c.chain.get_users_count(), keystore_event)
    };
    actions::set_stats(ui, height, domains, users, 0);
    add_event_row(ui, Severity::Info, "Application loaded");

    if let Some(event) = keystore_event {
        post(event);
    }
    if height > 0 {
        post(Event::BlockchainChanged { index: height });
    }
}

/// Sets the text of a `Label` by view id; silently ignores missing views.
pub(crate) fn set_label(ui: &UI, id: &str, text: &str) {
    if let Some(view) = ui.get_view(id) {
        if let Some(label) = view.borrow_mut().downcast_mut::<Label>() {
            label.set_text(text);
        }
    }
}

/// Shows or hides a view (using `Gone` so hidden views free their space).
pub(crate) fn set_visible(ui: &mut UI, id: &str, visible: bool) {
    if let Some(view) = ui.get_view(id) {
        let visibility = if visible { Visibility::Visible } else { Visibility::Gone };
        view.borrow_mut().set_visibility(visibility);
        ui.relayout();
    }
}
