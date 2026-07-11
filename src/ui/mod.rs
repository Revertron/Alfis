//! Lumio-based GUI for ALFIS. Replaces the former wry/tao webview UI.
//!
//! System tray (Windows only): the app shows a tray icon; closing the window
//! (X or Esc) hides it to the tray, double-clicking the icon — or the "Show
//! Window" menu item — restores it, and the tray "Quit" item exits. `--hide`
//! boots straight into the tray with the window hidden. On other platforms
//! there is no tray and closing the window quits the app.

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

use actions::{action_load_key, action_save_key, action_select_key};
use state::UiStatus;
use toasts::{add_event_row, Severity};

const WIDTH: u32 = 800;
const HEIGHT: u32 = 520;

/// Files embedded in the binary and served to Lumio by path. Lumio resolves
/// every `background_image`/`image` reference through the registered
/// `AssetsProvider`, so anything used from XML must be listed here.
struct Assets;

impl AssetsProvider for Assets {
    fn get_file(&self, path: &str) -> Option<&[u8]> {
        match path {
            "alfis_logo.svg" => Some(include_bytes!("../../img/logo/alfis_logo.svg")),
            "alfis_logo_white.svg" => Some(include_bytes!("../../img/logo/alfis_logo_white.svg")),
            _ => None
        }
    }
}

pub fn run_interface(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>, hide: bool) {
    #[cfg(not(target_os = "windows"))]
    if hide {
        warn!("--hide is only supported on Windows (system tray); showing the window");
    }
    // Must be set before the first paint (on the window thread): Lumio's asset
    // provider is thread-local and `run_loop` paints on this thread.
    set_provider(Box::new(Assets));
    let title = format!("ALFIS {}", env!("CARGO_PKG_VERSION"));

    let mut ui = UI::from_xml(include_str!("main.xml"), WIDTH, HEIGHT, default_typeface(), 1.0)
        .expect("Failed to parse main UI layout");

    let threads = match context.lock().unwrap().settings.mining.threads {
        0 => num_cpus::get(),
        t => t
    };
    let status = Arc::new(Mutex::new(UiStatus::new(threads)));

    wire_main_window(&mut ui, &context, &miner, &status);
    events::register_bus_listener(ui.handle(), Arc::clone(&context), Arc::clone(&status), threads);
    populate_initial_state(&mut ui, &context);

    ui.set_on_close(|_| {
        info!("Interface closed, exiting");
        post(Event::ActionQuit);
        // Give the network and miner threads a moment to wind down.
        thread::sleep(Duration::from_millis(100));
    });

    let dark_theme = context.lock().unwrap().settings.dark_theme;

    // The XML defaults the logo to the navy wordmark (for the light theme);
    // the dark palette needs the white-lettering copy to stay legible.
    if dark_theme {
        if let Some(view) = ui.get_view("logo") {
            if let Some(frame) = view.borrow_mut().downcast_mut::<Frame>() {
                frame.set_background_image(Some("alfis_logo_white.svg"));
            }
        }
    }

    // Handle for marshaling tray actions onto the UI thread — taken before
    // `ui` is moved into the launcher below.
    #[cfg(target_os = "windows")]
    let handle = ui.handle();

    // Logical (scaled) pixels match the old webview sizing on HiDPI displays.
    let mut config = WindowConfig::new(title.as_str(), WIDTH, HEIGHT)
        .logical_size()
        .center();
    if dark_theme {
        config = config.palette(Palette::dark());
    }
    // On Windows the app lives in the system tray: the close button hides the
    // window (and `--hide` starts it hidden) instead of quitting.
    #[cfg(target_os = "windows")]
    {
        config = config.hide_on_close(true).visible(!hide);
    }

    // Build the tray icon on this thread and keep it alive for the whole
    // process — `lumio::run` blocks until the app exits.
    #[cfg(target_os = "windows")]
    let _tray = build_tray(handle, &title);

    lumio::run(ui, config);
}

/// Builds the system-tray icon and menu, forwarding tray events onto the UI
/// thread via `handle`. The returned `TrayIcon` must be kept alive for the
/// whole process (dropping it removes the icon).
#[cfg(target_os = "windows")]
fn build_tray(handle: UiHandle, title: &str) -> tray_icon::TrayIcon {
    use tray_icon::menu::{Menu, MenuEvent, MenuItem};
    use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};

    let menu = Menu::new();
    let show_item = MenuItem::new("Show Window", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    menu.append(&show_item).expect("Failed to build tray menu");
    menu.append(&quit_item).expect("Failed to build tray menu");
    let show_id = show_item.id().clone();
    let quit_id = quit_item.id().clone();

    // Menu clicks: marshal onto the UI thread, which applies them via the
    // window handler. Quit goes through `request_quit` → `terminate_loop` →
    // `Drop for UI` → the `set_on_close` closure posts `ActionQuit` exactly
    // once, so we must NOT post it here.
    {
        let handle = handle.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if event.id == show_id {
                handle.run_on_ui_thread(|ui| ui.request_show());
            } else if event.id == quit_id {
                handle.run_on_ui_thread(|ui| ui.request_quit());
            }
        }));
    }

    // Left double-click (Windows-only event) shows the window. `with_menu_on_
    // left_click(false)` keeps the menu off left-click so the double-click
    // reliably arrives here; the menu stays available on right-click.
    {
        let handle = handle.clone();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            if let TrayIconEvent::DoubleClick { .. } = event {
                handle.run_on_ui_thread(|ui| ui.request_show());
            }
        }));
    }

    // Reuse the EXE icon embedded by build.rs: winres `set_icon` registers it
    // as integer resource ID 1 (equivalent to `set_icon_with_id(path, "1")`).
    let icon = Icon::from_resource(1, None).expect("Failed to load tray icon");

    TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip(title)
        .with_icon(icon)
        .build()
        .expect("Failed to build tray icon")
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
