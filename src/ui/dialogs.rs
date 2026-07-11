//! Domain mining dialogs: new/renew domain, DNS record editor, and the
//! "Advanced" sub-dialogs (transfer owner, contacts, domain info).
//!
//! Each dialog is a modal child window with its own `UI`. All windows run on
//! the same event-loop thread, so dialog state is shared via `Rc<RefCell<..>>`;
//! updates of a parent window go through its `UiHandle` (every `UI` drains its
//! task queue on its own update tick).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use alfis::blockchain::transaction::{ContactsData, DomainData};
use alfis::blockchain::types::ZoneData;
use alfis::dns::protocol::DnsRecord;
use alfis::commons::MAX_DATA_LEN;
use alfis::miner::Miner;
use alfis::Context;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use lumio::prelude::*;

use super::actions::{action_create_domain, check_domain_available};
use super::toasts::{add_event_row, show_toast, Severity};

const OWNER_XML: &str = r#"
<Frame direction="vertical" width="max" height="max" padding="10">
    <Label text="Signing public key" font_style="Bold" height="min" margin_bottom="2"/>
    <Edit id="owner_signing" width="max" height="28" placeholder="Signing public key"
          allowed_chars="0123456789abcdefABCDEF" margin_bottom="6"/>
    <Label text="Encryption public key" font_style="Bold" height="min" margin_bottom="2"/>
    <Edit id="owner_encryption" width="max" height="28" placeholder="Encryption public key"
          allowed_chars="0123456789abcdefABCDEF" margin_bottom="6"/>
    <Label width="max" height="min" margin_bottom="8"
           text="If you wish to transfer this domain to another owner, you need to set new owners public keys. Signing public key to the first field. And encryption public key to the second field. If you don't want to transfer just leave both fields empty."/>
    <Frame width="max" height="max"/>
    <Frame direction="horizontal" width="max" height="min">
        <Frame width="max" height="min"/>
        <Button id="btn_ok" text="Ok" height="28" margin_right="4"/>
        <Button id="btn_cancel" text="Cancel" height="28"/>
    </Frame>
</Frame>
"#;

const CONTACTS_XML: &str = r#"
<Frame direction="vertical" width="max" height="max" padding="10">
    <Label text="One" font_style="Bold" height="min" margin_bottom="2"/>
    <Frame direction="horizontal" width="max" height="min" margin_bottom="6">
        <Edit id="contact1_name" width="150" height="28" placeholder="Name" margin_right="6"/>
        <Edit id="contact1_value" width="max" height="28" placeholder="Text or link"/>
    </Frame>
    <Label text="Two" font_style="Bold" height="min" margin_bottom="2"/>
    <Frame direction="horizontal" width="max" height="min" margin_bottom="6">
        <Edit id="contact2_name" width="150" height="28" placeholder="Name" margin_right="6"/>
        <Edit id="contact2_value" width="max" height="28" placeholder="Text or link"/>
    </Frame>
    <Label text="Three" font_style="Bold" height="min" margin_bottom="2"/>
    <Frame direction="horizontal" width="max" height="min" margin_bottom="6">
        <Edit id="contact3_name" width="150" height="28" placeholder="Name" margin_right="6"/>
        <Edit id="contact3_value" width="max" height="28" placeholder="Text or link"/>
    </Frame>
    <Label width="max" height="min" margin_bottom="8"
           text="You can add some contacts to your domain if you wish to be contacted regarding your services."/>
    <Frame width="max" height="max"/>
    <Frame direction="horizontal" width="max" height="min">
        <Frame width="max" height="min"/>
        <Button id="btn_ok" text="Ok" height="28" margin_right="4"/>
        <Button id="btn_cancel" text="Cancel" height="28"/>
    </Frame>
</Frame>
"#;

const INFO_XML: &str = r#"
<Frame direction="vertical" width="max" height="max" padding="10">
    <Label text="Some description about your domain" font_style="Bold" height="min" margin_bottom="4"/>
    <Memo id="info_text" width="max" height="max" margin_bottom="6"/>
    <Label width="max" height="min" margin_bottom="8"
           text="You can add some description to your domain if you wish for users or search engines to know what is it about."/>
    <Frame direction="horizontal" width="max" height="min">
        <Frame width="max" height="min"/>
        <Button id="btn_ok" text="Ok" height="28" margin_right="4"/>
        <Button id="btn_cancel" text="Cancel" height="28"/>
    </Frame>
</Frame>
"#;

/// Everything the domain dialog edits; shared by its sub-dialogs.
struct DomainState {
    zones: Vec<ZoneData>,
    zone_index: Option<usize>,
    records: Vec<DnsRecord>,
    /// URL-encoded, exactly as stored in the blockchain (the old web UI
    /// encoded with `encodeURIComponent`).
    contacts: Vec<ContactsData>,
    info: String,
    signing: String,
    encryption: String
}

type SharedState = Rc<RefCell<DomainState>>;

/// Opens the "New domain" dialog. `prefill` carries an owned domain for the
/// renewal/edit flow (full name + its current data).
pub fn show_domain_dialog(ui: &mut UI, context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>,
                          main_handle: UiHandle, prefill: Option<(String, DomainData)>) {
    let zones = context.lock().unwrap().chain.get_zones().clone();
    let mut dlg = UI::from_xml(include_str!("domain_dialog.xml"), 540, 440, default_typeface(), 1.0)
        .expect("Failed to parse domain dialog layout");

    let mut initial_name = String::new();
    let mut state = DomainState {
        zones,
        zone_index: None,
        records: Vec::new(),
        contacts: Vec::new(),
        info: String::new(),
        signing: String::new(),
        encryption: String::new()
    };
    if let Some((name, data)) = prefill {
        initial_name = name.trim_end_matches(&format!(".{}", &data.zone)).to_owned();
        state.zone_index = state.zones.iter().position(|z| z.name == data.zone);
        state.records = data.records;
        state.contacts = data.contacts;
        state.info = data.info;
    }
    let state: SharedState = Rc::new(RefCell::new(state));

    if let Some(view) = dlg.get_view("zone_combo") {
        if let Some(combo) = view.borrow().downcast_ref::<ComboBox>() {
            for zone in &state.borrow().zones {
                let mark = if zone.yggdrasil { "*" } else { "" };
                combo.add_item(&format!(".{}{}", &zone.name, mark));
            }
            if let Some(index) = state.borrow().zone_index {
                combo.set_selected(index);
            }
        }
        let context = Arc::clone(context);
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::SelectionChanged, Box::new(move |dlg_ui, _view, data| {
            if let EventData::Selected(index) = data {
                state.borrow_mut().zone_index = Some(*index);
                update_availability(dlg_ui, &context, &state);
            }
            true
        }));
    }

    if let Some(view) = dlg.get_view("domain_name") {
        if let Some(edit) = view.borrow().downcast_ref::<Edit>() {
            edit.set_text(&initial_name);
        }
        let context = Arc::clone(context);
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::TextChanged, Box::new(move |dlg_ui, _view, _data| {
            update_availability(dlg_ui, &context, &state);
            true
        }));
    }

    if let Some(view) = dlg.get_view("btn_add_record") {
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |dlg_ui, _view, _data| {
            show_record_dialog(dlg_ui, Rc::clone(&state));
            true
        }));
    }

    if let Some(view) = dlg.get_view("btn_del_record") {
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |dlg_ui, _view, _data| {
            let selected = dlg_ui.get_view("records_table")
                .and_then(|v| v.borrow().downcast_ref::<TableView>().and_then(|t| t.selected_row()));
            if let Some(index) = selected {
                let mut s = state.borrow_mut();
                if index < s.records.len() {
                    s.records.remove(index);
                }
                drop(s);
                refresh_records_table(dlg_ui, &state.borrow().records);
            }
            true
        }));
    }

    if let Some(view) = dlg.get_view("btn_advanced") {
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |dlg_ui, _view, _data| {
            show_advanced_menu(dlg_ui, Rc::clone(&state));
            true
        }));
    }

    if let Some(view) = dlg.get_view("btn_mine") {
        let context = Arc::clone(context);
        let miner = Arc::clone(miner);
        let state = Rc::clone(&state);
        let main_handle = main_handle.clone();
        view.borrow_mut().on_event(EventType::Click, Box::new(move |dlg_ui, _view, _data| {
            mine_domain(dlg_ui, &context, &miner, &state, &main_handle);
            true
        }));
    }

    if let Some(view) = dlg.get_view("btn_cancel") {
        view.borrow_mut().on_event(EventType::Click, Box::new(|dlg_ui, _view, _data| {
            dlg_ui.close_window();
            true
        }));
    }

    refresh_records_table(&mut dlg, &state.borrow().records);
    // Initial availability: empty name (or a prefilled owned name) gates the button.
    update_availability(&mut dlg, context, &state);

    ui.open_window(WindowRequest {
        title: String::from("New domain"),
        width: 640,
        height: 540,
        ui: dlg,
        modal: true,
        resizable: true,
        minimizable: false,
        maximizable: false,
    });
}

/// "Mine domain" button: validate and hand the block over to the miner.
fn mine_domain(dlg_ui: &mut UI, context: &Arc<Mutex<Context>>, miner: &Arc<Mutex<Miner>>,
               state: &SharedState, main_handle: &UiHandle) {
    let s = state.borrow();
    let Some(zone) = s.zone_index.and_then(|i| s.zones.get(i)) else {
        drop(s);
        show_toast(dlg_ui, Severity::Warn, "Select a domain zone first");
        return;
    };
    let name = get_edit_text(dlg_ui, "domain_name").to_lowercase();
    if name.is_empty() {
        drop(s);
        show_toast(dlg_ui, Severity::Warn, "Enter a domain name first");
        return;
    }
    let full_name = format!("{}.{}", &name, &zone.name);
    let data = DomainData::new(Default::default(), zone.name.clone(), s.info.clone(), s.records.clone(), s.contacts.clone());
    let signing = s.signing.clone();
    let encryption = s.encryption.clone();
    drop(s);
    let renewal = dlg_ui.get_view("renewal")
        .and_then(|v| v.borrow().downcast_ref::<CheckBox>().map(|c| c.is_checked()))
        .unwrap_or(false);

    match action_create_domain(context, miner, &full_name, data, &signing, &encryption, renewal) {
        Ok(()) => {
            main_handle.run_on_ui_thread(move |main_ui| {
                add_event_row(main_ui, Severity::Info, &format!("Mining of domain '{}' has started", &full_name));
            });
            dlg_ui.close_window();
        }
        Err(message) => {
            show_toast(dlg_ui, Severity::Warn, &message);
        }
    }
}

fn update_availability(dlg_ui: &mut UI, context: &Arc<Mutex<Context>>, state: &SharedState) {
    let name = get_edit_text(dlg_ui, "domain_name").to_lowercase();
    let available = {
        let s = state.borrow();
        match s.zone_index.and_then(|i| s.zones.get(i)) {
            Some(zone) if !name.is_empty() => {
                check_domain_available(context, &format!("{}.{}", &name, &zone.name))
            }
            _ => false
        }
    };
    if let Some(view) = dlg_ui.get_view("domain_name") {
        if let Some(edit) = view.borrow().downcast_ref::<Edit>() {
            edit.set_error(!available);
        }
    }
    for id in ["btn_mine", "btn_add_record"] {
        if let Some(view) = dlg_ui.get_view(id) {
            view.borrow_mut().set_enabled(available);
        }
    }
}

fn refresh_records_table(dlg_ui: &mut UI, records: &[DnsRecord]) {
    if let Some(view) = dlg_ui.get_view("records_table") {
        if let Some(table) = view.borrow().downcast_ref::<TableView>() {
            fill_records_table(table, records);
        }
    }
    dlg_ui.relayout();
}

fn fill_records_table(table: &TableView, records: &[DnsRecord]) {
    table.clear_rows();
    for record in records {
        let name = record.get_domain().unwrap_or_default();
        let name = if name.is_empty() { String::from("@") } else { name };
        table.add_row_text(vec![name, record_type_name(record).to_owned(), record.get_ttl().to_string(), record_data_text(record)]);
    }
}

/// The record list's "Data" column, composed like the old web UI did.
fn record_data_text(record: &DnsRecord) -> String {
    match record {
        DnsRecord::MX { priority, host, .. } => format!("{} {}", priority, host),
        DnsRecord::SRV { priority, weight, port, host, .. } => format!("{} {} {} {}", priority, weight, port, host),
        _ => record.get_data().unwrap_or_default()
    }
}

fn record_type_name(record: &DnsRecord) -> &'static str {
    match record {
        DnsRecord::A { .. } => "A",
        DnsRecord::AAAA { .. } => "AAAA",
        DnsRecord::CNAME { .. } => "CNAME",
        DnsRecord::NS { .. } => "NS",
        DnsRecord::MX { .. } => "MX",
        DnsRecord::SRV { .. } => "SRV",
        DnsRecord::TXT { .. } => "TXT",
        DnsRecord::TLSA { .. } => "TLSA",
        _ => "?"
    }
}

/// The "Advanced" popup: change owner / set contacts / set domain info.
fn show_advanced_menu(dlg_ui: &mut UI, state: SharedState) {
    let mut menu = PopupMenu::new();
    menu.add_item("owner", "", "Change domain owner");
    menu.add_item("contacts", "", "Set owner contacts");
    menu.add_item("info", "", "Set domain info");
    menu.on_event(EventType::Click, Box::new(move |dlg_ui: &mut UI, view: &dyn View, _data: &EventData| {
        let index = view.as_any().downcast_ref::<PopupMenu>().and_then(|m| m.get_hovered_index());
        match index {
            Some(0) => show_owner_dialog(dlg_ui, Rc::clone(&state)),
            Some(1) => show_contacts_dialog(dlg_ui, Rc::clone(&state)),
            Some(2) => show_info_dialog(dlg_ui, Rc::clone(&state)),
            _ => {}
        }
        true
    }));
    let element: Element = Rc::new(RefCell::new(menu));
    let pos = dlg_ui.get_mouse_pos();
    dlg_ui.show_popup(element, pos.x, pos.y, PopupDirection::BottomRight, PopupMode::Popup);
}

/// DNS record editor, opened as a nested modal window over the domain dialog.
fn show_record_dialog(dlg_ui: &mut UI, state: SharedState) {
    let rec = UI::from_xml(include_str!("record_dialog.xml"), 540, 280, default_typeface(), 1.0)
        .expect("Failed to parse record dialog layout");

    if let Some(view) = rec.get_view("record_type") {
        if let Some(combo) = view.borrow().downcast_ref::<ComboBox>() {
            for t in ["A", "AAAA", "CNAME", "NS", "MX", "SRV", "TXT", "TLSA"] {
                combo.add_item(t);
            }
            combo.set_selected(0);
        }
    }

    // All windows share the UI thread, so the domain dialog's records table
    // can be captured and updated directly from the record dialog's handler.
    let records_table = dlg_ui.get_view("records_table");

    if let Some(view) = rec.get_view("btn_add") {
        view.borrow_mut().on_event(EventType::Click, Box::new(move |rec_ui, _view, _data| {
            match build_record(rec_ui) {
                Some(record) => {
                    state.borrow_mut().records.push(record);
                    if let Some(table_el) = &records_table {
                        if let Some(table) = table_el.borrow().downcast_ref::<TableView>() {
                            fill_records_table(table, &state.borrow().records);
                        }
                    }
                    rec_ui.close_window();
                }
                None => {
                    show_toast(rec_ui, Severity::Warn, "Record is not valid!");
                }
            }
            true
        }));
    }
    if let Some(view) = rec.get_view("btn_cancel") {
        view.borrow_mut().on_event(EventType::Click, Box::new(|rec_ui, _view, _data| {
            rec_ui.close_window();
            true
        }));
    }

    dlg_ui.open_window(WindowRequest {
        title: String::from("New record"),
        width: 540,
        height: 280,
        ui: rec,
        modal: true,
        resizable: true,
        minimizable: false,
        maximizable: false,
    });
}

/// Builds a `DnsRecord` from the record dialog fields by deserializing the
/// same JSON shape the old web UI produced — identical validation rules
/// (a failed number parse or a bad address makes the record invalid).
fn build_record(rec_ui: &UI) -> Option<DnsRecord> {
    let name = get_edit_text(rec_ui, "record_name").to_lowercase();
    let rtype = rec_ui.get_view("record_type")
        .and_then(|v| v.borrow().downcast_ref::<ComboBox>().and_then(|c| c.get_selected_text()))?;
    let ttl: u32 = get_edit_text(rec_ui, "record_ttl").parse().ok()?;
    let data = get_edit_text(rec_ui, "record_data");
    let priority = || get_edit_text(rec_ui, "record_priority").parse::<u32>().ok();
    let weight = || get_edit_text(rec_ui, "record_weight").parse::<u32>().ok();
    let port = || get_edit_text(rec_ui, "record_port").parse::<u32>().ok();

    let value = match rtype.as_str() {
        "CNAME" | "NS" => serde_json::json!({"type": rtype, "domain": name, "ttl": ttl, "host": data}),
        "MX" => serde_json::json!({"type": rtype, "domain": name, "ttl": ttl, "priority": priority()?, "host": data}),
        "TXT" => serde_json::json!({"type": rtype, "domain": name, "ttl": ttl, "data": data}),
        "SRV" => serde_json::json!({"type": rtype, "domain": name, "ttl": ttl, "priority": priority()?, "weight": weight()?, "port": port()?, "host": data}),
        "TLSA" => {
            let bytes = alfis::commons::from_hex(&data).ok()?;
            serde_json::json!({"type": rtype, "domain": name, "ttl": ttl, "certificate_usage": priority()?, "selector": weight()?, "matching_type": port()?, "data": bytes})
        }
        _ => serde_json::json!({"type": rtype, "domain": name, "ttl": ttl, "addr": data})
    };

    match serde_json::from_value::<DnsRecord>(value) {
        Ok(record) => {
            let okay = record.get_data().map(|d| d.len() <= MAX_DATA_LEN).unwrap_or(false);
            okay.then_some(record)
        }
        Err(e) => {
            debug!("Invalid record: {}", e);
            None
        }
    }
}

fn show_owner_dialog(dlg_ui: &mut UI, state: SharedState) {
    let mut ui = UI::from_xml(OWNER_XML, 480, 280, default_typeface(), 1.0).unwrap();
    for (id, value) in [("owner_signing", &state.borrow().signing), ("owner_encryption", &state.borrow().encryption)] {
        if let Some(view) = ui.get_view(id) {
            if let Some(edit) = view.borrow().downcast_ref::<Edit>() {
                edit.set_max_length(Some(64));
                edit.set_text(value);
            }
        }
    }
    if let Some(view) = ui.get_view("btn_ok") {
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |owner_ui, _view, _data| {
            let signing = get_edit_text(owner_ui, "owner_signing");
            let encryption = get_edit_text(owner_ui, "owner_encryption");
            if !signing.is_empty() && !encryption.is_empty() {
                if is_valid_key(&signing) && is_valid_key(&encryption) {
                    let mut s = state.borrow_mut();
                    s.signing = signing;
                    s.encryption = encryption;
                } else {
                    show_toast(owner_ui, Severity::Warn, "Wrong owner keys! Each key is 64 hex characters.");
                    return true;
                }
            } else {
                let mut s = state.borrow_mut();
                s.signing.clear();
                s.encryption.clear();
            }
            owner_ui.close_window();
            true
        }));
    }
    wire_cancel(&mut ui);
    dlg_ui.open_window(WindowRequest { title: String::from("Change domain owner"), width: 480, height: 280, ui, modal: true, resizable: true, minimizable: false, maximizable: false });
}

fn show_contacts_dialog(dlg_ui: &mut UI, state: SharedState) {
    let mut ui = UI::from_xml(CONTACTS_XML, 480, 320, default_typeface(), 1.0).unwrap();
    for (index, contact) in state.borrow().contacts.iter().take(3).enumerate() {
        set_edit_text(&ui, &format!("contact{}_name", index + 1), &decode_uri_component(&contact.name));
        set_edit_text(&ui, &format!("contact{}_value", index + 1), &decode_uri_component(&contact.value));
    }
    if let Some(view) = ui.get_view("btn_ok") {
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |contacts_ui, _view, _data| {
            let mut contacts = Vec::new();
            for index in 1..=3 {
                let name = get_edit_text(contacts_ui, &format!("contact{}_name", index));
                let value = get_edit_text(contacts_ui, &format!("contact{}_value", index));
                if name.is_empty() || value.is_empty() {
                    continue;
                }
                contacts.push(ContactsData {
                    name: encode_uri_component(name.trim()),
                    value: encode_uri_component(value.trim())
                });
            }
            state.borrow_mut().contacts = contacts;
            contacts_ui.close_window();
            true
        }));
    }
    wire_cancel(&mut ui);
    dlg_ui.open_window(WindowRequest { title: String::from("Owner contacts"), width: 480, height: 320, ui, modal: true, resizable: false, minimizable: false, maximizable: false });
}

fn show_info_dialog(dlg_ui: &mut UI, state: SharedState) {
    let mut ui = UI::from_xml(INFO_XML, 480, 300, default_typeface(), 1.0).unwrap();
    if let Some(view) = ui.get_view("info_text") {
        if let Some(memo) = view.borrow().downcast_ref::<Memo>() {
            memo.set_max_length(Some(250));
            memo.set_text(&state.borrow().info);
        }
    }
    if let Some(view) = ui.get_view("btn_ok") {
        let state = Rc::clone(&state);
        view.borrow_mut().on_event(EventType::Click, Box::new(move |info_ui, _view, _data| {
            if let Some(view) = info_ui.get_view("info_text") {
                if let Some(memo) = view.borrow().downcast_ref::<Memo>() {
                    state.borrow_mut().info = memo.get_text();
                }
            }
            info_ui.close_window();
            true
        }));
    }
    wire_cancel(&mut ui);
    dlg_ui.open_window(WindowRequest { title: String::from("Domain info"), width: 480, height: 300, ui, modal: true, resizable: false, minimizable: false, maximizable: false });
}

fn wire_cancel(ui: &mut UI) {
    if let Some(view) = ui.get_view("btn_cancel") {
        view.borrow_mut().on_event(EventType::Click, Box::new(|ui, _view, _data| {
            ui.close_window();
            true
        }));
    }
}

fn is_valid_key(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit())
}

fn get_edit_text(ui: &UI, id: &str) -> String {
    ui.get_view(id)
        .and_then(|v| v.borrow().downcast_ref::<Edit>().map(|e| e.get_text()))
        .unwrap_or_default()
}

fn set_edit_text(ui: &UI, id: &str, text: &str) {
    if let Some(view) = ui.get_view(id) {
        if let Some(edit) = view.borrow().downcast_ref::<Edit>() {
            edit.set_text(text);
        }
    }
}

/// `encodeURIComponent` equivalent — contacts are stored URL-encoded in the
/// blockchain for compatibility with domains mined by the old web UI.
fn encode_uri_component(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => result.push(*byte as char),
            _ => result.push_str(&format!("%{:02X}", byte))
        }
    }
    result
}

/// `decodeURIComponent` equivalent (lenient: bad escapes pass through).
fn decode_uri_component(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hex = &bytes[i + 1..i + 3];
            if hex.iter().all(|b| b.is_ascii_hexdigit()) {
                let hex = std::str::from_utf8(hex).unwrap();
                result.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}
