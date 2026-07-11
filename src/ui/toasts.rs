//! Toast notifications and Events-tab rows, color-coded by severity.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use chrono::Local;
use lumio::prelude::*;

/// Mirrors the old web UI message types: `info`, `warn`, `fail`, `luck`.
#[derive(Clone, Copy, PartialEq)]
pub enum Severity {
    Info,
    Warn,
    Fail,
    Luck
}

impl Severity {
    /// Toast background / border colors (from the Lumio notification recipe).
    fn colors(self) -> (u32, u32) {
        match self {
            Severity::Info => (0xFFE6F2FF, 0xFF4A90E2),
            Severity::Warn => (0xFFFFF8E1, 0xFFE8A33D),
            Severity::Fail => (0xFFFFE5E5, 0xFFD83A3A),
            Severity::Luck => (0xFFE5FFE9, 0xFF3FAA56)
        }
    }

    /// Text color for Events-tab message labels; `None` = theme default.
    fn text_color(self) -> Option<&'static str> {
        match self {
            Severity::Info => None,
            Severity::Warn => Some("#E8A33D"),
            Severity::Fail => Some("#D83A3A"),
            Severity::Luck => Some("#3FAA56")
        }
    }
}

thread_local! {
    static NEXT_TOAST_ID: Cell<u32> = const { Cell::new(0) };
}

fn next_toast_id() -> String {
    NEXT_TOAST_ID.with(|c| {
        let v = c.get();
        c.set(v + 1);
        format!("toast-{}", v)
    })
}

/// Shows a toast notification in the corner of the window.
pub fn show_toast(ui: &mut UI, severity: Severity, message: &str) {
    let (bg, border) = severity.colors();
    let toast = make_toast(message, bg, border);
    ui.show_notification(toast, &next_toast_id(), Some(Duration::from_secs(5)));
}

/// Appends a timestamped row to the Events tab and keeps it scrolled to the end.
pub fn add_event_row(ui: &mut UI, severity: Severity, message: &str) {
    let time = Local::now().format("%d.%m.%y %X").to_string();
    if let Some(view) = ui.get_view("events_table") {
        if let Some(table) = view.borrow().downcast_ref::<TableView>() {
            let time_label = make_label(&time, None);
            let msg_label = make_label(message, severity.text_color());
            let row = table.row_count();
            table.add_row(vec![time_label, msg_label]);
            table.scroll_to_row(row);
        }
    }
    ui.relayout();
}

fn make_label(text: &str, color: Option<&str>) -> Element {
    let label: Element = Rc::new(RefCell::new(Label::default()));
    {
        let mut l = label.borrow_mut();
        l.set_any("text", text);
        if let Some(color) = color {
            l.set_any("text_color", color);
        }
    }
    label
}

/// A Frame holding the message Label and a close button (Lumio toast recipe).
fn make_toast(message: &str, bg: u32, border: u32) -> Element {
    let frame: Element = Rc::new(RefCell::new(Frame::new(
        lumio::types::rect((0, 0), (340, 40)),
        Dimension::Max,
        Dimension::Min,
    )));
    {
        let mut f = frame.borrow_mut();
        f.set_padding(8, 12, 8, 12);
        f.set_background(Some(bg));
        f.set_border_color(Some(border));
    }

    let label: Element = Rc::new(RefCell::new(Label::default()));
    {
        let mut l = label.borrow_mut();
        l.set_any("text", message);
        l.set_any("text_color", "#FF000000");
        l.set_any("font_size", "16");
        l.set_width(Dimension::Max);
        l.set_height(Dimension::Min);
    }

    let close: Element = Rc::new(RefCell::new(Button::default()));
    {
        let mut b = close.borrow_mut();
        b.set_any("text", "x");
        b.set_width(Dimension::Dip(28));
        b.set_height(Dimension::Dip(28));
        b.set_margin(0, 8, 0, 0);
        b.on_event(EventType::Click, Box::new(|ui, view, _data| {
            ui.dismiss_notification_for(view);
            true
        }));
    }

    {
        let mut f = frame.borrow_mut();
        let container = f.as_container_mut().unwrap();
        label.borrow_mut().set_parent(Some(Rc::downgrade(&frame)));
        close.borrow_mut().set_parent(Some(Rc::downgrade(&frame)));
        container.add_view(label);
        container.add_view(close);
    }

    frame
}
