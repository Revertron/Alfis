//! Web UI for headless (server) installations, started by `--web-ui`.
//!
//! A small synchronous HTTP server (tiny_http) that serves the embedded
//! single-page UI and a JSON API over it. Live updates are pushed to the
//! browser through a Server-Sent Events stream fed by the event bus.
//!
//! The server speaks plain HTTP and is password-gated (see `auth`); for
//! remote access users are expected to tunnel it over SSH or put a TLS
//! reverse proxy in front of it.

mod api;
mod auth;
mod events;

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use alfis::commons::status::UiStatus;
use alfis::miner::Miner;
use alfis::Context;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use tiny_http::{Header, Method, Request, Response, Server};

const LOG_TARGET: &str = "alfis::WebUi";
/// Maximum request body we are willing to read (a domain with 30 records
/// fits in a few KB).
const MAX_BODY: u64 = 65536;
/// Maximum requests served concurrently (each takes a thread).
const MAX_WORKERS: usize = 32;
/// Maximum concurrently connected event-stream clients.
const MAX_SSE_CLIENTS: usize = 8;

/// Everything the request handlers need, shared between worker threads.
pub struct WebState {
    pub context: Arc<Mutex<Context>>,
    pub miner: Arc<Mutex<Miner>>,
    /// Password from the config, required to log in.
    pub password: String,
    /// Logged-in session tokens with their last-used time.
    pub sessions: Mutex<HashMap<String, Instant>>,
    /// Consecutive failed logins and the lockout deadline they triggered.
    pub login_failures: Mutex<(u32, Option<Instant>)>,
    /// Mining/syncing state accumulated from bus events.
    pub status: Mutex<UiStatus>,
    /// Connected nodes count from the last `NetworkStatus` event.
    pub nodes: AtomicUsize,
    /// Senders of connected SSE clients; dead ones are dropped on send.
    pub clients: Mutex<Vec<Sender<String>>>,
    /// Ring buffer of recent event rows for the Events tab.
    pub events_log: Mutex<VecDeque<serde_json::Value>>,
    /// File name to save a freshly mined key to (set by `/api/keys/create`).
    pub pending_key_file: Mutex<Option<String>>
}

/// Releases a worker slot when dropped, however the request handler ends.
struct WorkerGuard(Arc<AtomicUsize>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Binds the configured address and spawns the accept loop thread.
/// Returns an error when no password is configured or the bind fails.
pub fn start_web_ui(context: Arc<Mutex<Context>>, miner: Arc<Mutex<Miner>>) -> Result<(), String> {
    let (listen, password, threads) = {
        let c = context.lock().unwrap();
        let threads = match c.settings.mining.threads {
            0 => num_cpus::get(),
            t => t
        };
        (c.settings.webui.listen.clone(), c.settings.webui.password.clone(), threads)
    };
    if password.is_empty() {
        return Err(String::from("no password is set in the [webui] section of the config"));
    }
    let server = Server::http(&listen).map_err(|e| format!("cannot listen on {}: {}", &listen, e))?;

    let state = Arc::new(WebState {
        context,
        miner,
        password,
        sessions: Mutex::new(HashMap::new()),
        login_failures: Mutex::new((0, None)),
        status: Mutex::new(UiStatus::new(threads)),
        nodes: AtomicUsize::new(0),
        clients: Mutex::new(Vec::new()),
        events_log: Mutex::new(VecDeque::new()),
        pending_key_file: Mutex::new(None)
    });
    events::register_bus_listener(Arc::clone(&state), threads);

    let workers = Arc::new(AtomicUsize::new(0));
    thread::Builder::new().name(String::from("WebUI")).spawn(move || {
        for request in server.incoming_requests() {
            if workers.load(Ordering::SeqCst) >= MAX_WORKERS {
                let _ = request.respond(Response::empty(503));
                continue;
            }
            workers.fetch_add(1, Ordering::SeqCst);
            let state = Arc::clone(&state);
            // The guard decrements on drop, so neither a panicking handler
            // nor a failed spawn (which drops the closure) leaks the slot.
            let guard = WorkerGuard(Arc::clone(&workers));
            let _ = thread::Builder::new().name(String::from("WebUI worker")).spawn(move || {
                let _guard = guard;
                handle_request(&state, request);
            });
        }
    }).map_err(|e| format!("could not start server thread: {}", e))?;

    info!(target: LOG_TARGET, "Web UI is listening on http://{}", &listen);
    Ok(())
}

fn handle_request(state: &Arc<WebState>, request: Request) {
    let url = request.url().to_owned();
    let path = url.split('?').next().unwrap_or("").to_owned();
    trace!(target: LOG_TARGET, "{} {}", request.method(), &url);

    // Static assets and login are served without a session
    match (request.method().clone(), path.as_str()) {
        (Method::Get, "/") | (Method::Get, "/index.html") => return serve_asset(request, "index.html"),
        (Method::Get, "/scripts.js") => return serve_asset(request, "scripts.js"),
        (Method::Get, "/styles.css") => return serve_asset(request, "styles.css"),
        (Method::Get, "/bulma.css") => return serve_asset(request, "bulma.css"),
        (Method::Get, "/busy_indicator.css") => return serve_asset(request, "busy_indicator.css"),
        (Method::Get, "/logo.svg") => return serve_asset(request, "logo.svg"),
        (Method::Post, "/api/login") => return auth::login(state, request),
        _ => {}
    }

    if !path.starts_with("/api/") {
        return respond_json(request, 404, &serde_json::json!({"error": "Not found"}));
    }
    if !auth::authorized(state, &request) {
        return respond_json(request, 401, &serde_json::json!({"error": "Unauthorized"}));
    }

    match (request.method().clone(), path.as_str()) {
        (Method::Post, "/api/logout") => auth::logout(state, request),
        (Method::Get, "/api/status") => api::status(state, request),
        (Method::Get, "/api/keys") => api::keys(state, request),
        (Method::Post, "/api/keys/select") => api::keys_select(state, request),
        (Method::Post, "/api/keys/create") => api::keys_create(state, request),
        (Method::Get, "/api/domains") => api::domains(state, request),
        (Method::Get, "/api/domains/check") => api::domains_check(state, request, &url),
        (Method::Post, "/api/domains") => api::domains_create(state, request),
        (Method::Get, "/api/zones") => api::zones(state, request),
        (Method::Post, "/api/records/check") => api::records_check(state, request),
        (Method::Post, "/api/mining/stop") => api::mining_stop(state, request),
        (Method::Get, "/api/events/log") => api::events_log(state, request),
        (Method::Get, "/api/events") => events::serve_sse(state, request),
        _ => respond_json(request, 404, &serde_json::json!({"error": "Not found"}))
    }
}

fn serve_asset(request: Request, name: &str) {
    let (content, content_type): (&[u8], &str) = match name {
        "index.html" => (include_bytes!("assets/index.html"), "text/html; charset=utf-8"),
        "scripts.js" => (include_bytes!("assets/scripts.js"), "application/javascript; charset=utf-8"),
        "styles.css" => (include_bytes!("assets/styles.css"), "text/css; charset=utf-8"),
        "bulma.css" => (include_bytes!("assets/bulma.css"), "text/css; charset=utf-8"),
        "busy_indicator.css" => (include_bytes!("assets/busy_indicator.css"), "text/css; charset=utf-8"),
        "logo.svg" => (include_bytes!("../../img/logo/alfis_logo.svg"), "image/svg+xml"),
        _ => {
            let _ = request.respond(Response::empty(404));
            return;
        }
    };
    let response = Response::from_data(content).with_header(header("Content-Type", content_type));
    let _ = request.respond(response);
}

/// Builds a `tiny_http` header from static strings known to be valid.
pub fn header(field: &str, value: &str) -> Header {
    Header::from_bytes(field.as_bytes(), value.as_bytes()).expect("Invalid header")
}

/// Sends a JSON response with the given status code, ignoring I/O errors
/// (the client may be gone already).
pub fn respond_json(request: Request, status: u16, body: &serde_json::Value) {
    let response = Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Cache-Control", "no-store"));
    let _ = request.respond(response);
}

/// Reads a size-limited request body as a string.
pub fn read_body(request: &mut Request) -> Option<String> {
    let mut body = String::new();
    match request.as_reader().take(MAX_BODY).read_to_string(&mut body) {
        Ok(_) => Some(body),
        Err(_) => None
    }
}

/// Reads and parses a size-limited JSON request body, answering
/// 400 Bad Request itself when parsing fails.
pub fn read_json<T: serde::de::DeserializeOwned>(mut request: Request) -> Option<(Request, T)> {
    let body = match read_body(&mut request) {
        Some(body) => body,
        None => {
            respond_json(request, 400, &serde_json::json!({"error": "Cannot read request body"}));
            return None;
        }
    };
    match serde_json::from_str::<T>(&body) {
        Ok(value) => Some((request, value)),
        Err(e) => {
            debug!(target: LOG_TARGET, "Bad request body: {}", e);
            respond_json(request, 400, &serde_json::json!({"error": "Malformed request"}));
            None
        }
    }
}
