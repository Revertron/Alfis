//! Password login and cookie sessions for the web UI.
//!
//! One shared password (from the `[webui]` config section) is exchanged for
//! a random session token in an HttpOnly cookie. Tokens live in memory and
//! expire after a day of inactivity. The cookie carries no `Secure` flag on
//! purpose: TLS is terminated by a reverse proxy, if any.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand::Rng;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tiny_http::{Request, Response};

use super::{header, read_json, respond_json, WebState};

const SESSION_COOKIE: &str = "alfis_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
/// Delay before answering a failed login, to slow down brute force.
const FAILED_LOGIN_DELAY: Duration = Duration::from_millis(500);
/// After this many consecutive failures logins are rejected outright...
const MAX_LOGIN_FAILURES: u32 = 5;
/// ...for this long. Rejection is immediate (no delay), so a flood of
/// login attempts cannot pin all worker threads in sleep either.
const LOGIN_LOCKOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct LoginRequest {
    password: String
}

pub fn login(state: &Arc<WebState>, request: Request) {
    {
        let mut throttle = state.login_failures.lock().unwrap();
        if let Some(until) = throttle.1 {
            if Instant::now() < until {
                respond_json(request, 429, &serde_json::json!({"error": "Too many failed attempts, try again later"}));
                return;
            }
            *throttle = (0, None);
        }
    }
    let Some((request, login)) = read_json::<LoginRequest>(request) else { return; };
    let ok: bool = state.password.as_bytes().ct_eq(login.password.as_bytes()).into();
    if !ok {
        let addr = request.remote_addr().map(|a| a.to_string()).unwrap_or_default();
        warn!(target: super::LOG_TARGET, "Failed web UI login attempt from {}", &addr);
        {
            let mut throttle = state.login_failures.lock().unwrap();
            throttle.0 += 1;
            if throttle.0 >= MAX_LOGIN_FAILURES {
                throttle.1 = Some(Instant::now() + LOGIN_LOCKOUT);
            }
        }
        thread::sleep(FAILED_LOGIN_DELAY);
        respond_json(request, 401, &serde_json::json!({"error": "Wrong password"}));
        return;
    }

    let token = new_token();
    {
        *state.login_failures.lock().unwrap() = (0, None);
        let mut sessions = state.sessions.lock().unwrap();
        sessions.retain(|_, last_used| last_used.elapsed() < SESSION_TTL);
        sessions.insert(token.clone(), Instant::now());
    }
    info!(target: super::LOG_TARGET, "Successful web UI login");
    let cookie = format!("{}={}; HttpOnly; SameSite=Strict; Path=/", SESSION_COOKIE, &token);
    let response = Response::from_string("{}")
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Set-Cookie", &cookie));
    let _ = request.respond(response);
}

pub fn logout(state: &Arc<WebState>, request: Request) {
    if let Some(token) = session_token(&request) {
        state.sessions.lock().unwrap().remove(&token);
    }
    let cookie = format!("{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0", SESSION_COOKIE);
    let response = Response::from_string("{}")
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Set-Cookie", &cookie));
    let _ = request.respond(response);
}

/// Checks the session cookie and refreshes its last-used time.
pub fn authorized(state: &Arc<WebState>, request: &Request) -> bool {
    let Some(token) = session_token(request) else { return false; };
    let mut sessions = state.sessions.lock().unwrap();
    sessions.retain(|_, last_used| last_used.elapsed() < SESSION_TTL);
    match sessions.get_mut(&token) {
        Some(last_used) => {
            *last_used = Instant::now();
            true
        }
        None => false
    }
}

fn session_token(request: &Request) -> Option<String> {
    for h in request.headers() {
        if !h.field.equiv("Cookie") {
            continue;
        }
        for pair in h.value.as_str().split(';') {
            if let Some((name, value)) = pair.trim().split_once('=') {
                if name == SESSION_COOKIE && !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

fn new_token() -> String {
    let mut rng = rand::rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    alfis::to_hex(&buf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_token_is_random_hex() {
        let one = super::new_token();
        let two = super::new_token();
        assert_eq!(one.len(), 64);
        assert_ne!(one, two);
        assert!(one.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
