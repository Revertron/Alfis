extern crate tiny_http;

use std::io::Cursor;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use tiny_http::{Header, Response, Server, StatusCode};

use crate::commons::WEB_SERVER_ADDR;

pub const INDEX: &str = include_str!("webview/index.html");
pub const BULMA: &str = include_str!("webview/bulma.css");
pub const STYLES: &str = include_str!("webview/styles.css");
pub const BUSY: &str = include_str!("webview/busy.css");
pub const SCRIPTS: &str = include_str!("webview/scripts.js");

pub fn start_server() {
    let server = Server::http(WEB_SERVER_ADDR).unwrap();

    for request in server.incoming_requests() {
        debug!("Got '{:?}' request for url: {}", request.method(), request.url());

        let response = process_request(&request.url());
        if request.respond(response).is_err() {
            warn!("Unable to send response!");
        }
    }
}

fn process_request(url: &str) -> Response<Cursor<Vec<u8>>> {
    let headers = vec![get_type(url)];
    match url {
        "/" => get_response(200, headers, INDEX),
        "/bulma.css" => get_response(200, headers, BULMA),
        "/styles.css" => get_response(200, headers, STYLES),
        "/busy.css" => get_response(200, headers, BUSY),
        "/scripts.js" => get_response(200, headers, SCRIPTS),
        &_ => get_response(404, vec!(), ""),
    }
}

fn get_response(code: u16, headers: Vec<Header>, body: &str) -> Response<Cursor<Vec<u8>>> {
    Response::new(StatusCode(code), headers, Cursor::new(body.as_bytes().to_vec()), Some(body.len()), None)
}

fn get_type(str: &str) -> Header {
    let parts: Vec<&str> = str.rsplitn(2, ".").collect();
    match parts[0] {
        "/" | "html" | "htm"  => Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
        "css" => Header::from_bytes(&b"Content-Type"[..], &b"text/css"[..]).unwrap(),
        "js" => Header::from_bytes(&b"Content-Type"[..], &b"application/javascript"[..]).unwrap(),
        &_ => Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap()
    }
}