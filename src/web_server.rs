use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

pub const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
pub const CONTENT_TYPE_JS: &str = "application/javascript";
pub const CONTENT_TYPE_CSS: &str = "text/css";

#[get("/")]
async fn html() -> impl Responder {
    let body = include_str!("webview/index.html");
    HttpResponse::Ok().body(body)
}

#[get("/bulma.css")]
async fn bulma() -> impl Responder {
    let body = include_str!("webview/bulma.css");
    HttpResponse::Ok().content_type(CONTENT_TYPE_CSS).body(body)
}

#[get("/styles.css")]
async fn styles() -> impl Responder {
    let body = include_str!("webview/styles.css");
    HttpResponse::Ok().content_type(CONTENT_TYPE_CSS).body(body)
}

#[get("/busy.css")]
async fn busy() -> impl Responder {
    let body = include_str!("webview/busy.css");
    HttpResponse::Ok().content_type(CONTENT_TYPE_CSS).body(body)
}

#[get("/scripts.js")]
async fn scripts() -> impl Responder {
    let body = include_str!("webview/scripts.js");
    HttpResponse::Ok().content_type(CONTENT_TYPE_JS).body(body)
}

#[post("/api")]
async fn api(req_body: String) -> impl Responder {
    HttpResponse::Ok().body("Not implemented")
}

#[actix_web::main]
pub async fn start_server() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(html)
            .service(bulma)
            .service(styles)
            .service(busy)
            .service(scripts)
            .service(api)
    }).bind("127.0.0.1:4280")?.run().await
}