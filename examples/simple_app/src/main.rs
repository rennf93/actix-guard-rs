//! Minimal guarded actix-web application, using the real adapter surface:
//! [`actix_guard_rs::GuardTransform`] registered with `web::scope::wrap`.
//!
//! Routes:
//!
//! | Route | Guard | Behavior |
//! |---|---|---|
//! | `GET /health` | excluded | `200 ok` |
//! | `GET /` | guarded | `200` greeting |
//! | `GET /search?q=...` | guarded | `200 search ok`, or `400` when the query trips the engine |
//! | `POST /echo` | guarded | echoes the body; `400` for a threat, `413` over the body cap |
//!
//! The excluded path is expressed with actix's own scoping: the guarded routes
//! live in a `web::scope` that carries the guard middleware, and `/health` is
//! registered on the `App` outside that scope. That is exactly the Python
//! distro's excluded-paths effect.

use actix_guard_rs::{GuardTransform, default_config};
use actix_web::{App, HttpResponse, HttpServer, web};

async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

async fn root() -> HttpResponse {
    HttpResponse::Ok().body("actix-guard-rs simple app")
}

async fn search() -> HttpResponse {
    HttpResponse::Ok().body("search ok")
}

async fn echo(body: web::Bytes) -> HttpResponse {
    HttpResponse::Ok().body(body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("APP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let bind_addr = addr.clone();
    HttpServer::new(move || {
        App::new().route("/health", web::get().to(health)).service(
            web::scope("")
                .wrap(GuardTransform::new(default_config()))
                .route("/", web::get().to(root))
                .route("/search", web::get().to(search))
                .route("/echo", web::post().to(echo)),
        )
    })
    .bind(bind_addr)?
    .run()
    .await
}
