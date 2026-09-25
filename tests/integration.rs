//! End-to-end behavior of the public API: `GuardTransform` wrapping real
//! services, exercised with the actix Web test utilities.

use actix_guard_rs::{BLOCKED_MESSAGE, GuardTransform, OVERSIZE_MESSAGE, default_config};
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::http::header::CONTENT_TYPE;
use actix_web::test::{TestRequest, call_service, init_service, read_body};
use actix_web::{App, Error, HttpRequest, HttpResponse, web};
use bytes::Bytes;
use std::future::Ready;
use std::io;
use std::task::{Context, Poll};

/// An echo handler: answers `method path x-custom body`, so tests can assert
/// that the guard forwards the request untouched.
async fn echo(request: HttpRequest, body: Bytes) -> HttpResponse {
    let custom = request
        .headers()
        .get("x-custom")
        .map(|value| value.to_str().expect("ascii").to_owned())
        .unwrap_or_default();
    HttpResponse::Ok().body(format!(
        "{} {} {custom} {}",
        request.method(),
        request.path(),
        String::from_utf8_lossy(&body)
    ))
}

async fn body_text<B>(response: ServiceResponse<B>) -> String
where
    B: MessageBody,
{
    String::from_utf8_lossy(&read_body(response).await).into_owned()
}

fn get(path: &str) -> ServiceRequest {
    TestRequest::get().uri(path).to_srv_request()
}

fn post(path: &str, body: &str) -> ServiceRequest {
    TestRequest::post()
        .uri(path)
        .insert_header(("content-type", "application/json"))
        .set_payload(body.to_owned())
        .to_srv_request()
}

#[actix_web::test]
async fn benign_request_passes_through_untouched() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/items?limit=5")
        .insert_header(("x-custom", "hello"))
        .set_payload(r#"{"name":"renn"}"#)
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        r#"POST /api/items hello {"name":"renn"}"#
    );
}

#[actix_web::test]
async fn xss_payload_in_body_is_blocked() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/comment")
        .set_payload("<script>alert(1)</script>")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "text/plain; charset=utf-8"
    );
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[actix_web::test]
async fn traversal_payload_in_path_is_blocked() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/files/../../etc/passwd")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[actix_web::test]
async fn command_injection_in_query_is_blocked() {
    // Raw spaces are invalid in a URI, so the payload travels percent-encoded
    // and the engine's preprocessor decodes it back to `$(echo id)`.
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/search?cmd=$(echo%20id)")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn xss_payload_in_scanned_header_is_blocked() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/")
        .insert_header(("x-comment", "<script>alert(1)</script>"))
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn excluded_headers_are_never_scanned() {
    // `User-Agent` is on the exclusion list, so even a value that looks like a
    // payload is not fed to the engine. This pins the documented policy.
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/")
        .insert_header(("user-agent", "<script>alert(1)</script>"))
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn body_over_the_cap_is_rejected_with_413() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()).with_body_cap(16))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/items")
        .set_payload("this body is much longer than sixteen bytes")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_text(response).await, OVERSIZE_MESSAGE);
}

#[actix_web::test]
async fn body_under_the_cap_is_forwarded_intact() {
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()).with_body_cap(16))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::post()
        .uri("/api/items")
        .set_payload("short but valid")
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        "POST /api/items  short but valid"
    );
}

#[actix_web::test]
async fn custom_header_name_is_case_insensitive_on_the_exclusion_list() {
    // `HeaderMap` normalizes names to lowercase; scanning decisions must not
    // depend on the casing the client sent.
    let service = init_service(
        App::new()
            .wrap(GuardTransform::new(default_config()))
            .default_service(web::to(echo)),
    )
    .await;
    let request = TestRequest::get()
        .uri("/")
        .insert_header(("X-Custom", "benign value"))
        .insert_header(("user-agent", "actix-guard-tests/0.1"))
        .to_request();

    let response = call_service(&service, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn concurrent_requests_are_screened_independently() {
    let guard = GuardTransform::new(default_config())
        .new_transform(EchoService)
        .await
        .expect("transform");

    let handles: Vec<_> = (0..24)
        .map(|index| {
            let guard = guard.clone();
            let request = if index % 2 == 0 {
                get("/health")
            } else {
                post("/api/comment", "<script>alert(1)</script>")
            };
            actix_web::rt::spawn(
                async move { guard.call(request).await.expect("response").status() },
            )
        })
        .collect();

    for (index, handle) in handles.into_iter().enumerate() {
        let status = handle.await.expect("task");
        if index % 2 == 0 {
            assert_eq!(status, StatusCode::OK, "benign request {index}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "threat request {index}");
        }
    }
}

#[actix_web::test]
async fn inner_service_errors_are_propagated_not_swallowed() {
    let guard = GuardTransform::new(default_config())
        .new_transform(ErrorService)
        .await
        .expect("transform");

    let error = guard
        .call(get("/health"))
        .await
        .expect_err("inner error must propagate");
    assert!(error.to_string().contains("upstream down"));
}

#[actix_web::test]
async fn poll_ready_forwards_to_the_inner_service() {
    let guard = GuardTransform::new(default_config())
        .new_transform(EchoService)
        .await
        .expect("transform");
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Service::poll_ready(&guard, &mut cx) {
        Poll::Ready(result) => result.expect("ready"),
        Poll::Pending => panic!("echo service is always ready"),
    }
}

/// A minimal inner service for direct construction: always answers `200` with
/// an empty body and never inspects the request.
#[derive(Clone)]
struct EchoService;

impl Service<ServiceRequest> for EchoService {
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<ServiceResponse, Error>>;

    fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        std::future::ready(Ok(request.into_response(HttpResponse::Ok().finish())))
    }
}

/// An inner service that always fails, to prove the guard does not swallow
/// upstream errors.
#[derive(Clone)]
struct ErrorService;

impl Service<ServiceRequest> for ErrorService {
    type Response = ServiceResponse;
    type Error = Error;
    type Future = Ready<Result<ServiceResponse, Error>>;

    fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&self, _request: ServiceRequest) -> Self::Future {
        std::future::ready(Err(Error::from(io::Error::other("upstream down"))))
    }
}
