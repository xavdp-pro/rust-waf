//! Private, read-only ban lookup for Nginx's access phase. Never forwards to PHP.
use crate::{App, Evidence, finish, ingress, one};
use axum::{body::Body, extract::Request, response::Response};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use hyper_util::rt::TokioIo;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, net::UnixListener, sync::Semaphore, time::timeout};

async fn check(app: Arc<App>, request: Request) -> Response {
    let start = Instant::now();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let reject = |status, reason| {
        finish(
            &app,
            &id,
            start,
            status,
            Evidence {
                decision: "block",
                reason,
                matches: serde_json::json!([]),
                backend_attempted: false,
                ban_started: false,
                application: None,
            },
            Bytes::new(),
            HeaderMap::new(),
        )
    };
    // This socket has no inspection/forwarding endpoint and accepts no body.
    if request.method() != "GET"
        || request.uri() != "/"
        || request.headers().contains_key("transfer-encoding")
        || request.headers().contains_key("expect")
        || request.headers().contains_key("upgrade")
        || one(request.headers(), "content-length").is_err()
        || one(request.headers(), "content-length")
            .ok()
            .flatten()
            .is_some_and(|s| s != "0")
    {
        return reject(StatusCode::BAD_REQUEST, "invalid_ban_lookup_request");
    }
    let ip = match one(request.headers(), "x-waf-client-ip") {
        Ok(Some(ip)) => match ip.parse() {
            Ok(ip) => ip,
            Err(_) => return reject(StatusCode::BAD_REQUEST, "missing_trusted_identity"),
        },
        _ => return reject(StatusCode::BAD_REQUEST, "missing_trusted_identity"),
    };
    let trusted = match one(request.headers(), "x-waf-admin-friend") {
        Ok(Some("0")) => false,
        Ok(Some("1")) => true,
        _ => return reject(StatusCode::BAD_REQUEST, "missing_trusted_access_flag"),
    };
    let remaining = match app.bans.lock() {
        Ok(table) => table.remaining(ip, trusted, Instant::now()),
        Err(_) => return reject(StatusCode::SERVICE_UNAVAILABLE, "ban_state_unavailable"),
    };
    if let Some(duration) = remaining {
        // auth_request accepts only 2xx, 401 or 403; use 403 for an active ban.
        let mut response = reject(StatusCode::FORBIDDEN, "temporary_local_ban_early");
        response.headers_mut().insert(
            "retry-after",
            HeaderValue::from_str(&duration.as_secs().saturating_add(1).to_string()).unwrap(),
        );
        return response;
    }
    // Allowed lookups are not visitor decisions and must not double-count traffic.
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

pub async fn serve(listener: UnixListener, app: Arc<App>) -> io::Result<()> {
    // Separate bounded capacity prevents full inspection tasks from starving
    // lookups. It cannot grow with pending visitor connections.
    let capacity = Arc::new(Semaphore::new(app.config.max_concurrent));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let prefix = match ingress::validate(
                &mut stream,
                app.inspector.policy.limits.header_bytes.min(8192),
                app.inspector.policy.limits.header_count.min(16),
                app.config.request_timeout_seconds.min(2),
            )
            .await
            {
                Ok(prefix) => prefix,
                Err(_) => {
                    let _ = timeout(Duration::from_secs(1), stream.write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
                    return;
                }
            };
            let service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(check(app, request.map(Body::new)).await)
                    }
                },
            );
            let connection = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(ingress::replay(stream, prefix)), service);
            let _ = timeout(Duration::from_secs(3), connection).await;
        });
    }
}
