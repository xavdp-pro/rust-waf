//! Private-socket HTTP gateway. The backend URI always uses a fixed destination.
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    response::Response,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};
use waf_core::{
    inspect::{Inspector, normalize, normalize_headers},
    profile::{Profile, compose},
};

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Observe,
    Enforce,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen_socket: PathBuf,
    backend_socket: PathBuf,
    site_id: String,
    profiles: Vec<PathBuf>,
    mode: Mode,
    max_concurrent: usize,
    request_timeout_seconds: u64,
    backend_timeout_seconds: u64,
    response_bytes: usize,
}
struct App {
    inspector: Inspector,
    config: Config,
    semaphore: Semaphore,
}
fn one<'a>(headers: &'a HeaderMap, key: &str) -> Result<Option<&'a str>, &'static str> {
    let mut values = headers.get_all(key).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err("duplicate_singleton_header");
    }
    first
        .map(|v| v.to_str().map_err(|_| "invalid_header_text"))
        .transpose()
}
fn strip_hop(headers: &mut HeaderMap) {
    let tokens = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>();
    for token in tokens {
        headers.remove(token);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
struct Evidence<'a> {
    decision: &'a str,
    reason: &'a str,
    matches: serde_json::Value,
    backend_attempted: bool,
}
fn finish(
    app: &App,
    id: &str,
    start: Instant,
    status: StatusCode,
    evidence: Evidence<'_>,
    body: Bytes,
    mut headers: HeaderMap,
) -> Response {
    let Evidence {
        decision,
        reason,
        matches,
        backend_attempted,
    } = evidence;
    let event = serde_json::json!({"schema_version":1,"ts_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        "request_id":id,"fingerprint":app.inspector.policy.fingerprint,"decision":decision,"reason":reason,"matches":matches,
        "status":status.as_u16(),"elapsed_us":start.elapsed().as_micros(),"backend_attempted":backend_attempted});
    let write_result = writeln!(io::stdout().lock(), "{event}");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = if write_result.is_ok() {
        status
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    strip_hop(&mut headers);
    headers.remove("content-length");
    headers.insert("x-request-id", HeaderValue::from_str(id).unwrap());
    *response.headers_mut() = headers;
    response
}
async fn handle(State(app): State<Arc<App>>, request: Request) -> Response {
    let start = Instant::now();
    // Unix socket permissions are the trust boundary; public Nginx overwrites identity headers.
    let id = uuid::Uuid::new_v4().simple().to_string();
    let deny = |status, reason| {
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
            },
            Bytes::from_static(b"Request denied\n"),
            HeaderMap::new(),
        )
    };
    let _permit = match app.semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => return deny(StatusCode::SERVICE_UNAVAILABLE, "concurrency_limit"),
    };
    let (mut parts, body) = request.into_parts();
    if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .contains(&parts.method.as_str())
    {
        return deny(StatusCode::METHOD_NOT_ALLOWED, "unsupported_method");
    }
    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        return deny(StatusCode::BAD_REQUEST, "absolute_request_target");
    }
    let limits = &app.inspector.policy.limits;
    if parts.headers.len() > limits.header_count
        || parts
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > limits.header_bytes
    {
        return deny(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "header_limit");
    }
    for name in [
        "host",
        "content-type",
        "content-length",
        "content-encoding",
        "x-waf-client-ip",
        "x-waf-admin-friend",
    ] {
        if let Err(reason) = one(&parts.headers, name) {
            return deny(StatusCode::BAD_REQUEST, reason);
        }
    }
    let client_ip = one(&parts.headers, "x-waf-client-ip").ok().flatten();
    if client_ip.is_none_or(|s| s.parse::<std::net::IpAddr>().is_err()) {
        return deny(StatusCode::BAD_REQUEST, "missing_trusted_identity");
    }
    if !matches!(
        one(&parts.headers, "x-waf-admin-friend").ok().flatten(),
        Some("0" | "1")
    ) {
        return deny(StatusCode::BAD_REQUEST, "missing_trusted_access_flag");
    }
    if parts.headers.contains_key("upgrade") || parts.headers.contains_key("expect") {
        return deny(StatusCode::BAD_REQUEST, "unsupported_transport_feature");
    }
    if one(&parts.headers, "content-encoding")
        .ok()
        .flatten()
        .is_some_and(|s| s != "identity")
    {
        return deny(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_encoding",
        );
    }
    if parts.headers.contains_key("content-length")
        && parts.headers.contains_key("transfer-encoding")
    {
        return deny(StatusCode::BAD_REQUEST, "ambiguous_framing");
    }
    if let Some(value) = one(&parts.headers, "content-length").ok().flatten() {
        match value.parse::<usize>() {
            Ok(length) if length <= limits.body_bytes => {}
            _ => return deny(StatusCode::PAYLOAD_TOO_LARGE, "declared_body_limit"),
        }
    }
    let body = match timeout(
        Duration::from_secs(app.config.request_timeout_seconds),
        to_bytes(body, limits.body_bytes),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return deny(StatusCode::PAYLOAD_TOO_LARGE, "body_limit_or_read_error"),
        Err(_) => return deny(StatusCode::REQUEST_TIMEOUT, "body_timeout"),
    };
    let content_type = one(&parts.headers, "content-type")
        .ok()
        .flatten()
        .unwrap_or("");
    let mut views = match normalize(
        &app.inspector.policy,
        parts.uri.path(),
        parts.uri.query().unwrap_or(""),
        content_type,
        body.clone(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return deny(StatusCode::BAD_REQUEST, &e.0),
    };
    let headers = parts
        .headers
        .iter()
        .map(|(key, value)| value.to_str().map(|v| (key.to_string(), v.to_string())))
        .collect::<Result<Vec<_>, _>>();
    let headers = match headers {
        Ok(h) => h,
        Err(_) => return deny(StatusCode::BAD_REQUEST, "invalid_header_text"),
    };
    views.headers = match normalize_headers(&app.inspector.policy, &headers) {
        Ok(h) => h,
        Err(e) => return deny(StatusCode::BAD_REQUEST, &e.0),
    };
    let matches = app.inspector.inspect(&views, parts.method.as_str());
    let blocked = matches.iter().any(|m| m.exception_profile.is_none());
    let records = serde_json::to_value(&matches).unwrap();
    if blocked && app.config.mode == Mode::Enforce {
        return finish(
            &app,
            &id,
            start,
            StatusCode::FORBIDDEN,
            Evidence {
                decision: "block",
                reason: "rule_match",
                matches: records,
                backend_attempted: false,
            },
            Bytes::from_static(b"Request denied\n"),
            HeaderMap::new(),
        );
    }
    let invalid_connection = parts.headers.get_all("connection").iter().any(|value| {
        value.to_str().map_or(true, |text| {
            text.split(',').any(|token| {
                !matches!(
                    token.trim().to_ascii_lowercase().as_str(),
                    "close" | "keep-alive"
                )
            })
        })
    });
    if invalid_connection {
        return deny(StatusCode::BAD_REQUEST, "unsafe_connection_tokens");
    }
    strip_hop(&mut parts.headers);
    for name in [
        "x-request-id",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "forwarded",
    ] {
        parts.headers.remove(name);
    }
    parts
        .headers
        .insert("x-request-id", HeaderValue::from_str(&id).unwrap());
    parts.headers.insert(
        "content-length",
        HeaderValue::from_str(&body.len().to_string()).unwrap(),
    );
    let request = http::Request::from_parts(parts, Full::new(body));
    let forward = async {
        let stream = UnixStream::connect(&app.config.backend_socket).await?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        // Drop guard prevents a cancelled timeout from leaving backend connection tasks alive.
        struct Abort(tokio::task::JoinHandle<()>);
        impl Drop for Abort {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _guard = Abort(task);
        let response = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        let (parts, body) = response.into_parts();
        let body = to_bytes(Body::new(body), app.config.response_bytes)
            .await
            .map_err(io::Error::other)?;
        Ok::<_, io::Error>((parts.status, parts.headers, body))
    };
    match timeout(
        Duration::from_secs(app.config.backend_timeout_seconds),
        forward,
    )
    .await
    {
        Ok(Ok((status, headers, body))) => finish(
            &app,
            &id,
            start,
            status,
            Evidence {
                decision: if blocked { "observe" } else { "allow" },
                reason: "inspected",
                matches: records,
                backend_attempted: true,
            },
            body,
            headers,
        ),
        _ => finish(
            &app,
            &id,
            start,
            StatusCode::BAD_GATEWAY,
            Evidence {
                decision: "error",
                reason: "backend_unavailable_or_response_limit",
                matches: records,
                backend_attempted: true,
            },
            Bytes::from_static(b"Backend unavailable\n"),
            HeaderMap::new(),
        ),
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: waf-proxy CONFIG.json")?;
    let bytes = fs::read(path)?;
    if bytes.len() > 65536 {
        return Err("configuration exceeds 64 KiB".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    if config.max_concurrent == 0
        || config.max_concurrent > 64
        || !(1..=60).contains(&config.request_timeout_seconds)
        || !(1..=120).contains(&config.backend_timeout_seconds)
        || config.response_bytes == 0
        || config.response_bytes > 64 * 1024 * 1024
        || config.listen_socket == config.backend_socket
        || !config.listen_socket.is_absolute()
        || !config.backend_socket.is_absolute()
    {
        return Err("invalid runtime bounds or socket paths".into());
    }
    let profiles = config
        .profiles
        .iter()
        .map(|p| Profile::parse(&fs::read(p)?).map_err(Into::into))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let inspector = Inspector::new(compose(profiles, &config.site_id)?)?;
    // Never unlink an existing socket: a second process must fail, not steal the listener.
    let listener = UnixListener::bind(&config.listen_socket)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&config.listen_socket, fs::Permissions::from_mode(0o660))?;
    let app = Arc::new(App {
        semaphore: Semaphore::new(config.max_concurrent),
        config,
        inspector,
    });
    axum::serve(listener, Router::new().fallback(handle).with_state(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
