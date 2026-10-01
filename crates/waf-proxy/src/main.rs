//! Private-socket HTTP gateway. The backend URI always uses a fixed destination.
mod ban_gate;
mod ingress;
use axum::{
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
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};
use waf_core::{
    ban::{BanConfig, BanTable},
    inspect::{Inspector, normalize_headers},
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
    #[serde(default)]
    ban_lookup_socket: Option<PathBuf>,
    site_id: String,
    profiles: Vec<PathBuf>,
    mode: Mode,
    max_concurrent: usize,
    request_timeout_seconds: u64,
    backend_timeout_seconds: u64,
    response_bytes: usize,
    #[serde(default)]
    bans: BanConfig,
}
struct App {
    inspector: Inspector,
    config: Config,
    semaphore: Semaphore,
    bans: Mutex<BanTable>,
    wordpress: Option<waf_wordpress::Wordpress>,
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
    ban_started: bool,
    application: Option<serde_json::Value>,
}
// Hyper otherwise discards representation length on an empty 304 body. This
// metadata-only body is used exclusively for 304; its encoder sends no frames.
struct RepresentationMetadata(u64);
impl hyper::body::Body for RepresentationMetadata {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(None)
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.0)
    }
}
fn representation_length(headers: &HeaderMap) -> Result<Option<u64>, &'static str> {
    one(headers, "content-length")?
        .map(|text| {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid_backend_content_length");
            }
            text.parse().map_err(|_| "invalid_backend_content_length")
        })
        .transpose()
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
        ban_started,
        application,
    } = evidence;
    let event = serde_json::json!({"schema_version":1,"ts_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        "request_id":id,"fingerprint":app.inspector.policy.fingerprint,"decision":decision,"reason":reason,"matches":matches,
        "status":status.as_u16(),"elapsed_us":start.elapsed().as_micros(),"backend_attempted":backend_attempted,"ban_started":ban_started,"application":application});
    let write_result = writeln!(io::stdout().lock(), "{event}");
    strip_hop(&mut headers);
    let response_body = if write_result.is_ok() && status == StatusCode::NOT_MODIFIED {
        match representation_length(&headers).ok().flatten() {
            Some(length) => Body::new(RepresentationMetadata(length)),
            None => Body::empty(),
        }
    } else {
        Body::from(body)
    };
    let mut response = Response::new(response_body);
    *response.status_mut() = if write_result.is_ok() {
        status
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    // Forwarded bytes are unchanged and Hyper validates ordinary response framing.
    // HEAD/304 Content-Length describes the selected representation, not body bytes.
    if status == StatusCode::NO_CONTENT {
        headers.remove("content-length");
    }
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
                ban_started: false,
                application: None,
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
    let client_ip: std::net::IpAddr = client_ip.unwrap().parse().unwrap();
    let trusted = one(&parts.headers, "x-waf-admin-friend").ok().flatten() == Some("1");
    let remaining = match app.bans.lock() {
        Ok(table) => table.remaining(client_ip, trusted, Instant::now()),
        Err(_) => return deny(StatusCode::SERVICE_UNAVAILABLE, "ban_state_unavailable"),
    };
    if let Some(duration) = remaining {
        let mut response = deny(StatusCode::TOO_MANY_REQUESTS, "temporary_local_ban");
        response.headers_mut().insert(
            "retry-after",
            HeaderValue::from_str(&duration.as_secs().saturating_add(1).to_string()).unwrap(),
        );
        return response;
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
    let mut scanned = match app
        .inspector
        .scan(
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
    scanned.views.headers = match normalize_headers(&app.inspector.policy, &headers) {
        Ok(h) => h,
        Err(e) => return deny(StatusCode::BAD_REQUEST, &e.0),
    };
    let context = if let Some(wordpress) = &app.wordpress {
        match wordpress
            .analyze(waf_wordpress::Request {
                path: parts.uri.path(),
                query: parts.uri.query().unwrap_or(""),
                wire_method: parts.method.as_str(),
                headers: &headers,
                content_type,
                body: body.clone(),
                max_parts: app.inspector.policy.limits.multipart_parts,
            })
            .await
        {
            Ok(context) => Some(context),
            Err(error) => return deny(StatusCode::BAD_REQUEST, &error.0),
        }
    } else {
        None
    };
    let application = context
        .as_ref()
        .map(|context| serde_json::to_value(context).unwrap());
    if let (Some(wordpress), Some(context)) = (&app.wordpress, &context) {
        if let Some(denial) = wordpress.check(context, trusted) {
            return finish(
                &app,
                &id,
                start,
                StatusCode::from_u16(denial.status).unwrap(),
                Evidence {
                    decision: "block",
                    reason: denial.reason,
                    matches: serde_json::json!([{"policy_id":denial.policy_id,"profile_id":denial.profile_id}]),
                    backend_attempted: false,
                    ban_started: false,
                    application,
                },
                Bytes::from_static(b"Request denied\n"),
                HeaderMap::new(),
            );
        }
    }
    let effective_method = context.as_ref().map_or(parts.method.as_str(), |context| {
        context.effective_method.as_str()
    });
    let confirmed_fields = context
        .as_ref()
        .map(|context| {
            context
                .confirmed_fields
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let matches =
        app.inspector
            .inspect_scanned_with_fields(&scanned, effective_method, &confirmed_fields);
    // Inspection is complete. Do not retain normalized bodies during backend I/O.
    drop(scanned);
    let blocked = matches.iter().any(|m| m.exception_profile.is_none());
    let records = serde_json::to_value(&matches).unwrap();
    if blocked && app.config.mode == Mode::Enforce {
        let reliable = matches
            .iter()
            .any(|m| m.high_confidence && m.exception_profile.is_none());
        let ban_started = if reliable {
            match app.bans.lock() {
                Ok(mut table) => table.record_reliable(client_ip, trusted, Instant::now()),
                Err(_) => return deny(StatusCode::SERVICE_UNAVAILABLE, "ban_state_unavailable"),
            }
        } else {
            false
        };
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
                ban_started,
                application: application.clone(),
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
        representation_length(&parts.headers).map_err(io::Error::other)?;
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
                ban_started: false,
                application: application.clone(),
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
                ban_started: false,
                application,
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
        || config.ban_lookup_socket.as_ref().is_some_and(|path| {
            !path.is_absolute() || path == &config.listen_socket || path == &config.backend_socket
        })
    {
        return Err("invalid runtime bounds or socket paths".into());
    }
    let profiles = config
        .profiles
        .iter()
        .map(|p| Profile::parse(&fs::read(p)?).map_err(Into::into))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let inspector = Inspector::new(compose(profiles, &config.site_id)?)?;
    let wordpress = waf_wordpress::Wordpress::from_modules(&inspector.policy.modules)?;
    let bans = Mutex::new(BanTable::new(config.bans.clone())?);
    // Never unlink an existing socket: a second process must fail, not steal the listener.
    let listener = UnixListener::bind(&config.listen_socket)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&config.listen_socket, fs::Permissions::from_mode(0o660))?;
    let gate_listener = config
        .ban_lookup_socket
        .as_ref()
        .map(|path| {
            let listener = UnixListener::bind(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
            Ok::<_, io::Error>(listener)
        })
        .transpose()?;
    let app = Arc::new(App {
        bans,
        wordpress,
        semaphore: Semaphore::new(config.max_concurrent),
        config,
        inspector,
    });
    let mut gate_task =
        gate_listener.map(|listener| tokio::spawn(ban_gate::serve(listener, app.clone())));
    let connections = Arc::new(Semaphore::new(app.config.max_concurrent));
    loop {
        let (mut stream, _) = tokio::select! {
            result = listener.accept() => result?,
            _ = tokio::signal::ctrl_c() => break,
            _ = async {
                if let Some(task) = &mut gate_task { let _ = task.await; }
                else { std::future::pending::<()>().await; }
            } => return Err("ban gate listener terminated".into()),
        };
        let app = app.clone();
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            // Do not spawn unbounded denial tasks while the connection budget is full.
            drop(stream);
            continue;
        };
        tokio::spawn(async move {
            let start = Instant::now();
            let id = uuid::Uuid::new_v4().simple().to_string();
            let validation = ingress::validate(
                &mut stream,
                app.inspector.policy.limits.header_bytes,
                app.inspector.policy.limits.header_count,
                app.config.request_timeout_seconds,
            )
            .await;
            let prefix = match validation {
                Ok(prefix) => prefix,
                Err(error) => {
                    let response = finish(
                        &app,
                        &id,
                        start,
                        error.status,
                        Evidence {
                            decision: "block",
                            reason: error.reason,
                            matches: serde_json::json!([]),
                            backend_attempted: false,
                            ban_started: false,
                            application: None,
                        },
                        Bytes::from_static(b"Request denied\n"),
                        HeaderMap::new(),
                    );
                    let (parts, body) = response.into_parts();
                    let body = to_bytes(body, 1024).await.unwrap_or_default();
                    let head = format!(
                        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Request-ID: {}\r\n\r\n",
                        parts.status.as_u16(),
                        parts.status.canonical_reason().unwrap_or("Denied"),
                        body.len(),
                        id
                    );
                    let _ = timeout(Duration::from_secs(1), async {
                        stream.write_all(head.as_bytes()).await?;
                        stream.write_all(&body).await
                    })
                    .await;
                    return;
                }
            };
            let _permit = permit;
            let connection_seconds =
                app.config.request_timeout_seconds + app.config.backend_timeout_seconds + 30;
            let service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            handle(State(app), request.map(Body::new)).await,
                        )
                    }
                },
            );
            // Exactly one request per connection keeps raw-header validation complete.
            let connection = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(ingress::replay(stream, prefix)), service);
            let _ = timeout(Duration::from_secs(connection_seconds), connection).await;
        });
    }
    Ok(())
}
