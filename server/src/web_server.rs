//! HTTP front door of the web gateway: serves the browser client's static files and
//! upgrades `/ws` to the session `WebSocket`.
//!
//! Ported from SubnetDesk's `src/web_gateway.rs` (AGPL-3.0; `restrict_request`,
//! `security_headers`, `websocket_upgrade`, lines 1318–1407): every request passes
//! the `Host` allow-list and the per-IP request budget, every response carries the
//! strict [`CONTENT_SECURITY_POLICY`] and anti-framing headers, and the `WebSocket`
//! upgrade additionally checks `Origin` against the request authority and takes a
//! [`ConnectionLimiter`] permit for the life of the session. noVNC's `websock.js`
//! and `KasmVNC`'s web client are served the same way: a static bundle from the same
//! origin that opens one binary `WebSocket` back to it.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::web_gateway::{
    CONTENT_SECURITY_POLICY, ConnectionLimiter, MAX_WEB_CONNECTIONS,
    MAX_WEB_CONNECTIONS_PER_SOURCE, MAX_WEB_REQUESTS_PER_MINUTE, MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN,
    RequestRateBudget, authority_host_allowed, origin_allowed,
};
use crate::web_session::{AgentDialer, GatewayIdentity, run_web_session};

/// Request path of the session `WebSocket`.
pub const WEBSOCKET_PATH: &str = "/ws";

/// Settings of the HTTP front door.
#[derive(Debug, Clone)]
pub struct WebGatewayConfig {
    /// Directory holding the built browser client (`web/dist`): `index.html` plus the
    /// compiled scripts. `None` serves only the `WebSocket`.
    pub web_root: Option<PathBuf>,
    /// Hosts (lower-case, no port) accepted in the `Host` header.
    pub allowed_hosts: HashSet<String>,
    /// The public URL is `https://`: browsers send an `https` `Origin` even though a
    /// reverse proxy hands the gateway plain HTTP. `X-Forwarded-Proto: https` has the
    /// same effect per request.
    pub behind_tls: bool,
    /// Maximum concurrent browser sessions.
    pub max_connections: usize,
    /// Maximum concurrent browser sessions per source IP.
    pub max_connections_per_source: usize,
    /// Maximum HTTP requests per source IP per minute.
    pub max_requests_per_minute: usize,
}

impl WebGatewayConfig {
    /// Defaults from SubnetDesk `web_gateway.rs` with the given `Host` allow-list.
    #[must_use]
    pub fn new(allowed_hosts: HashSet<String>) -> Self {
        Self {
            web_root: None,
            allowed_hosts,
            behind_tls: false,
            max_connections: MAX_WEB_CONNECTIONS,
            max_connections_per_source: MAX_WEB_CONNECTIONS_PER_SOURCE,
            max_requests_per_minute: MAX_WEB_REQUESTS_PER_MINUTE,
        }
    }
}

/// Shared state of the HTTP front door.
pub struct WebState {
    config: WebGatewayConfig,
    limiter: ConnectionLimiter,
    budget: Mutex<RequestRateBudget>,
    dialer: Arc<dyn AgentDialer>,
    identity: Arc<GatewayIdentity>,
}

impl WebState {
    /// Builds the state for `config`, dialing agents with `dialer` and introducing the
    /// gateway to agents as `identity`.
    #[must_use]
    pub fn new(
        config: WebGatewayConfig,
        dialer: Arc<dyn AgentDialer>,
        identity: GatewayIdentity,
    ) -> Arc<Self> {
        Arc::new(Self {
            limiter: ConnectionLimiter::new(
                config.max_connections,
                config.max_connections_per_source,
            ),
            budget: Mutex::new(RequestRateBudget::new(
                config.max_requests_per_minute,
                Duration::from_secs(60),
            )),
            config,
            dialer,
            identity: Arc::new(identity),
        })
    }
}

impl std::fmt::Debug for WebState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Builds the router: `/` and the static files of the browser client, `/ws` for
/// sessions, SubnetDesk's request restrictions and security headers on everything.
pub fn router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route(WEBSOCKET_PATH, get(websocket_upgrade))
        .route("/{*path}", get(static_file))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            restrict_request,
        ))
        .with_state(state)
}

/// Serves the gateway on `listener` until it fails.
///
/// # Errors
///
/// Returns the I/O error that stopped the server.
pub async fn serve(listener: TcpListener, state: Arc<WebState>) -> std::io::Result<()> {
    if let Ok(local) = listener.local_addr() {
        info!(listen = %local, "web gateway listening for browsers");
    }
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// `Host` header, or the request-target authority for absolute-form requests
/// (`request_authority` in SubnetDesk `web_gateway.rs:351`).
#[must_use]
pub fn request_authority<'a>(headers: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
}

/// Whether the browser sees this request as `https` (so its `Origin` is `https://`):
/// configured with `behind_tls`, or signalled per request by the reverse proxy's
/// `X-Forwarded-Proto`. A client that forges the header only changes which scheme
/// its own `Origin` must carry.
#[must_use]
pub fn request_is_secure(headers: &HeaderMap, behind_tls: bool) -> bool {
    behind_tls
        || headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .next()
                    .is_some_and(|first| first.trim().eq_ignore_ascii_case("https"))
            })
}

/// Resolves a request path to a file under `root` and its media type. Segments must
/// be `[A-Za-z0-9_-][A-Za-z0-9._-]*` (no hidden files, no `..`) and the extension
/// must be one the browser client ships; everything else is `None` (404).
#[must_use]
pub fn static_file_path(root: &FsPath, request_path: &str) -> Option<(PathBuf, &'static str)> {
    let mut file = root.to_path_buf();
    let mut last = None;
    for segment in request_path.trim_start_matches('/').split('/') {
        let mut bytes = segment.bytes();
        let first = bytes.next()?;
        if !(first.is_ascii_alphanumeric() || first == b'_' || first == b'-') {
            return None;
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
            return None;
        }
        file.push(segment);
        last = Some(segment);
    }
    let (_, extension) = last?.rsplit_once('.')?;
    let media_type = match extension {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "webmanifest" => "application/manifest+json",
        _ => return None,
    };
    Some((file, media_type))
}

async fn restrict_request(
    State(state): State<Arc<WebState>>,
    request: Request,
    next: Next,
) -> Response {
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip());
    let authority = request_authority(request.headers(), request.uri()).unwrap_or_default();
    if !authority_host_allowed(authority, &state.config.allowed_hosts) {
        warn!(?source, %authority, "rejected web request: Host is not allowed");
        return (StatusCode::FORBIDDEN, "Host is not allowed").into_response();
    }
    let Some(source) = source else {
        return (StatusCode::FORBIDDEN, "Unknown source").into_response();
    };
    let allowed = state
        .budget
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .allow_at(source, Instant::now());
    if !allowed {
        warn!(%source, "rejected web request: rate budget exceeded");
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    }
    next.run(request).await
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), fullscreen=(self)"),
    );
    response
}

async fn index(State(state): State<Arc<WebState>>) -> Response {
    serve_static(&state, "index.html").await
}

async fn static_file(State(state): State<Arc<WebState>>, Path(path): Path<String>) -> Response {
    serve_static(&state, &path).await
}

async fn serve_static(state: &WebState, request_path: &str) -> Response {
    let Some(root) = state.config.web_root.as_deref() else {
        return (StatusCode::NOT_FOUND, "No browser client is installed").into_response();
    };
    let Some((file, media_type)) = static_file_path(root, request_path) else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };
    match tokio::fs::read(&file).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, media_type)], Body::from(bytes)).into_response(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::NOT_FOUND, "Not found").into_response()
        }
        Err(error) => {
            warn!(path = %file.display(), %error, "static file unreadable");
            (StatusCode::INTERNAL_SERVER_ERROR, "Unreadable").into_response()
        }
    }
}

async fn websocket_upgrade(
    State(state): State<Arc<WebState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Response {
    let authority = request_authority(&headers, &uri).unwrap_or_default();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let secure = request_is_secure(&headers, state.config.behind_tls);
    if !origin_allowed(origin, authority, secure) {
        warn!(%remote, ?origin, %authority, "rejected websocket: Origin does not match Host");
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    let permit = match state.limiter.try_acquire(remote.ip()) {
        Ok(permit) => permit,
        Err(error) => {
            warn!(%remote, %error, "rejected websocket");
            return (StatusCode::TOO_MANY_REQUESTS, "Too many web sessions").into_response();
        }
    };
    let dialer = Arc::clone(&state.dialer);
    let identity = Arc::clone(&state.identity);
    websocket
        .max_frame_size(MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN)
        .max_message_size(MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN)
        .on_upgrade(move |socket| async move {
            let result = run_web_session(socket, dialer, identity, remote).await;
            drop(permit);
            match result {
                Ok(()) => info!(%remote, "browser session closed"),
                Err(error) => warn!(%remote, %error, "browser session failed"),
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_paths_are_confined_to_the_web_root() {
        let root = FsPath::new("/srv/web");
        let (file, media) = static_file_path(root, "/index.html").unwrap_or_default();
        assert_eq!(file, root.join("index.html"));
        assert_eq!(media, "text/html; charset=utf-8");
        let (file, media) = static_file_path(root, "assets/app-v1.js").unwrap_or_default();
        assert_eq!(file, root.join("assets").join("app-v1.js"));
        assert_eq!(media, "text/javascript; charset=utf-8");

        for bad in [
            "../Cargo.toml",
            "/..%2fsecret",
            "/.env",
            "/a//b.js",
            "/dir/",
            "/noext",
            "/app.exe",
            "/C:\\windows\\win.ini",
            "",
        ] {
            assert!(static_file_path(root, bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn secure_follows_configuration_or_forwarded_proto() {
        let mut headers = HeaderMap::new();
        assert!(!request_is_secure(&headers, false));
        assert!(request_is_secure(&headers, true));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(request_is_secure(&headers, false));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http, https"));
        assert!(!request_is_secure(&headers, false));
    }

    #[test]
    fn authority_comes_from_host_then_uri() {
        let mut headers = HeaderMap::new();
        let uri: Uri = "http://proxy.example:8080/ws".parse().unwrap_or_default();
        assert_eq!(
            request_authority(&headers, &uri),
            Some("proxy.example:8080")
        );
        headers.insert(header::HOST, HeaderValue::from_static(" desk.example "));
        assert_eq!(request_authority(&headers, &uri), Some("desk.example"));
        let relative: Uri = "/ws".parse().unwrap_or_default();
        headers.remove(header::HOST);
        assert_eq!(request_authority(&headers, &relative), None);
    }
}
