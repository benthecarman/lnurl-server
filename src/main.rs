use axum::error_handling::HandleErrorLayer;
use axum::http::{Method, StatusCode, Uri};
use axum::routing::get;
use axum::{http, Extension, Json, Router};
use bitcoin::hashes::{sha256, Hash};
use clap::Parser;
use nostr::prelude::ToBech32;
use nostr::Keys;
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, to_string};
use sled::Db;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::spawn;
use tokio::sync::RwLock;
use tonic_openssl_lnd::lnrpc::{GetInfoRequest, GetInfoResponse};
use tonic_openssl_lnd::LndLightningClient;
use tower::ServiceBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{Any, CorsLayer};

use crate::config::*;
use crate::routes::*;
use crate::subscriber::start_invoice_subscription;

mod config;
mod db;
mod routes;
mod subscriber;
mod systemd;

#[derive(Clone)]
pub struct State {
    pub db: Db,
    pub lnd: LndLightningClient,
    pub keys: Keys,
    pub name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,

    // -- config options --
    pub domain: String,
    pub route_hints: bool,
    pub min_sendable: u64,
    pub max_sendable: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = Config::parse();

    if let Some(Command::HealthCheck) = config.command {
        return health_probe(&config.bind, config.port).await;
    }

    // tonic_openssl_lnd silently falls back to cleartext gRPC (while still
    // sending the macaroon!) when the cert file cannot be read, so verify
    // both credential files are readable before connecting.
    let cert_file = config.cert_file();
    let macaroon_file = config.macaroon_file();
    std::fs::read(&cert_file)
        .map_err(|e| anyhow::anyhow!("Failed to read LND TLS cert file {cert_file}: {e}"))?;
    std::fs::read(&macaroon_file)
        .map_err(|e| anyhow::anyhow!("Failed to read LND macaroon file {macaroon_file}: {e}"))?;

    let mut client = tonic_openssl_lnd::connect(
        config.lnd_host.clone(),
        config.lnd_port,
        cert_file,
        macaroon_file,
    )
    .await
    .expect("failed to connect");

    let mut ln_client = client.lightning().clone();
    let lnd_info: GetInfoResponse = ln_client
        .get_info(GetInfoRequest {})
        .await
        .expect("Failed to get lnd info")
        .into_inner();

    println!("Connected to LND: {}", lnd_info.identity_pubkey);

    // Create the datadir if it doesn't exist
    let path = PathBuf::from(&config.data_dir);
    let data_dir_existed = path.exists();
    std::fs::create_dir_all(path.clone())?;

    // The data dir holds the Nostr secret key and zap data; restrict access
    #[cfg(unix)]
    if !data_dir_existed {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }

    let db_path = {
        let mut path = path.clone();
        path.push("zaps.db");
        path
    };

    // DB management
    let db = sled::open(&db_path)?;

    let keys_path = {
        let mut path = path.clone();
        path.push("keys.json");
        path
    };

    let keys = get_keys(keys_path);

    let state = State {
        db,
        lnd: client.lightning().clone(),
        keys: keys.clone(),
        name_watcher: Arc::new(RwLock::new(HashMap::new())),
        domain: config.domain.clone(),
        route_hints: config.route_hints,
        min_sendable: config.min_sendable,
        max_sendable: config.max_sendable,
    };

    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .expect("Failed to parse bind/port for webserver");

    println!("Webserver running on http://{}", addr);

    // Per-IP rate limiting: the endpoints are unauthenticated by design, so
    // this bounds how fast a single client can create invoices / write records.
    let governor_conf = Box::new(
        GovernorConfigBuilder::default()
            .period(Duration::from_millis(100))
            .burst_size(50)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("invalid rate limit config"),
    );

    let server_router = Router::new()
        .route("/health-check", get(health_check))
        .route("/get-invoice/:hash", get(get_invoice))
        .route("/verify/:desc_hash/:pay_hash", get(verify))
        .route("/.well-known/lnurlp/:name", get(get_lnurl_pay))
        .fallback(fallback)
        .layer(
            ServiceBuilder::new()
                // HandleErrorLayer wraps GovernorLayer to turn its boxed
                // errors (e.g. rate limit exceeded) into proper responses
                .layer(HandleErrorLayer::new(handle_layer_error))
                .layer(GovernorLayer {
                    config: Box::leak(governor_conf),
                }),
        )
        .layer(Extension(state.clone()))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(vec![http::header::CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST]),
        );

    let server = axum::Server::bind(&addr)
        .serve(server_router.into_make_service_with_connect_info::<SocketAddr>());

    // Invoice event stream
    spawn(start_invoice_subscription(
        state.db.clone(),
        state.lnd.clone(),
        keys,
        config.telegram_token,
        config.telegram_chat_id,
        state.name_watcher.clone(),
    ));

    // Precompute names for LNURL pay server watcher
    {
        let mut name_watcher = state.name_watcher.write().await;
        for name in config.precompute_name {
            let metadata = calc_metadata(&name, &state.domain);
            let hash = sha256::Hash::hash(metadata.as_bytes());
            name_watcher.insert(hash, name);
        }

        for proxy in config.proxied_name {
            // proxy string is in the format <description_hash>:<name>
            let parts: Vec<&str> = proxy.split(':').collect();
            if parts.len() != 2 {
                panic!("Invalid proxied name: {proxy}");
            }
            let desc_hash = parts[0];
            let hash = sha256::Hash::from_str(desc_hash)
                .expect("invalid description hash in proxied name");
            name_watcher.insert(hash, parts[1].to_string());
        }

        println!(
            "Precomputed {} names for LNURL pay server",
            name_watcher.len()
        );
    }

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    // The listener is bound, LND is reachable and the names are loaded, so
    // report readiness to systemd (a no-op outside a Type=notify unit)
    systemd::spawn_watchdog();
    systemd::notify_ready(&format!("Serving on http://{addr}"));

    // Await the server to receive the shutdown signal
    if let Err(e) = graceful.await {
        eprintln!("shutdown error: {}", e);
    }

    Ok(())
}

/// Resolves when the process receives a shutdown signal: Ctrl+C (SIGINT) or,
/// on unix, SIGTERM, which is what systemd and Docker send on stop.
///
/// Tells systemd the service is stopping before returning, so the graceful
/// shutdown drains in-flight requests while systemd waits for the exit.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to create Ctrl+C shutdown signal");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to create SIGTERM shutdown signal")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("Shutdown signal received, stopping webserver");
    systemd::notify_stopping();
}

/// Probes the local server's `/health-check` route and returns an error if it
/// does not answer with a success status. Backs the `health-check` subcommand
/// used by the Docker `HEALTHCHECK` and similar liveness checks.
///
/// # Parameters
/// * `bind` - The server's bind address; a wildcard address maps to loopback
/// * `port` - The server's port
async fn health_probe(bind: &str, port: u16) -> anyhow::Result<()> {
    let host = match bind {
        "0.0.0.0" => "127.0.0.1",
        "[::]" => "[::1]",
        other => other,
    };
    let url = format!("http://{host}:{port}/health-check");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client.get(&url).send().await?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        // the body carries the reason, e.g. {"status":"fail","output":"lnd unreachable"}
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::anyhow!("{url} returned {status}: {body}"))
    }
}

/// Fallback route handler that returns a 404 Not Found response
/// when a request is made to a non-existent route.
///
/// # Parameters
/// * `uri` - The URI of the request
///
/// # Returns
/// A 404 status code and a message indicating the route was not found
async fn fallback(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("No route for {}", uri))
}

/// Error handler for tower middleware layers (currently the rate limiter).
///
/// # Parameters
/// * `err` - The boxed error produced by the layer
///
/// # Returns
/// A 429 status code for rate limit errors, 500 for anything else
async fn handle_layer_error(err: tower::BoxError) -> (StatusCode, String) {
    if err.is::<tower_governor::errors::GovernorError>() {
        (
            StatusCode::TOO_MANY_REQUESTS,
            String::from("Rate limit exceeded"),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {err}"),
        )
    }
}

/// Storage structure for Nostr keys used by the server.
///
/// Contains the server's private key in bech32 format.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct NostrKeys {
    server_key: String,
}

impl NostrKeys {
    /// Generates a new set of Nostr keys for the server.
    ///
    /// # Returns
    /// A `NostrKeys` instance containing the newly generated server key in bech32 format.
    fn generate() -> Self {
        let server_key = Keys::generate();

        NostrKeys {
            server_key: server_key.secret_key().to_bech32().unwrap(),
        }
    }
}

/// Retrieves Nostr keys from a file or generates new keys if the file doesn't exist.
///
/// If the file exists, keys are loaded from it. If not, new keys are generated and saved to the file.
///
/// # Parameters
/// * `path` - The path to the file storing the keys
///
/// # Returns
/// The loaded or newly generated `Keys`
fn get_keys(path: PathBuf) -> Keys {
    match File::open(&path) {
        Ok(file) => {
            // the file holds the Nostr secret key; fix overly permissive modes
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = file.metadata() {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        eprintln!(
                            "Warning: {} has insecure permissions {mode:03o}, setting to 600",
                            path.display()
                        );
                        let _ =
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                    }
                }
            }

            let reader = BufReader::new(file);
            let n: NostrKeys = from_reader(reader).expect("Could not parse JSON");

            Keys::parse(&n.server_key).expect("Could not parse key")
        }
        Err(_) => {
            let keys = NostrKeys::generate();
            let json_str = to_string(&keys).expect("Could not serialize data");

            // create_new avoids following clobbering symlinks; mode 600 keeps
            // the secret key readable only by the owner
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path).expect("Could not create file");
            file.write_all(json_str.as_bytes())
                .expect("Could not write to file");

            Keys::parse(&keys.server_key).expect("Could not parse key")
        }
    }
}

/// Response body for `/health-check`, in the format of the IETF draft for
/// HTTP API health checks:
/// https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    /// Reason for a "fail" status, omitted when passing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl HealthResponse {
    pub fn pass() -> Self {
        Self {
            status: String::from("pass"),
            version: String::from("0"),
            output: None,
        }
    }

    pub fn fail(output: &str) -> Self {
        Self {
            status: String::from("fail"),
            version: String::from("0"),
            output: Some(output.to_string()),
        }
    }
}

/// How long the health check waits for LND. Kept below the 5 second timeouts
/// of the `health-check` subcommand and the Docker HEALTHCHECK, so a hung
/// LND produces a "fail" response instead of a probe timeout.
const HEALTH_LND_TIMEOUT: Duration = Duration::from_secs(3);

/// Checks that LND answers a GetInfo call within `timeout`.
///
/// Error details go to the log; the returned reason is generic because the
/// health check route is unauthenticated.
async fn check_lnd(mut lnd: LndLightningClient, timeout: Duration) -> Result<(), &'static str> {
    match tokio::time::timeout(timeout, lnd.get_info(GetInfoRequest {})).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            eprintln!("Health check failed, LND GetInfo error: {e}");
            Err("lnd unreachable")
        }
        Err(_) => {
            eprintln!("Health check failed, LND GetInfo timed out after {timeout:?}");
            Err("lnd timeout")
        }
    }
}

/// Health check that passes only if LND answers a GetInfo call, so the
/// service reports unhealthy while the node is down or unreachable.
///
/// The route is unauthenticated but rate limited, and GetInfo is one of the
/// cheapest LND calls, so the load a client can push onto the node is
/// bounded.
pub async fn health_check(
    Extension(state): Extension<State>,
) -> (StatusCode, Json<HealthResponse>) {
    match check_lnd(state.lnd.clone(), HEALTH_LND_TIMEOUT).await {
        Ok(()) => (StatusCode::OK, Json(HealthResponse::pass())),
        Err(output) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse::fail(output)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::http::{HeaderMap, HeaderValue};
    use axum::response::Response;

    /// Serves `router` on a random loopback port.
    fn serve(router: Router) -> SocketAddr {
        let server =
            axum::Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(router.into_make_service());
        let addr = server.local_addr();
        tokio::spawn(server);
        addr
    }

    /// A stand-in LND that answers any gRPC call with an empty message and
    /// `grpc-status: 0`. An empty protobuf decodes as a default
    /// `GetInfoResponse`, which is all the health check needs.
    fn serve_fake_lnd() -> SocketAddr {
        async fn ok_grpc() -> Response<Body> {
            let (mut tx, body) = Body::channel();
            tokio::spawn(async move {
                // gRPC frame: 1 byte compression flag + 4 byte length, all zero
                let _ = tx.send_data(Bytes::from_static(&[0; 5])).await;
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                let _ = tx.send_trailers(trailers).await;
            });
            Response::builder()
                .header("content-type", "application/grpc")
                .body(body)
                .unwrap()
        }
        serve(Router::new().fallback(ok_grpc))
    }

    /// Builds a `State` whose LND client points at `lnd_port` on loopback.
    async fn test_state(lnd_port: u16) -> State {
        let dir = std::env::temp_dir().join(format!(
            "lnurl-server-test-{}-{lnd_port}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let macaroon = dir.join("macaroon");
        std::fs::write(&macaroon, b"test").unwrap();
        // an unreadable cert makes the client speak cleartext HTTP/2, which
        // is what the fake LND serves
        let mut client = tonic_openssl_lnd::connect(
            "127.0.0.1".to_string(),
            lnd_port as u32,
            dir.join("missing.cert").to_string_lossy().into_owned(),
            macaroon.to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        State {
            db: sled::Config::new().temporary(true).open().unwrap(),
            lnd: client.lightning().clone(),
            keys: Keys::generate(),
            name_watcher: Arc::new(RwLock::new(HashMap::new())),
            domain: String::new(),
            route_hints: false,
            min_sendable: 1_000,
            max_sendable: 1_000_000,
        }
    }

    /// Serves the real health check route backed by `state`.
    fn serve_health_check(state: State) -> SocketAddr {
        serve(
            Router::new()
                .route("/health-check", get(health_check))
                .layer(Extension(state)),
        )
    }

    /// Reserves a loopback port and releases it so nothing listens there.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn health_check_passes_when_lnd_answers() {
        let lnd = serve_fake_lnd();
        let addr = serve_health_check(test_state(lnd.port()).await);

        let response = reqwest::get(format!("http://{addr}/health-check"))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "pass");
        assert!(body.get("output").is_none());

        health_probe("127.0.0.1", addr.port()).await.unwrap();
        // a wildcard bind is probed over loopback
        health_probe("0.0.0.0", addr.port()).await.unwrap();
    }

    #[tokio::test]
    async fn health_check_fails_when_lnd_unreachable() {
        let addr = serve_health_check(test_state(closed_port()).await);

        let response = reqwest::get(format!("http://{addr}/health-check"))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 503);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "fail");
        assert_eq!(body["output"], "lnd unreachable");

        let err = health_probe("127.0.0.1", addr.port()).await.unwrap_err();
        assert!(err.to_string().contains("lnd unreachable"), "{err}");
    }

    #[tokio::test]
    async fn check_lnd_times_out_when_lnd_hangs() {
        // accepts connections but never answers
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                held.push(socket);
            }
        });

        let state = test_state(port).await;
        let result = check_lnd(state.lnd, Duration::from_millis(200)).await;
        assert_eq!(result, Err("lnd timeout"));
    }

    #[tokio::test]
    async fn health_probe_fails_without_server() {
        assert!(health_probe("127.0.0.1", closed_port()).await.is_err());
    }
}
