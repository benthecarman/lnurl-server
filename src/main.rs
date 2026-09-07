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

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

impl HealthResponse {
    /// Fabricate a status: pass response without checking database connectivity
    pub fn new_ok() -> Self {
        Self {
            status: String::from("pass"),
            version: String::from("0"),
        }
    }
}

/// IETF draft RFC for HTTP API Health Checks:
/// https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check
pub async fn health_check() -> Result<Json<HealthResponse>, (StatusCode, String)> {
    Ok(Json(HealthResponse::new_ok()))
}
