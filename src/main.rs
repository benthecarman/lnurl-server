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
use std::path::PathBuf;
use std::sync::Arc;
use tokio::spawn;
use tokio::sync::RwLock;
use tonic_openssl_lnd::lnrpc::{GetInfoRequest, GetInfoResponse};
use tonic_openssl_lnd::LndLightningClient;
use tower_http::cors::{Any, CorsLayer};

use crate::config::*;
use crate::routes::*;
use crate::subscriber::start_invoice_subscription;

mod config;
mod db;
mod routes;
mod subscriber;

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

    let mut client = tonic_openssl_lnd::connect(
        config.lnd_host.clone(),
        config.lnd_port,
        config.cert_file(),
        config.macaroon_file(),
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
    std::fs::create_dir_all(path.clone())?;

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

    let addr: std::net::SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .expect("Failed to parse bind/port for webserver");

    println!("Webserver running on http://{}", addr);

    let server_router = Router::new()
        .route("/health-check", get(health_check))
        .route("/get-invoice/:hash", get(get_invoice))
        .route("/verify/:desc_hash/:pay_hash", get(verify))
        .route("/.well-known/lnurlp/:name", get(get_lnurl_pay))
        .fallback(fallback)
        .layer(Extension(state.clone()))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(vec![http::header::CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST]),
        );

    let server = axum::Server::bind(&addr).serve(server_router.into_make_service());

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
    }

    let graceful = server.with_graceful_shutdown(async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to create Ctrl+C shutdown signal");
    });

    // Await the server to receive the shutdown signal
    if let Err(e) = graceful.await {
        eprintln!("shutdown error: {}", e);
    }

    Ok(())
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
            let reader = BufReader::new(file);
            let n: NostrKeys = from_reader(reader).expect("Could not parse JSON");

            Keys::parse(&n.server_key).expect("Could not parse key")
        }
        Err(_) => {
            let keys = NostrKeys::generate();
            let json_str = to_string(&keys).expect("Could not serialize data");

            let mut file = File::create(path).expect("Could not create file");
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
