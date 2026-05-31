use crate::db::{get_invoice_record, upsert_invoice_record, upsert_zap, InvoiceRecord, Zap};
use crate::node::parse_invoice;
use crate::State;
use anyhow::anyhow;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::hashes::{sha256, Hash};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use lnurl::pay::PayResponse;
use lnurl::Tag;
use nostr::{Event, JsonUtil};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;

/// Maximum length of a Lightning address name served by the LNURL-pay endpoint.
const MAX_NAME_LENGTH: usize = 64;

/// Maximum number of names tracked in memory by the name watcher.
const MAX_WATCHED_NAMES: usize = 10_000;

/// Creates a Lightning invoice and optionally stores zap request information.
///
/// This is the core implementation for generating invoices for LNURL-pay requests.
///
/// # Parameters
/// * `state` - Application state containing LND client and configuration
/// * `hash` - A description hash or identifier for the invoice
/// * `amount_msats` - The invoice amount in millisatoshis
/// * `zap_request` - Optional Nostr zap request event
///
/// # Returns
/// A string containing the BOLT11 invoice if successful, or an error
pub(crate) async fn get_invoice_impl(
    state: &State,
    hash: &str,
    amount_msats: u64,
    zap_request: Option<Event>,
) -> anyhow::Result<String> {
    let desc_hash = match zap_request.as_ref() {
        None => sha256::Hash::from_str(hash)?,
        Some(event) => {
            // todo validate as valid zap request
            if event.kind != nostr::Kind::ZapRequest {
                return Err(anyhow!("Invalid zap request"));
            }
            sha256::Hash::hash(event.as_json().as_bytes())
        }
    };

    let invoice = state
        .node
        .create_invoice(desc_hash, amount_msats, state.route_hints)
        .await?;
    let bolt11 = parse_invoice(&invoice.payment_request)?;
    upsert_invoice_record(
        &state.db,
        invoice.payment_hash.clone(),
        InvoiceRecord {
            invoice: bolt11.clone(),
            desc_hash: hex::encode(desc_hash.to_byte_array()),
        },
    )?;

    if let Some(zap_request) = zap_request {
        let zap = Zap {
            invoice: bolt11,
            request: zap_request,
            note_id: None,
        };
        upsert_zap(&state.db, invoice.payment_hash, zap)?;
    }

    Ok(invoice.payment_request)
}

/// HTTP endpoint for generating Lightning invoices from a LNURL-pay request.
///
/// This route handles the callback phase of the LNURL-pay protocol.
///
/// # Parameters
/// * `hash` - Path parameter containing the description hash
/// * `params` - Query parameters including the amount and optional zap request
/// * `state` - Application state
///
/// # Returns
/// A JSON response with the invoice and verification URL, or an error response
pub async fn get_invoice(
    Path(hash): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (amount_msats, zap_request) = match params.get("amount").and_then(|a| a.parse::<u64>().ok())
    {
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "reason": "Missing amount parameter",
            })),
        )),
        Some(amount_msats) => {
            if amount_msats == 0
                || amount_msats < state.min_sendable
                || amount_msats > state.max_sendable
                || amount_msats > i64::MAX as u64
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "status": "ERROR",
                        "reason": format!(
                            "Amount must be between {} and {} millisatoshis",
                            state.min_sendable, state.max_sendable
                        ),
                    })),
                ));
            }

            let zap_request = params.get("nostr").map_or_else(
                || Ok(None),
                |event_str| {
                    Event::from_json(event_str)
                        .map_err(|_| {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(json!({
                                    "status": "ERROR",
                                    "reason": "Invalid zap request",
                                })),
                            )
                        })
                        .map(Some)
                },
            )?;

            Ok((amount_msats, zap_request))
        }
    }?;

    match get_invoice_impl(&state, &hash, amount_msats, zap_request).await {
        Ok(invoice) => {
            let invoice = Bolt11Invoice::from_str(&invoice).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "status": "ERROR",
                        "reason": "Invalid invoice",
                    })),
                )
            })?;
            let payment_hash = hex::encode(invoice.payment_hash().to_byte_array());
            let verify_url = format!("https://{}/verify/{hash}/{payment_hash}", state.domain);
            Ok(Json(json!({
                "status": "OK",
                "pr": invoice,
                "verify": verify_url,
                "routes": [],
            })))
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub fn calc_metadata(name: &str, domain: &str) -> String {
    format!("[[\"text/identifier\",\"{name}@{domain}\"],[\"text/plain\",\"Sats for {name}\"]]",)
}

/// HTTP endpoint that provides the LNURL-pay metadata and parameters.
///
/// This is the entry point for the LNURL-pay protocol, served at the .well-known/lnurlp/{name} path.
///
/// # Parameters
/// * `name` - Path parameter containing the username portion of the Lightning address
/// * `state` - Application state with domain and configuration
///
/// # Returns
/// A LNURL PayResponse with callback URL and other parameters, or an error response
pub async fn get_lnurl_pay(
    Path(name): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<PayResponse>, (StatusCode, Json<Value>)> {
    if name.is_empty() || name.len() > MAX_NAME_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "reason": format!("Name parameter must be 1-{MAX_NAME_LENGTH} characters"),
            })),
        ));
    }

    let metadata = calc_metadata(&name, &state.domain);

    let hash = sha256::Hash::hash(metadata.as_bytes());
    let callback = format!("https://{}/get-invoice/{}", state.domain, hex::encode(hash));

    let resp = PayResponse {
        callback,
        min_sendable: state.min_sendable,
        max_sendable: state.max_sendable,
        tag: Tag::PayRequest,
        metadata,
        comment_allowed: None,
        allows_nostr: Some(true),
        nostr_pubkey: Some(
            state
                .keys
                .public_key()
                .xonly()
                .expect("cant get xonly pubkey"),
        ),
    };

    // insert the name into the state for later use, but bound the map's size
    // so unauthenticated requests cannot grow memory without limit
    tokio::spawn(async move {
        let mut map = state.name_watcher.write().await;
        if map.len() < MAX_WATCHED_NAMES || map.contains_key(&hash) {
            map.insert(hash, name)
        } else {
            None
        }
    });

    Ok(Json(resp))
}

/// HTTP endpoint for verifying the status of a Lightning invoice payment.
///
/// This route is called by clients to check if an invoice has been paid.
///
/// # Parameters
/// * `desc_hash` and `pay_hash` - Path parameters for the description hash and payment hash
/// * `state` - Application state with LND client
///
/// # Returns
/// A JSON response indicating settlement status and preimage (if settled), or an error response
pub async fn verify(
    Path((desc_hash, pay_hash)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let desc_hash: Vec<u8> = hex::decode(desc_hash).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "reason": "Invalid description hash",
            })),
        )
    })?;

    let pay_hash: Vec<u8> = hex::decode(pay_hash).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "ERROR",
                "reason": "Invalid payment hash",
            })),
        )
    })?;
    let pay_hash_hex = hex::encode(&pay_hash);

    let status = match state.node.lookup_invoice(&pay_hash_hex).await {
        Ok(Some(status)) => status,
        Ok(None) | Err(_) => {
            return Ok(Json(json!({
                "status": "ERROR",
                "reason": "Not found",
            })));
        }
    };

    let invoice = match status.payment_request {
        Some(payment_request) => Bolt11Invoice::from_str(&payment_request),
        None => Ok(get_invoice_record(&state.db, &pay_hash_hex)
            .map_err(handle_anyhow_error)?
            .map(|record| record.invoice)
            .ok_or_else(|| {
                (
                    StatusCode::OK,
                    Json(json!({
                        "status": "ERROR",
                        "reason": "Not found",
                    })),
                )
            })?),
    }
    .map_err(|_| {
        (
            StatusCode::OK,
            Json(json!({
                "status": "ERROR",
                "reason": "Not found",
            })),
        )
    })?;

    match invoice.description() {
        Bolt11InvoiceDescriptionRef::Direct(_) => Ok(Json(json!({
            "status": "ERROR",
            "reason": "Not found",
        }))),
        Bolt11InvoiceDescriptionRef::Hash(h) => {
            if h.0.to_byte_array().to_vec() == desc_hash {
                if status.settled {
                    let preimage = status.preimage.unwrap_or_default();
                    Ok(Json(json!({
                        "status": "OK",
                        "settled": true,
                        "preimage": preimage,
                        "pr": invoice,
                    })))
                } else {
                    Ok(Json(json!({
                        "status": "OK",
                        "settled": false,
                        "preimage": (),
                        "pr": invoice,
                    })))
                }
            } else {
                Ok(Json(json!({
                    "status": "ERROR",
                    "reason": "Not found",
                })))
            }
        }
    }
}

/// Utility function for converting anyhow errors to HTTP response format.
///
/// # Parameters
/// * `err` - The anyhow Error to convert
///
/// # Returns
/// A tuple containing a 400 Bad Request status code and a JSON error response
pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, Json<Value>) {
    let err = json!({
        "status": "ERROR",
        "reason": format!("{err}"),
    });
    (StatusCode::BAD_REQUEST, Json(err))
}
