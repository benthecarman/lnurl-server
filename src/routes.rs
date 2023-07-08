use crate::db::{upsert_zap, Zap};
use crate::State;
use anyhow::anyhow;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256, Hash};
use lightning_invoice::Invoice;
use nostr::Event;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use tonic_openssl_lnd::lnrpc;

pub(crate) async fn get_invoice_impl(
    state: State,
    hash: String,
    amount_msats: u64,
    zap_request: Option<Event>,
) -> anyhow::Result<String> {
    let mut lnd = state.lnd.clone();
    let desc_hash = match zap_request.as_ref() {
        None => sha256::Hash::from_hex(&hash)?,
        Some(event) => {
            // todo validate as valid zap request
            if event.kind != nostr::Kind::ZapRequest {
                return Err(anyhow!("Invalid zap request"));
            }
            sha256::Hash::hash(event.as_json().as_bytes())
        }
    };

    let request = lnrpc::Invoice {
        value_msat: amount_msats as i64,
        description_hash: desc_hash.to_vec(),
        expiry: 86_400,
        ..Default::default()
    };

    let resp = lnd.add_invoice(request).await?.into_inner();

    if let Some(zap_request) = zap_request {
        let invoice = Invoice::from_str(&resp.payment_request)?;
        let zap = Zap {
            invoice,
            request: zap_request,
            note_id: None,
        };
        upsert_zap(&state.db, resp.r_hash.to_hex(), zap)?;
    }

    Ok(resp.payment_request)
}

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

    match get_invoice_impl(state, hash, amount_msats, zap_request).await {
        Ok(invoice) => Ok(Json(json!({
            "pr": invoice,
            "routers": []
        }))),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, Json<Value>) {
    let err = json!({
        "status": "ERROR",
        "reason": format!("{err}"),
    });
    (StatusCode::BAD_REQUEST, Json(err))
}
