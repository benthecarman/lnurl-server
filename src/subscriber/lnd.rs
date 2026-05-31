use crate::subscriber::spawn_paid_invoice_handler;
use bitcoin::hashes::sha256;
use nostr::Keys;
use sled::Db;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic_openssl_lnd::lnrpc::invoice::InvoiceState;
use tonic_openssl_lnd::{lnrpc, LndLightningClient};

pub async fn start(
    db: Db,
    mut lnd: LndLightningClient,
    key: Keys,
    telegram_token: Option<String>,
    telegram_id: Option<String>,
    name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build http client");

    // last settle index seen, so a resubscription resumes where we left off
    // instead of replaying the node's full invoice history
    let mut settle_index = 0;

    loop {
        println!("Starting invoice subscription");

        let sub = lnrpc::InvoiceSubscription {
            settle_index,
            ..Default::default()
        };
        let mut invoice_stream = match lnd.subscribe_invoices(sub).await {
            Ok(stream) => stream.into_inner(),
            Err(e) => {
                eprintln!("Failed to start invoice subscription: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        loop {
            let ln_invoice = match invoice_stream.message().await {
                Ok(Some(invoice)) => invoice,
                Ok(None) => {
                    eprintln!("Invoice subscription stream closed, resubscribing");
                    break;
                }
                Err(e) => {
                    eprintln!("Failed to receive invoices: {e}");
                    break;
                }
            };

            settle_index = settle_index.max(ln_invoice.settle_index);

            match InvoiceState::from_i32(ln_invoice.state) {
                Some(InvoiceState::Settled) => {
                    spawn_paid_invoice_handler(
                        db.clone(),
                        hex::encode(ln_invoice.r_hash),
                        key.clone(),
                        client.clone(),
                        telegram_token.clone(),
                        telegram_id.clone(),
                        ln_invoice.description_hash,
                        Arc::clone(&name_watcher),
                    );
                }
                None
                | Some(InvoiceState::Canceled)
                | Some(InvoiceState::Open)
                | Some(InvoiceState::Accepted) => {}
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
