use crate::db::get_invoice_record;
use crate::subscriber::spawn_paid_invoice_handler;
use bitcoin::hashes::sha256;
use ldk_server_client::ldk_server_grpc::events::event_envelope;
use ldk_server_client::ldk_server_grpc::types::payment_kind;
use nostr::Keys;
use sled::Db;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub async fn start(
    db: Db,
    client: Arc<ldk_server_client::client::LdkServerClient>,
    key: Keys,
    telegram_token: Option<String>,
    telegram_id: Option<String>,
    name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,
) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build http client");
    loop {
        println!("Starting ldk-server event subscription");

        let mut stream = match client.subscribe_events().await {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Failed to start ldk-server event subscription: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        while let Some(event) = stream.next_message().await {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    eprintln!("Failed to receive ldk-server event: {e}");
                    break;
                }
            };

            let Some(event_envelope::Event::PaymentReceived(payment_received)) = event.event else {
                continue;
            };
            let Some(payment) = payment_received.payment else {
                continue;
            };
            let Some(kind) = payment.kind.and_then(|kind| kind.kind) else {
                continue;
            };

            let payment_hash = match kind {
                payment_kind::Kind::Bolt11(payment) => payment.hash,
                _ => continue,
            };

            let desc_hash = match get_invoice_record(&db, &payment_hash) {
                Ok(Some(record)) => match hex::decode(record.desc_hash) {
                    Ok(desc_hash) => desc_hash,
                    Err(e) => {
                        eprintln!("Invalid stored description hash for {payment_hash}: {e}");
                        continue;
                    }
                },
                Ok(None) => Vec::new(),
                Err(e) => {
                    eprintln!("Failed to read invoice record for {payment_hash}: {e}");
                    continue;
                }
            };

            spawn_paid_invoice_handler(
                db.clone(),
                payment_hash,
                key.clone(),
                http.clone(),
                telegram_token.clone(),
                telegram_id.clone(),
                desc_hash,
                Arc::clone(&name_watcher),
            );
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
