use crate::db::{claim_zap, get_zap, remove_zap};
use crate::node::NodeClient;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use lightning_invoice::{
    Bolt11InvoiceDescription, Bolt11InvoiceDescriptionRef, Currency, InvoiceBuilder, PaymentSecret,
};
use nostr::prelude::ToBech32;
use nostr::{EventBuilder, Keys};
use nostr_sdk::Client;
use sled::Db;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[cfg(feature = "ldk-server")]
mod ldk_server;
#[cfg(feature = "lnd")]
mod lnd;

const RELAYS: [&str; 8] = [
    "wss://relay.snort.social",
    "wss://relay.nostr.band",
    "wss://eden.nostr.land",
    "wss://nos.lol",
    "wss://nostr.fmt.wiz.biz",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://sendit.nosflare.com",
];

/// Starts a subscription to listen for invoice updates from the node backend.
///
/// Dispatches to the backend-specific subscriber, which runs in an infinite
/// loop, listening for settled invoices and processing the associated zap
/// requests.
///
/// # Parameters
/// * `db` - The database instance for storing/retrieving zap data
/// * `node` - The node client for interacting with the lightning node
/// * `key` - The Nostr keys for signing events
pub async fn start_invoice_subscription(
    db: Db,
    node: NodeClient,
    key: Keys,
    telegram_token: Option<String>,
    telegram_id: Option<String>,
    name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,
) {
    match node {
        #[cfg(feature = "lnd")]
        NodeClient::Lnd(client) => {
            lnd::start(db, *client, key, telegram_token, telegram_id, name_watcher).await
        }
        #[cfg(feature = "ldk-server")]
        NodeClient::LdkServer(client) => {
            ldk_server::start(db, client, key, telegram_token, telegram_id, name_watcher).await
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!("At least one node backend feature must be enabled"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_paid_invoice_handler(
    db: Db,
    payment_hash: String,
    keys: Keys,
    http: reqwest::Client,
    telegram_token: Option<String>,
    telegram_id: Option<String>,
    desc_hash: Vec<u8>,
    name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,
) {
    tokio::spawn(async move {
        let fut = handle_paid_invoice(
            &db,
            payment_hash,
            keys,
            http,
            telegram_token,
            telegram_id,
            desc_hash,
            name_watcher,
        );

        match tokio::time::timeout(Duration::from_secs(30), fut).await {
            Ok(Ok(source)) => match source {
                InvoiceSource::Name(name) => {
                    if let Some(name) = name {
                        println!("Handled paid invoice with name: {name}");
                    } else {
                        println!("Handled paid invoice without saved name");
                    }
                }
                InvoiceSource::Zap => {
                    println!("Handled paid invoice with zap request!");
                }
            },
            Ok(Err(e)) => {
                eprintln!("Failed to handle paid invoice: {e}");
            }
            Err(_) => {
                eprintln!("Timeout");
            }
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvoiceSource {
    Name(Option<String>),
    Zap,
}

/// Processes a paid invoice by creating and broadcasting a zap receipt.
///
/// When an invoice is paid, this function creates a zap receipt and broadcasts it to Nostr relays.
///
/// # Parameters
/// * `db` - The database instance to retrieve and update the zap data
/// * `payment_hash` - The hash of the payment that was settled
/// * `keys` - The Nostr keys for signing the zap receipt
///
/// # Returns
/// `Ok(())` if successful, or an error if any part of the process fails
#[allow(clippy::too_many_arguments)]
async fn handle_paid_invoice(
    db: &Db,
    payment_hash: String,
    keys: Keys,
    http: reqwest::Client,
    telegram_token: Option<String>,
    telegram_id: Option<String>,
    desc_hash: Vec<u8>,
    name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,
) -> anyhow::Result<InvoiceSource> {
    match get_zap(db, &payment_hash)? {
        None => {
            let hash = sha256::Hash::from_slice(&desc_hash)
                .map_err(|_| anyhow::anyhow!("Invalid description hash"))?;
            let name_watcher = name_watcher.read().await;
            let name = name_watcher.get(&hash).cloned();
            Ok(InvoiceSource::Name(name))
        }
        Some(zap) => {
            if zap.note_id.is_some() {
                return Ok(InvoiceSource::Zap);
            }

            // Atomically claim the zap so that concurrent or replayed settlement
            // events for the same payment hash cannot both broadcast a receipt.
            // If we crash after claiming, the record keeps its marker and is
            // skipped on replay: a lost receipt is preferred over a duplicate.
            if !claim_zap(db, &payment_hash, &zap)? {
                return Ok(InvoiceSource::Zap);
            }

            let preimage = zap.request.id.to_bytes();
            let invoice_hash = Sha256::hash(&preimage);

            let payment_secret = zap.request.id.to_bytes();

            let private_key = SecretKey::from_slice(zap.request.id.as_bytes())?;

            let amt_msats = zap
                .invoice
                .amount_milli_satoshis()
                .ok_or_else(|| anyhow::anyhow!("Invoice has no amount"))?;

            let desc = match zap.invoice.description() {
                Bolt11InvoiceDescriptionRef::Direct(str) => {
                    Bolt11InvoiceDescription::Direct(str.clone())
                }
                Bolt11InvoiceDescriptionRef::Hash(hash) => {
                    Bolt11InvoiceDescription::Hash(hash.clone())
                }
            };

            let fake_invoice = InvoiceBuilder::new(Currency::Bitcoin)
                .amount_milli_satoshis(amt_msats)
                .invoice_description(desc)
                .current_timestamp()
                .payment_hash(invoice_hash)
                .payment_secret(PaymentSecret(payment_secret))
                .min_final_cltv_expiry_delta(144)
                .basic_mpp()
                .build_signed(|hash| {
                    Secp256k1::signing_only().sign_ecdsa_recoverable(hash, &private_key)
                })?;

            let event = EventBuilder::zap_receipt(
                fake_invoice.to_string(),
                Some(hex::encode(preimage)),
                &zap.request,
            )
            .sign_with_keys(&keys)?;

            // Create new client
            let client = Client::new(keys);
            for r in RELAYS {
                if let Err(e) = client.add_relay(r).await {
                    eprintln!("Failed to add relay {r}: {e}");
                }
            }
            client.connect().await;

            let event_id = client.send_event(&event).await?;
            let _ = client.disconnect().await;

            let note_id = event_id.to_bech32()?;
            println!("Broadcasted event id: {note_id}!");

            // The receipt is out; drop the record so zap data is not kept
            // forever and replayed settlements find nothing to redo.
            remove_zap(db, &payment_hash)?;

            if let Some(token) = telegram_token {
                if let Some(id) = telegram_id {
                    tokio::spawn(async move {
                        let url = format!(
                            "https://api.telegram.org/bot{token}/sendMessage?chat_id={}&text={}",
                            urlencoding::encode(id.as_str()),
                            urlencoding::encode(
                                format!("Zapped! {} sats", amt_msats / 1000).as_str()
                            )
                        );

                        // without_url(): reqwest errors embed the request URL,
                        // which contains the bot token and must not hit the logs
                        if let Err(e) = http.get(&url).send().await {
                            eprintln!("Failed to send Telegram message: {}", e.without_url());
                        }
                    });
                }
            }

            Ok(InvoiceSource::Zap)
        }
    }
}
