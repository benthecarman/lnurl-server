use crate::db::{get_zap, upsert_zap};
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
use tonic_openssl_lnd::lnrpc::invoice::InvoiceState;
use tonic_openssl_lnd::{lnrpc, LndLightningClient};

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

/// Starts a subscription to listen for invoice updates from LND.
///
/// This function runs in an infinite loop, creating a subscription to LND's invoice stream
/// and handling paid invoices by processing the associated zap requests.
///
/// # Parameters
/// * `db` - The database instance for storing/retrieving zap data
/// * `lnd` - The LND Lightning client for interacting with the LND node
/// * `key` - The Nostr keys for signing events
pub async fn start_invoice_subscription(
    db: Db,
    mut lnd: LndLightningClient,
    key: Keys,
    telegram_token: Option<String>,
    telegram_id: Option<String>,
    name_watcher: Arc<RwLock<HashMap<sha256::Hash, String>>>,
) {
    let client = reqwest::Client::new();
    loop {
        println!("Starting invoice subscription");

        let sub = lnrpc::InvoiceSubscription::default();
        let mut invoice_stream = lnd
            .subscribe_invoices(sub)
            .await
            .expect("Failed to start invoice subscription")
            .into_inner();

        while let Some(ln_invoice) = invoice_stream
            .message()
            .await
            .expect("Failed to receive invoices")
        {
            match InvoiceState::from_i32(ln_invoice.state) {
                Some(InvoiceState::Settled) => {
                    let db = db.clone();
                    let key = key.clone();
                    let client = client.clone();
                    let telegram_token = telegram_token.clone();
                    let telegram_id = telegram_id.clone();
                    let name_watcher = Arc::clone(&name_watcher);
                    tokio::spawn(async move {
                        let fut = handle_paid_invoice(
                            &db,
                            hex::encode(ln_invoice.r_hash),
                            key,
                            client,
                            telegram_token,
                            telegram_id,
                            ln_invoice.description_hash,
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
                None
                | Some(InvoiceState::Canceled)
                | Some(InvoiceState::Open)
                | Some(InvoiceState::Accepted) => {}
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
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
        Some(mut zap) => {
            if zap.note_id.is_some() {
                return Ok(InvoiceSource::Zap);
            }

            let preimage = zap.request.id.to_bytes();
            let invoice_hash = Sha256::hash(&preimage);

            let payment_secret = zap.request.id.to_bytes();

            let private_key = SecretKey::from_slice(zap.request.id.as_bytes())?;

            let amt_msats = zap
                .invoice
                .amount_milli_satoshis()
                .expect("Invoice must have an amount");

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

                        if let Err(e) = http.get(&url).send().await {
                            eprintln!("Failed to send Telegram message: {e}");
                        }
                    });
                }
            }

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

            println!(
                "Broadcasted event id: {}!",
                event_id.to_bech32().expect("bech32")
            );

            zap.note_id = Some(event_id.to_bech32().expect("bech32"));
            upsert_zap(db, payment_hash, zap)?;

            Ok(InvoiceSource::Zap)
        }
    }
}
