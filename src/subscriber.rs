use crate::db::{get_zap, upsert_zap};
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::SECP256K1;
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, InvoiceBuilder};
use nostr::key::SecretKey;
use nostr::prelude::ToBech32;
use nostr::{EventBuilder, Keys};
use nostr_sdk::Client;
use sled::Db;
use std::net::SocketAddr;
use tonic_openssl_lnd::lnrpc::invoice::InvoiceState;
use tonic_openssl_lnd::{lnrpc, LndLightningClient};

const RELAYS: [&str; 8] = [
    "wss://nostr.mutinywallet.com",
    "wss://relay.snort.social",
    "wss://relay.nostr.band",
    "wss://eden.nostr.land",
    "wss://nos.lol",
    "wss://nostr.fmt.wiz.biz",
    "wss://relay.damus.io",
    "wss://nostr.wine",
];

pub async fn start_invoice_subscription(db: Db, mut lnd: LndLightningClient, key: Keys) {
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
                    match handle_paid_invoice(&db, ln_invoice.r_hash.to_hex(), key.clone()).await {
                        Ok(_) => {
                            println!("Handled paid invoice!");
                        }
                        Err(e) => {
                            eprintln!("Failed to handle paid invoice: {}", e);
                        }
                    }
                }
                None
                | Some(InvoiceState::Canceled)
                | Some(InvoiceState::Open)
                | Some(InvoiceState::Accepted) => {}
            }
        }
    }
}

async fn handle_paid_invoice(db: &Db, payment_hash: String, keys: Keys) -> anyhow::Result<()> {
    match get_zap(db, payment_hash.clone())? {
        None => Ok(()),
        Some(mut zap) => {
            if zap.note_id.is_some() {
                return Ok(());
            }

            let preimage = &mut [0u8; 32];
            OsRng.fill_bytes(preimage);
            let invoice_hash = Sha256::hash(preimage);

            let payment_secret = &mut [0u8; 32];
            OsRng.fill_bytes(payment_secret);

            let priv_key_bytes = &mut [0u8; 32];
            OsRng.fill_bytes(priv_key_bytes);
            let private_key = SecretKey::from_slice(priv_key_bytes)?;

            let amt_msats = zap
                .invoice
                .amount_milli_satoshis()
                .expect("Invoice must have an amount");

            let fake_invoice = InvoiceBuilder::new(Currency::Bitcoin)
                .amount_milli_satoshis(amt_msats)
                .invoice_description(zap.invoice.description())
                .current_timestamp()
                .payment_hash(invoice_hash)
                .payment_secret(PaymentSecret(*payment_secret))
                .min_final_cltv_expiry_delta(144)
                .build_signed(|hash| SECP256K1.sign_ecdsa_recoverable(hash, &private_key))?;

            let event = EventBuilder::new_zap(
                fake_invoice.to_string(),
                Some(preimage.to_hex()),
                zap.request.clone(),
            )
            .to_event(&keys)?;

            // Create new client
            let client = Client::new(&keys);
            let relays: Vec<(String, Option<SocketAddr>)> =
                RELAYS.into_iter().map(|r| (r.to_string(), None)).collect();
            client.add_relays(relays).await?;

            let event_id = client.send_event(event).await?;

            println!(
                "Broadcasted event id: {}!",
                event_id.to_bech32().expect("bech32")
            );

            zap.note_id = Some(event_id.to_bech32().expect("bech32"));
            upsert_zap(db, payment_hash, zap)?;

            Ok(())
        }
    }
}
