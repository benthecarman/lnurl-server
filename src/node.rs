use crate::config::Config;
#[cfg(any(feature = "lnd", feature = "ldk-server"))]
use crate::config::NodeBackend;
use anyhow::{anyhow, bail};
use bitcoin::hashes::sha256;
#[cfg(any(feature = "lnd", feature = "ldk-server"))]
use bitcoin::hashes::Hash;
use lightning_invoice::Bolt11Invoice;
use std::str::FromStr;
#[cfg(feature = "ldk-server")]
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "ldk-server")]
use ldk_server_client::client::LdkServerClient;
#[cfg(feature = "ldk-server")]
use ldk_server_client::ldk_server_grpc::api::{
    Bolt11ReceiveRequest, GetNodeInfoRequest, GetPaymentDetailsRequest,
};
#[cfg(feature = "ldk-server")]
use ldk_server_client::ldk_server_grpc::types::{
    bolt11_invoice_description, payment_kind, Payment, PaymentStatus,
};

#[cfg(feature = "lnd")]
use tonic_openssl_lnd::lnrpc;
#[cfg(feature = "lnd")]
use tonic_openssl_lnd::lnrpc::invoice::InvoiceState;
#[cfg(feature = "lnd")]
use tonic_openssl_lnd::lnrpc::{GetInfoRequest, GetInfoResponse};
#[cfg(feature = "lnd")]
use tonic_openssl_lnd::LndLightningClient;

#[derive(Clone)]
pub enum NodeClient {
    #[cfg(feature = "lnd")]
    Lnd(Box<LndLightningClient>),
    #[cfg(feature = "ldk-server")]
    LdkServer(Arc<LdkServerClient>),
}

pub struct CreatedInvoice {
    pub payment_request: String,
    pub payment_hash: String,
}

pub struct InvoiceStatus {
    pub payment_request: Option<String>,
    pub settled: bool,
    pub preimage: Option<String>,
}

impl NodeClient {
    pub async fn connect(config: &Config) -> anyhow::Result<Self> {
        match config.node_backend() {
            #[cfg(feature = "lnd")]
            NodeBackend::Lnd => {
                // tonic_openssl_lnd silently falls back to cleartext gRPC
                // (while still sending the macaroon!) when the cert file
                // cannot be read, so verify both credential files are
                // readable before connecting.
                let cert_file = config.cert_file();
                let macaroon_file = config.macaroon_file();
                std::fs::read(&cert_file)
                    .map_err(|e| anyhow!("Failed to read LND TLS cert file {cert_file}: {e}"))?;
                std::fs::read(&macaroon_file).map_err(|e| {
                    anyhow!("Failed to read LND macaroon file {macaroon_file}: {e}")
                })?;

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
                Ok(Self::Lnd(Box::new(client.lightning().clone())))
            }
            #[cfg(feature = "ldk-server")]
            NodeBackend::LdkServer => {
                let cert_pem = std::fs::read(config.ldk_server_cert_file())?;
                let macaroon = std::fs::read_to_string(config.ldk_server_macaroon_file())?
                    .trim()
                    .to_string();
                let client = LdkServerClient::new(
                    format!("{}:{}", config.ldk_server_host, config.ldk_server_port),
                    macaroon,
                    &cert_pem,
                )
                .map_err(|e| anyhow!("Failed to create ldk-server client: {e}"))?;
                let info = client.get_node_info(GetNodeInfoRequest {}).await?;

                println!("Connected to LDK Server: {}", info.node_id);
                Ok(Self::LdkServer(Arc::new(client)))
            }
            #[allow(unreachable_patterns)]
            backend => bail!("Backend {backend:?} is not enabled at compile time"),
        }
    }

    /// Checks that the node answers a cheap info call within `timeout`.
    ///
    /// Error details go to the log; the returned reason is generic because
    /// the health check route is unauthenticated.
    pub async fn check_health(&self, timeout: Duration) -> Result<(), &'static str> {
        let result = match self {
            #[cfg(feature = "lnd")]
            Self::Lnd(lnd) => {
                let mut lnd = lnd.clone();
                tokio::time::timeout(timeout, lnd.get_info(GetInfoRequest {}))
                    .await
                    .map(|r| r.map(|_| ()).map_err(|e| e.to_string()))
            }
            #[cfg(feature = "ldk-server")]
            Self::LdkServer(client) => {
                tokio::time::timeout(timeout, client.get_node_info(GetNodeInfoRequest {}))
                    .await
                    .map(|r| r.map(|_| ()).map_err(|e| e.to_string()))
            }
        };

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                eprintln!("Health check failed, node info error: {e}");
                Err("node unreachable")
            }
            Err(_) => {
                eprintln!("Health check failed, node info timed out after {timeout:?}");
                Err("node timeout")
            }
        }
    }

    pub async fn create_invoice(
        &self,
        desc_hash: sha256::Hash,
        amount_msats: u64,
        _route_hints: bool,
    ) -> anyhow::Result<CreatedInvoice> {
        match self {
            #[cfg(feature = "lnd")]
            Self::Lnd(lnd) => {
                let mut lnd = lnd.clone();
                let request = lnrpc::Invoice {
                    value_msat: amount_msats as i64,
                    description_hash: desc_hash.to_byte_array().to_vec(),
                    expiry: 86_400,
                    private: _route_hints,
                    ..Default::default()
                };
                let resp = lnd.add_invoice(request).await?.into_inner();

                Ok(CreatedInvoice {
                    payment_request: resp.payment_request,
                    payment_hash: hex::encode(resp.r_hash),
                })
            }
            #[cfg(feature = "ldk-server")]
            Self::LdkServer(client) => {
                let description =
                    ldk_server_client::ldk_server_grpc::types::Bolt11InvoiceDescription {
                        kind: Some(bolt11_invoice_description::Kind::Hash(hex::encode(
                            desc_hash.to_byte_array(),
                        ))),
                    };
                let resp = client
                    .bolt11_receive(Bolt11ReceiveRequest {
                        amount_msat: Some(amount_msats),
                        description: Some(description),
                        expiry_secs: 86_400,
                    })
                    .await?;

                Ok(CreatedInvoice {
                    payment_request: resp.invoice,
                    payment_hash: resp.payment_hash,
                })
            }
            #[allow(unreachable_patterns)]
            _ => bail!("No node backend feature is enabled"),
        }
    }

    pub async fn lookup_invoice(
        &self,
        payment_hash: &str,
    ) -> anyhow::Result<Option<InvoiceStatus>> {
        match self {
            #[cfg(feature = "lnd")]
            Self::Lnd(lnd) => {
                let mut lnd = lnd.clone();
                let request = lnrpc::PaymentHash {
                    r_hash: hex::decode(payment_hash)?,
                    ..Default::default()
                };
                let resp = match lnd.lookup_invoice(request).await {
                    Ok(resp) => resp.into_inner(),
                    Err(_) => return Ok(None),
                };
                let settled = resp.state() == InvoiceState::Settled && !resp.r_preimage.is_empty();
                let preimage = (!resp.r_preimage.is_empty()).then(|| hex::encode(resp.r_preimage));
                Ok(Some(InvoiceStatus {
                    payment_request: Some(resp.payment_request),
                    settled,
                    preimage,
                }))
            }
            #[cfg(feature = "ldk-server")]
            Self::LdkServer(client) => {
                let resp = client
                    .get_payment_details(GetPaymentDetailsRequest {
                        payment_id: payment_hash.to_string(),
                    })
                    .await?;
                if let Some(payment) = resp.payment {
                    return Ok(Some(ldk_payment_status(payment)));
                }

                Ok(None)
            }
            #[allow(unreachable_patterns)]
            _ => bail!("No node backend feature is enabled"),
        }
    }
}

#[cfg(feature = "ldk-server")]
fn ldk_payment_status(payment: Payment) -> InvoiceStatus {
    let settled = PaymentStatus::from_i32(payment.status) == Some(PaymentStatus::Succeeded);
    let preimage = payment
        .kind
        .and_then(|kind| kind.kind)
        .and_then(|kind| match kind {
            payment_kind::Kind::Bolt11(payment) => payment.preimage,
            _ => None,
        });

    InvoiceStatus {
        payment_request: None,
        settled,
        preimage,
    }
}

pub fn parse_invoice(invoice: &str) -> anyhow::Result<Bolt11Invoice> {
    Bolt11Invoice::from_str(invoice).map_err(|_| anyhow!("Invalid invoice format"))
}
