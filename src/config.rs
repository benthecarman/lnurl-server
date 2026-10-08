use bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeBackend {
    Lnd,
    LdkServer,
}

#[derive(Parser, Debug, Clone)]
#[command(version, author, about)]
/// A simple LNURL pay server. Allows you to have a lightning address for your own node.
pub struct Config {
    /// Location of database and keys files
    #[clap(default_value_t = String::from("."), long, env = "LNURL_DATA_DIR")]
    pub data_dir: String,

    /// Bind address for lnurl-server's webserver
    #[clap(default_value_t = String::from("0.0.0.0"), long, env = "LNURL_BIND")]
    pub bind: String,

    /// Port for lnurl-server's webserver
    #[clap(default_value_t = 3000, long, env = "LNURL_PORT")]
    pub port: u16,

    /// Host of the GRPC server for lnd
    #[clap(default_value_t = String::from("127.0.0.1"), long, env = "LNURL_LND_HOST")]
    pub lnd_host: String,

    /// Port of the GRPC server for lnd
    #[clap(default_value_t = 10009, long, env = "LNURL_LND_PORT")]
    pub lnd_port: u32,

    /// Lightning node backend to connect to
    #[clap(long, env = "LNURL_NODE_BACKEND")]
    pub node_backend: Option<NodeBackend>,

    /// Host of the HTTPS gRPC server for ldk-server
    #[clap(default_value_t = String::from("127.0.0.1"), long, env = "LNURL_LDK_SERVER_HOST")]
    pub ldk_server_host: String,

    /// Port of the HTTPS gRPC server for ldk-server
    #[clap(default_value_t = 3536, long, env = "LNURL_LDK_SERVER_PORT")]
    pub ldk_server_port: u16,

    /// Path to tls.crt file for ldk-server
    #[clap(long, env = "LNURL_LDK_SERVER_CERT_FILE")]
    ldk_server_cert_file: Option<String>,

    /// Path to the hex macaroon file for ldk-server. Defaults to the admin
    /// macaroon; prefer a least-privilege one (see README)
    #[clap(long, env = "LNURL_LDK_SERVER_MACAROON_FILE")]
    ldk_server_macaroon_file: Option<String>,

    /// Network lnd is running on ["bitcoin", "testnet", "signet, "regtest"]
    #[clap(default_value_t = Network::Bitcoin, short, long, env = "LNURL_NETWORK")]
    pub network: Network,

    /// Minimum amount in millisatoshis that can be sent via LNURL
    #[clap(default_value_t = 1_000, long, env = "LNURL_MIN_SENDABLE")]
    pub min_sendable: u64,

    /// Maximum amount in millisatoshis that can be sent via LNURL
    #[clap(default_value_t = 11_000_000_000, long, env = "LNURL_MAX_SENDABLE")]
    pub max_sendable: u64,

    /// Path to tls.cert file for lnd
    #[clap(long, env = "LNURL_CERT_FILE")]
    cert_file: Option<String>,

    /// Path to the macaroon file for lnd. Defaults to admin.macaroon; prefer
    /// a least-privilege one (see README)
    #[clap(long, env = "LNURL_MACAROON_FILE")]
    macaroon_file: Option<String>,

    /// The domain name you are running lnurl-server on
    #[clap(default_value_t = String::from(""), long, env = "LNURL_DOMAIN")]
    pub domain: String,

    /// Include route hints in invoices
    #[clap(long, env = "LNURL_ROUTE_HINTS")]
    pub route_hints: bool,

    /// Telegram bot token for sending notifications
    #[clap(long, env = "LNURL_TELEGRAM_TOKEN")]
    pub telegram_token: Option<String>,

    /// Telegram chat id for sending notifications
    #[clap(long, env = "LNURL_TELEGRAM_CHAT_ID")]
    pub telegram_chat_id: Option<String>,

    /// Precomputed names for the LNURL pay server watcher
    #[clap(long)]
    pub precompute_name: Vec<String>,

    /// Proxied names for the LNURL pay server watcher
    /// In the format <description_hash>:<name>
    /// e.g. "abc123:alice"
    #[clap(long)]
    pub proxied_name: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Utility commands. Without one, the server starts.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Probe a running server's /health-check route and exit non-zero if it
    /// does not answer, for Docker HEALTHCHECK and similar liveness checks
    HealthCheck,
}

impl Config {
    pub fn node_backend(&self) -> NodeBackend {
        match self.node_backend {
            Some(backend) => backend,
            None => default_node_backend(),
        }
    }

    /// Gets the path to the LND macaroon file.
    ///
    /// If a macaroon file path is explicitly specified in the config, that path is used.
    /// Otherwise, it uses a default path based on the network.
    ///
    /// # Returns
    /// A string containing the path to the macaroon file
    pub fn macaroon_file(&self) -> String {
        self.macaroon_file
            .clone()
            .unwrap_or_else(|| default_macaroon_file(&self.network))
    }

    /// Gets the path to the LND TLS certificate file.
    ///
    /// If a certificate file path is explicitly specified in the config, that path is used.
    /// Otherwise, it uses a default path.
    ///
    /// # Returns
    /// A string containing the path to the TLS certificate file
    pub fn cert_file(&self) -> String {
        self.cert_file.clone().unwrap_or_else(default_cert_file)
    }

    pub fn ldk_server_cert_file(&self) -> String {
        self.ldk_server_cert_file
            .clone()
            .unwrap_or_else(default_ldk_server_cert_file)
    }

    pub fn ldk_server_macaroon_file(&self) -> String {
        self.ldk_server_macaroon_file
            .clone()
            .unwrap_or_else(|| default_ldk_server_macaroon_file(&self.network))
    }
}

#[cfg(feature = "lnd")]
fn default_node_backend() -> NodeBackend {
    NodeBackend::Lnd
}

#[cfg(all(not(feature = "lnd"), feature = "ldk-server"))]
fn default_node_backend() -> NodeBackend {
    NodeBackend::LdkServer
}

#[cfg(not(any(feature = "lnd", feature = "ldk-server")))]
fn default_node_backend() -> NodeBackend {
    unreachable!("At least one node backend feature must be enabled")
}

/// Gets the user's home directory path.
///
/// This function retrieves the home directory path and ensures it doesn't
/// have a trailing slash for consistent path construction.
///
/// # Returns
/// A string representing the home directory path
fn home_directory() -> String {
    let buf = home::home_dir().expect("Failed to get home dir");
    let str = format!("{}", buf.display());

    // to be safe remove possible trailing '/' and
    // we can manually add it to paths
    match str.strip_suffix('/') {
        Some(stripped) => stripped.to_string(),
        None => str,
    }
}

/// Gets the default path for the LND TLS certificate file.
///
/// # Returns
/// A string with the default path to the LND TLS certificate file
pub fn default_cert_file() -> String {
    format!("{}/.lnd/tls.cert", home_directory())
}

pub fn default_ldk_server_cert_file() -> String {
    format!("{}/.ldk-server/tls.crt", home_directory())
}

pub fn default_ldk_server_macaroon_file(network: &Network) -> String {
    format!(
        "{}/.ldk-server/{}/macaroons/admin.macaroon",
        home_directory(),
        network.to_string().to_lowercase()
    )
}

/// Gets the default path for the LND macaroon file based on the network.
///
/// # Parameters
/// * `network` - The Bitcoin network (mainnet, testnet, signet, regtest)
///
/// # Returns
/// A string with the default path to the LND macaroon file
///
/// # Panics
/// Panics if an unsupported network is provided
pub fn default_macaroon_file(network: &Network) -> String {
    let network_str = match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => panic!("Unsupported network"),
    };

    format!(
        "{}/.lnd/data/chain/bitcoin/{}/admin.macaroon",
        home_directory(),
        network_str
    )
}
