use bitcoin::Network;
use clap::Parser;

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

    /// Network lnd is running on ["bitcoin", "testnet", "signet, "regtest"]
    #[clap(default_value_t = Network::Bitcoin, short, long, env = "LNURL_NETWORK")]
    pub network: Network,

    /// Path to tls.cert file for lnd
    #[clap(long, env = "LNURL_CERT_FILE")]
    cert_file: Option<String>,

    /// Path to admin.macaroon file for lnd
    #[clap(long, env = "LNURL_MACAROON_FILE")]
    macaroon_file: Option<String>,

    /// The domain name you are running lnurl-server on
    #[clap(default_value_t = String::from(""), long, env = "LNURL_DOMAIN")]
    pub domain: String,

    /// Include route hints in invoices
    #[clap(long, env = "LNURL_ROUTE_HINTS")]
    pub route_hints: bool,
}

impl Config {
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
