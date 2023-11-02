# lnurl-server

A simple LNURL pay server. Allows you to have a lightning address for your own node.

## Installation

```bash
cargo install lnurl-server
```

## Usage

```bash
lnurl-server --domain mydomain.com --network bitcoin --data-dir ~/.lnurl-server/ --port 8080 --lnd-host localhost --lnd-port 10009 --macaroon-file ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon --cert-file ~/.lnd/tls.cert
```
