# lnurl-server

A simple LNURL pay server. Allows you to have a lightning address for your own node.

## Installation

```bash
cargo install lnurl-server --locked
```

## Usage

```bash
lnurl-server --domain mydomain.com --network bitcoin --data-dir ~/.lnurl-server/ --bind 127.0.0.1 --port 8080 --lnd-host localhost --lnd-port 10009 --macaroon-file ~/.lnd/data/chain/bitcoin/mainnet/invoice.macaroon --cert-file ~/.lnd/tls.cert
```

Every option can also be set via an environment variable, e.g. `LNURL_DOMAIN`,
`LNURL_TELEGRAM_TOKEN`. Run `lnurl-server --help` for the full list. Prefer
environment variables over command line flags for secrets like
`--telegram-token`, since flags are visible in process listings and shell
history.

## Deployment

### TLS reverse proxy (required)

lnurl-server speaks plain HTTP, but the LNURL protocol (LUD-06/LUD-16) requires
HTTPS: wallets will refuse `http://` lightning addresses, and serving metadata
over cleartext lets an on-path attacker substitute invoices. You **must** put a
TLS-terminating reverse proxy (Caddy, nginx, Traefik, ...) in front of it, and
`--domain` must match the public TLS hostname.

When proxied, keep the server on loopback with `--bind 127.0.0.1` (the default
is `0.0.0.0`) so the plaintext port is not exposed directly.

Minimal Caddy example:

```caddyfile
mydomain.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
    }
}
```

The rate limiter uses the forwarded client IP. Configure the proxy to overwrite
`X-Forwarded-For`, as above, rather than trusting a value supplied by the
client.

### Macaroon permissions

The server only needs `GetInfo`, `AddInvoice`, `LookupInvoice` and
`SubscribeInvoices`. Do **not** use `admin.macaroon`; bake a least-privilege
macaroon instead:

```bash
lncli bakemacaroon info:read invoices:read invoices:write --save_to ~/.lnd/lnurl.macaroon
```

and point `--macaroon-file` at it.

### Data directory

The data dir holds `keys.json` (the Nostr secret key used to sign zap receipts)
and `zaps.db` (payment history). The server creates it with `0700` permissions
and the key file with `0600`; keep it on a private volume and include it in
backups if you want to keep your zap identity across reinstalls.

### Docker

Images are published to `ghcr.io/benthecarman/lnurl-server`. The container runs
as a non-root user and takes flags as arguments:

```bash
docker run -d \
  -v lnurl-data:/var/lib/lnurl-server \
  -v ~/.lnd/tls.cert:/tls.cert:ro \
  -v ~/.lnd/lnurl.macaroon:/lnurl.macaroon:ro \
  ghcr.io/benthecarman/lnurl-server \
  --domain mydomain.com --bind 0.0.0.0 --port 8080 \
  --lnd-host <lnd-host> --cert-file /tls.cert --macaroon-file /lnurl.macaroon
```

Mount LND credentials read-only, and put the container on a network reachable
by your TLS proxy (inside Docker, `--bind 0.0.0.0` is appropriate). Secrets can
be passed with `--env-file` instead of flags.

Note the LND connection uses TLS with the pinned `tls.cert`; the server refuses
to start if the cert or macaroon file is unreadable rather than risking a
cleartext connection.
