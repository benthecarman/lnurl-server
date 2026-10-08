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

Do **not** give the server an admin macaroon. Bake a least-privilege one for
your backend instead.

#### LND

The server only calls `GetInfo`, `AddInvoice`, `LookupInvoice` and
`SubscribeInvoices`:

```bash
lncli bakemacaroon info:read invoices:read invoices:write --save_to ~/.lnd/lnurl.macaroon
```

Point `--macaroon-file` at it.

#### LDK Server

The server only calls `GetNodeInfo`, `Bolt11Receive`, `GetPaymentDetails` and
`SubscribeEvents`, which need `node:read`, `invoices:create`, `payments:read`
and `events:read`. `create-macaroon` registers a named token with the server
so it can be revoked later, and prints it as JSON:

```bash
ldk-server-cli create-macaroon lnurl-server \
  --permissions node:read invoices:create payments:read events:read \
  | jq -r .token > ~/.ldk-server/lnurl.macaroon
chmod 600 ~/.ldk-server/lnurl.macaroon
```

Point `--ldk-server-api-key-file` at it. To revoke it, look up its ID with
`ldk-server-cli list-macaroons` and run `ldk-server-cli revoke-macaroon <id>`.

### Data directory

The data dir holds `keys.json` (the Nostr secret key used to sign zap receipts)
and `zaps.db` (payment history). The server creates it with `0700` permissions
and the key file with `0600`; keep it on a private volume and include it in
backups if you want to keep your zap identity across reinstalls.

### systemd

The server speaks the `sd_notify` protocol, so the unit can use `Type=notify`.
`systemctl start` then returns only once the server is connected to the node and
listening, and units ordered after it wait for that. `systemctl stop` sends
`SIGTERM`, which starts a graceful shutdown. If `WatchdogSec=` is set, the
server pings the watchdog and systemd restarts it when the process stops
responding.

Create a dedicated system user (e.g. `useradd --system lnurl`) and make the
macaroon and cert readable by it. `StateDirectory=` makes systemd create the
data dir with the right owner and mode.

```ini
[Unit]
Description=LNURL pay server
After=network-online.target lnd.service
Wants=network-online.target

[Service]
Type=notify
User=lnurl
ExecStart=/usr/local/bin/lnurl-server
StateDirectory=lnurl-server
StateDirectoryMode=0700
Environment=LNURL_DATA_DIR=/var/lib/lnurl-server
Environment=LNURL_DOMAIN=mydomain.com
Environment=LNURL_BIND=127.0.0.1
Environment=LNURL_PORT=8080
Environment=LNURL_MACAROON_FILE=/etc/lnurl-server/lnurl.macaroon
Environment=LNURL_CERT_FILE=/etc/lnurl-server/tls.cert
# Secrets such as LNURL_TELEGRAM_TOKEN go here, not in the unit file
EnvironmentFile=-/etc/lnurl-server/env
WatchdogSec=30
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Outside systemd the notifications are skipped, so the same binary runs
unchanged by hand or in Docker.

### Docker

Images are published to `ghcr.io/benthecarman/lnurl-server`. The container runs
as a non-root user and takes flags as arguments:

```bash
docker run -d \
  -v lnurl-data:/var/lib/lnurl-server \
  -v ~/.lnd/tls.cert:/tls.cert:ro \
  -v ~/.lnd/lnurl.macaroon:/lnurl.macaroon:ro \
  -e LNURL_PORT=8080 \
  ghcr.io/benthecarman/lnurl-server \
  --domain mydomain.com --bind 0.0.0.0 \
  --lnd-host <lnd-host> --cert-file /tls.cert --macaroon-file /lnurl.macaroon
```

Mount LND credentials read-only, and put the container on a network reachable
by your TLS proxy (inside Docker, `--bind 0.0.0.0` is appropriate). Secrets can
be passed with `--env-file` instead of flags.

The image has a `HEALTHCHECK` that runs `lnurl-server health-check` every 30
seconds. It probes `/health-check` on `LNURL_PORT` (default 3000) over
loopback. The probe is a separate process, so it sees environment variables but
not the flags given to the server. Set the port with `-e LNURL_PORT` as above,
or override the probe with `--health-cmd`. The same command works outside
Docker, e.g. `lnurl-server --port 8080 health-check`.

The `/health-check` route answers `503` with `{"status":"fail"}` when the node
does not answer an info call (`GetInfo` on LND, `GetNodeInfo` on LDK Server)
within a few seconds, so the probe fails while the node is down or
unreachable.

Note the LND connection uses TLS with the pinned `tls.cert`; the server refuses
to start if the cert or macaroon file is unreadable rather than risking a
cleartext connection.

## Lightning backends

By default the crate builds with both `lnd` and `ldk-server` support and uses LND unless `--node-backend ldk-server` is set. At least one backend feature must be enabled.

To use LDK Server:

```bash
lnurl-server --node-backend ldk-server --domain mydomain.com --network bitcoin --data-dir ~/.lnurl-server/ --port 8080 --ldk-server-host localhost --ldk-server-port 3536 --ldk-server-cert-file ~/.ldk-server/tls.crt --ldk-server-api-key-file ~/.ldk-server/lnurl.macaroon
```

For backend-specific builds:

```bash
cargo build --no-default-features --features lnd
cargo build --no-default-features --features ldk-server
```
