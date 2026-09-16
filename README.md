# Autonomous AnyConnect SAML + TOTP VPN proxy

Run an AnyConnect-compatible VPN, unattended browser authentication, and HTTP/SOCKS5
proxies in one Docker container. OpenConnect owns the VPN protocol and SSO callback;
Playwright completes Microsoft-style username, password, and TOTP forms. The host
keeps its normal routes and DNS.

The HTTP proxy is available at `http://127.0.0.1:8080`; SOCKS5 is available at
`socks5h://127.0.0.1:1080`. Both published ports default to **localhost only** and
require no proxy password. Use `socks5h` for proxy-side DNS resolution.

## Start from the published image

Requires Linux, Docker Compose v2, `/dev/net/tun`, and permission to grant network
capabilities inside the container. Rootless Docker support depends on the host's
TUN and user-namespace configuration.

```bash
cp .env.sample .env
chmod 600 .env
```

Fill in `VPN_SERVER`, `VPN_USERNAME`, `VPN_PASSWORD`, and `VPN_TOTP_SECRET` in `.env`.
The server must be HTTPS. The TOTP seed can be raw base32, `base32:...`, or an
`otpauth://` URI. The supported generator uses six-digit SHA-1 codes and a 30-second
period; keep the host clock synchronized. Single-quote Compose dotenv values that
contain `$`, `#`, spaces, or other special characters.

```bash
docker compose config --quiet
docker compose up -d --wait --wait-timeout 240
docker compose ps
```

The default image is `ghcr.io/cjangrist/anyconnect-browser-auth:latest` with
`VPN_PULL_POLICY=always`. Configuration rendering without `--quiet` can print secrets.

## Build and run this checkout locally

Set these non-secret values in your private `.env`:

```dotenv
VPN_IMAGE=anyconnect-browser-auth:local
VPN_PULL_POLICY=never
```

Then build and start:

```bash
docker compose build
docker compose up -d --wait --wait-timeout 240
```

This keeps subsequent `docker compose up` operations on the local build. Changing
source alone does not update a running container: rebuild and run `up` again.
`COMPOSE_PROJECT_NAME` selects the local stack name.

## Keepalive, health, and recovery

One ICMP echo is sent **every second**, rotating across five default targets:
`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222`, and `94.140.14.14`.
Each target receives one echo every five seconds. Every ping binds explicitly to
`tun0`, so replies over the ordinary host-facing route cannot make a dead VPN look
healthy. Pings have a bounded lifetime and stop with their VPN session.

The liveness watchdog runs independently of web requests and proxy probes. It checks
the interface's administrative state and the most recent successful tunnel-bound
reply. One unavailable responder does not interrupt service. With the defaults, a
complete loss of replies becomes stale after 15 seconds; three failed watchdog ticks
trigger recovery. A missing or down interface is detected without waiting for stale
ping replies.

Before starting proxies, the supervisor records the pre-VPN public IP, waits for
successful tunnel keepalives, and verifies that VPN egress differs from the baseline.
Baseline collection retries if the Internet or an IP-reporting endpoint is unavailable.

Docker's routine `healthcheck` reads an atomically published local state file and
checks both proxy protocols. It makes **no website requests**. The state includes
readiness and a timestamp, so an old file cannot keep a dead supervisor healthy.

Deeper egress checks run every five minutes. They rotate through a pool of 26 HTTPS
IP-reporting endpoints and try up to three endpoints per check. A single website's
rate limit, invalid response, or certificate failure does not restart the VPN. A
confirmed return to the baseline IP requests a reconnect. Repeated transport failures
across the fallback endpoints also request recovery. Manual `deep-healthcheck` performs
fresh direct, HTTP-proxy, and SOCKS-proxy egress checks and may take up to about 27
seconds when fallback endpoints time out.

Each proxy is supervised separately. A dead process is replaced at the next supervision
cycle; a hung process must fail three probes before replacement. Restarting HTTP does
not stop SOCKS, and restarting SOCKS does not stop HTTP. Proxy cleanup is bounded and
port reuse waits for the old process to exit. Tinyproxy allows 1,024 clients and has a
60-second inactivity timeout; this is an idle timeout, not a total request deadline.

Both proxy binaries are built from pinned upstream source with a connection-establishment
fix in [docker/proxy-connect-recovery.patch](docker/proxy-connect-recovery.patch).
A TCP attempt gets at most 2.5 seconds, then the proxy tries another resolved address
or a fresh socket. It makes up to two passes through the addresses within a 7.5-second
TCP connection budget. DNS resolution precedes that budget. This repairs connections
whose SYN packets receive no reply even while other connections to the same host work.
Retries happen before application data is sent; established streams are not replayed.
Tinyproxy retains its separate 60-second inactivity timeout after connecting.

OpenConnect uses a five-second dead-peer detection interval to repair transport
interruptions using its existing session. Once a tunnel interface appears, the first
keepalive reply has a 15-second budget, independent of the longer SSO deadline.
Failed browser authentication reports a session-specific status to the supervisor
so it can retry promptly. When the
watchdog requests a new session, it sends SIGTERM and allows five seconds for exit
before SIGKILL. Remaining authentication descendants are terminated with the old
process group. A forced OpenConnect termination exits the supervisor so Docker can
restart a fresh network namespace. Normal child exit retries browser SSO after five
seconds. SIGTERM to the container stops the children without scheduling another login.

Recovery needs no manual login during the supported SSO/TOTP flow. A broken TCP
connection cannot be resumed across a lost tunnel or dead proxy process; clients must
retry requests interrupted by those events. Gateway or identity-provider outages,
changed MFA policies, and rejected credentials can extend the recovery period.

## Routing and firewall behavior

UID-scoped IPv4 and IPv6 rules protect Tinyproxy and MicroSocks before either starts.
Proxy traffic can leave through `tun0`; established responses to proxy clients are
also allowed. The gateway's explicit split exclusions are honored, including Microsoft
365 destinations when the gateway pushes those prefixes. The gateway's own control
route and unrelated host routes do not become implicit bypass permissions.

The route hook intersects validated pushed exclusions with installed routes. It
refreshes policy on connect/reconnect and revokes the exceptions on disconnect.
Each firewall family is replaced with a single `iptables-restore --noflush`
transaction, avoiding a period with an empty permissive chain. Other chains are
preserved. Ordinary traffic cannot fall back to direct egress when the tunnel fails.
Split-excluded destinations intentionally use the direct route while connected.

The container uses exactly `1.1.1.1`, `1.0.0.1`, `8.8.8.8`, and `8.8.4.4` as DNS
servers. The supervisor writes and verifies that resolver configuration before
baseline capture and authentication, and the route hook reasserts it after network
events. This replaces Docker's embedded resolver and service-name DNS in this container.

Compose drops all capabilities and adds `KILL`, `NET_ADMIN`, `NET_RAW`, `SETUID`, and
`SETGID`. `NET_RAW` permits the image's ping binary. It publishes only TCP proxy ports;
`VPN_PROXY_HOST_IP` explicitly controls their host binding. Logs rotate at three
10-MB files.

## Configuration

Every supported environment variable is listed in the secret-free [.env.sample](.env.sample).
Runtime variables are passed through Compose as bare names. Empty optional values
use the defaults in [src/config.js](src/config.js).

| Setting | Default | Purpose |
| --- | --- | --- |
| `VPN_PROXY_HOST_IP` | `127.0.0.1` | Published host address for both proxies. |
| `VPN_KEEPALIVE_TARGETS` | Five IPs listed above | Comma-separated, deduplicated ICMP targets. |
| `VPN_KEEPALIVE_INTERVAL_SECONDS` | `1` | Aggregate send interval; must be positive and at most one second. |
| `VPN_KEEPALIVE_STALE_MILLISECONDS` | `15000` | Maximum reply age; must exceed a full target rotation plus two seconds. |
| `VPN_LIVENESS_INTERVAL_MILLISECONDS` | `1000` | Independent watchdog cadence. |
| `VPN_LIVENESS_STATE_STALE_MILLISECONDS` | `30000` | Maximum age of supervisor state accepted by healthcheck. |
| `VPN_LEAK_CHECK_INTERVAL_MILLISECONDS` | `300000` | Direct egress verification interval. |
| `VPN_PROXY_EGRESS_CHECK_INTERVAL_MILLISECONDS` | `300000` | Egress verification interval per proxy. |
| `VPN_PROXY_SUPERVISE_INTERVAL_MILLISECONDS` | `15000` | Local proxy supervision interval. |
| `VPN_PROXY_FAILURE_THRESHOLD` | `3` | Consecutive proxy failures before recycling. |
| `VPN_PROXY_PROBE_TIMEOUT_MILLISECONDS` | `5000` | Absolute protocol-probe deadline. |
| `VPN_PROXY_START_TIMEOUT_MILLISECONDS` | `15000` | Proxy readiness budget. |
| `VPN_WATCHDOG_FAILURE_THRESHOLD` | `3` | Consecutive liveness failures before reconnection. |
| `VPN_WATCHDOG_STARTUP_GRACE_MILLISECONDS` | Browser timeout + 30000 | Time allowed for initial SSO/tunnel setup. |
| `VPN_BROWSER_TIMEOUT_MILLISECONDS` | `180000` | Browser authentication deadline. |
| `VPN_PUBLIC_IP_ENDPOINT` | Rotating pool | Optional single HTTPS endpoint returning a plain IP. |
| `VPN_PUBLIC_IP_FAMILY` | `4` | Address family for public-IP verification. |
| `VPN_TUNNEL_INTERFACE` | `tun0` | OpenConnect and keepalive interface. |
| `VPN_HEALTHCHECK_INTERVAL` | `60s` | Docker healthcheck interval, independent of the watchdog. |
| `VPN_HEALTHCHECK_TIMEOUT` | `10s` | Docker healthcheck deadline. |
| `VPN_HEALTHCHECK_RETRIES` | `8` | Docker's consecutive failure count. |
| `VPN_HEALTHCHECK_START_PERIOD` | `90s` | Docker startup grace period. |

The sample also documents browser-profile and runtime-state paths. Docker does not
restart a container just because its health status becomes unhealthy; the supervisor
performs recovery, and `restart: unless-stopped` handles supervisor exits.

The public-IP check assumes those endpoints use the VPN. Gateways that route all public
Internet traffic directly need a VPN-routed verification endpoint. An IPv6-only setup
also needs suitable IPv6 keepalive targets and a compatible IP-reporting endpoint.

## Verification and diagnostics

```bash
npm ci
npm test
docker compose config --quiet
docker compose exec -T vpn /app/vpn.js self-test
docker compose exec -T vpn /app/vpn.js healthcheck
docker compose exec -T vpn /app/vpn.js deep-healthcheck
curl --fail --proxy http://127.0.0.1:8080 https://api.ipify.org
curl --fail --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
docker compose logs --since 10m vpn
```

The self-test validates credential presence and TOTP generation without printing
secrets. The routine healthcheck checks fresh readiness plus proxy protocols; the deep
check verifies current application egress. `/app/vpn.js probe` repeats routine checks.

[test/live-recovery.cjs](test/live-recovery.cjs) is an **opt-in disruptive local test**.
It can kill or stop proxy/OpenConnect processes and interrupt tunnel traffic. Its
`--phase` values are `browser`, `proxies`, `keepalive`, `tunnel`, `transport`, `firewall`, `syn`,
`egress`, `saturation`, `soak`, and `cleanup`.
The egress phase can take six minutes with the default five-minute deep-check interval.
Run phases sequentially against a dedicated local stack; simultaneous fault injection
invalidates their recovery measurements. Pass `--container`, `--session`, `--browser-config`, and `--output` for
your local setup; `--minutes` controls the soak length. Browser verification requires
an installed `agent-browser` and Chrome. The session and browser config are required
to keep the test isolated from other browser work. This script is excluded from ordinary `npm test`.

Inspect `watchdog.liveness.failed`, `watchdog.reconnect.triggered`,
`public_ip.endpoint.failed`, and per-proxy restart events to distinguish tunnel loss,
provider failures, and proxy failures. Authentication logs redact credential values and
SSO material. Keep raw operational logs private.

## Source layout and image maintenance

- `src/vpn.js`: lifecycle, independent watchdog, and CLI dispatch.
- `src/authentication.js`: browser state machine, TOTP, and authentication redaction.
- `src/network.js`: DNS, atomic firewall policy, pushed exclusions, and IP verification.
- `src/keepalive.js`: rotating tunnel-bound ICMP and atomic health state.
- `src/proxies.js`: protocol probes and independent process supervision.
- `src/runtime.js`: logging and bounded subprocess utilities.
- `src/config.js` and `src/state.js`: configuration and supervisor-owned state.

The Dockerfile pins OpenConnect commit `70d1e79d1e55849dfc71dcc199b1edb535b547e4`,
MicroSocks `98421a21c4adc4c77c0cf3a5d650cc28ad3e0107` (v1.0.5),
Tinyproxy `baecbf4c3e006fa68ab92f65bbd4138c47ede111` (1.11.3),
Playwright `1.62.0`, and agent-browser `0.34.0`. The proxy source diff is applied during
compilation; the resulting binaries replace the distribution binaries. Distribution
packages still supply Tinyproxy's service account and static error/statistics pages.
Keep the Playwright dependency, lockfile,
and image tag aligned. Before publishing, build the image and verify fresh SSO,
Chrome through both proxies, child and container recovery, firewall behavior, and
sustained traffic. The existing GitHub workflow publishes the image on repository
pushes to `main`; local commits and PR branch pushes do not publish it.

## Authentication compatibility and private files

The browser supports Microsoft-style account selection, username/password, software
TOTP choice, code retry, and “Stay signed in?” pages. It does not implement push MFA,
SMS retrieval, passkeys, CAPTCHA, device-compliance enrollment, or arbitrary IdP forms.
The container's browser profile is separate from the host profile and persists across
restarts of the same container. Recreating the container starts with a fresh profile.

`.env`, `tmp/`, and `trash/` are excluded from Git and the build context. Old transcripts,
research checkouts, and test evidence can be archived under timestamped `trash/`
directories. Credentials stay in the private `.env`; Docker administrators can inspect
the runtime environment, so access to Docker and backups also controls those secrets.

Use `docker compose stop` to stop the local service while retaining its container.

The project is MIT licensed; see [LICENSE](LICENSE). Dependencies retain their licenses.
Upstream references: [OpenConnect](https://gitlab.com/openconnect/openconnect),
[OpenConnect manual](https://www.infradead.org/openconnect/manual.html),
[Playwright](https://playwright.dev/), and [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
