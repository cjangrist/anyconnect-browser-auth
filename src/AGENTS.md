# VPN supervisor source

These CommonJS modules implement the container's control plane. Read the root
[guide](../AGENTS.md) for repository-wide procedures and the
[README](../README.md) for operator commands. The [Dockerfile](../Dockerfile)
copies this directory's contents into `/app`, so `src/vpn.js` becomes `/app/vpn.js`.
Relative module imports must continue to work in both layouts.

## Responsibility map

| File | Owns | Main connections |
| --- | --- | --- |
| [`vpn.js`](vpn.js) | CLI dispatch, startup, OpenConnect sessions, watchdog, maintenance scheduling, shutdown. | Coordinates all other modules; invoked by Docker, OpenConnect's external-browser callback, and the route hook. |
| [`authentication.js`](authentication.js) | Credential reads, base32/TOTP, browser form state machine, callback recognition, authentication redaction. | Lazily loads Playwright; OpenConnect supplies the SSO URL through `vpn.js`. |
| [`config.js`](config.js) | Environment-derived constants and configuration validation. | Shared by runtime modules; public settings also appear in root Compose and `.env.sample`. |
| [`state.js`](state.js) | Mutable process handles, timers, readiness, counters, and serialized proxy-operation promise. | Shared within one Node process; separate CLI invocations do not share this object. |
| [`runtime.js`](runtime.js) | Event logging, subprocess deadlines, UID/GID lookup, stream handling, bounded child cleanup, atomic file writes. | Low-level utilities used by the supervisor, networking, keepalive, and proxies. |
| [`network.js`](network.js) | Static DNS, baseline IP, rotating public-IP checks, pushed exclusions, UID-scoped firewall policy. | Invokes system tools; used both by the supervisor and separate route-hook commands. |
| [`keepalive.js`](keepalive.js) | Tunnel-bound ping rotation, last successful reply, interface checks, startup grace, liveness file. | Uses shared state in the supervisor and reads published state for healthcheck processes. |
| [`proxies.js`](proxies.js) | HTTP/SOCKS protocol probes, process definitions, readiness, independent recovery, egress checks. | Requires networking to resolve proxy identities and the supervisor to permit serving traffic. |

## Lifecycle and concurrency

`connectForever` validates configuration and credentials, writes static DNS, installs
the proxy firewall, and captures the public IP before starting the VPN. Baseline
collection retries before authentication. Each `runOpenConnect` session resets
readiness, starts the keepalive scheduler, creates an authentication session ID, and
launches OpenConnect in a separate process group.

OpenConnect calls this same executable with an SSO URL. That separate Node process
runs the persistent Playwright browser and watches for the accepted local SSO
callback. On failure it writes `authentication-status` with the session ID; the
supervisor ignores status belonging to a different session. The browser supports
the Microsoft-style account/password/software-TOTP flow implemented in
`driveAuthenticationPage`; new identity-provider behavior belongs there.

The watchdog evaluates interface state and keepalive freshness independently of
slow website requests. It publishes liveness and launches at most one maintenance
operation at a time. Maintenance verifies egress before setting tunnel readiness,
then supervises proxies. Preserve the session identity and shutdown checks after
awaited work: an old operation must not make a replacement session ready.

Proxy start/stop/supervision operations are serialized by `queueProxyOperation`;
the HTTP and SOCKS checks within a supervision pass run independently. A proxy must
not start unless `canServeProxyTraffic` permits it. Local protocol success and
successful application egress are different observations.

OpenConnect exit clears readiness, stops keepalives and proxies, and terminates
remaining processes in its group. Ordinary exit enters the reconnect loop. Forced
OpenConnect termination exits the supervisor so Docker can recreate the network
namespace on restart. Container termination sets shutdown intent before cleanup
so no replacement session or proxy starts during shutdown.

## State crossing process boundaries

| State | Producer and consumer |
| --- | --- |
| Original public IP | Captured before OpenConnect; read by direct and proxy egress comparisons. |
| Liveness JSON | Atomically written by the supervisor; checked for freshness and readiness by independent healthchecks. |
| Authentication status | Written by a failed browser invocation; consumed only by its matching watchdog session. |
| Split-exclusion JSON | Captures gateway-pushed prefixes during route-hook processing; used with installed routes when refreshing policy. |
| Browser profile | Playwright session data reused within the same container filesystem. |

Paths come from `config.js`. The baseline file's parent determines `RUNTIME_DIRECTORY`
for authentication status and split-exclusion files; the liveness file and browser
profile have independent path settings. State is private runtime material, not a
checked-in fixture. The root Compose file does not mount a persistent profile volume.

## Invariants to preserve

- Keepalive cadence is aggregate across the target rotation, and each ping binds to
  the configured tunnel interface. The stale deadline must accommodate a full
  rotation and ping completion. Failed or old-session pings cannot renew liveness.
- A healthcheck needs a fresh published state, ready tunnel, fresh reply, readable
  baseline, and working local proxy protocols. It does not contact public websites.
  Deep health checks additionally verify direct and both proxy egress paths.
- A baseline-IP match is a confirmed leak and requests reconnect. Provider-side
  errors or invalid IP content can be inconclusive; repeated transport failures
  count toward recovery. Preserve curl CONNECT-status classification so a proxy
  connection failure cannot masquerade as an unhealthy reporting website.
- Firewall exceptions require validated gateway-pushed prefixes matching installed
  non-tunnel gateway routes. A parsed route by itself grants no exception. Replace
  each firewall family atomically and retain terminal rejection for proxy UIDs.
- Authentication selectors must use visible fields, prioritize password forms,
  verify retained input, and submit the filled field where required. Hidden username
  fields and unfocused password fields are regression cases in `test/recovery.test.js`.
- `log` does not automatically redact arbitrary objects. Sanitize authentication
  messages at the call site and never log credentials, generated codes, cookies,
  SSO query strings, or the complete environment.
- Runtime imports must remain safe for tests: `vpn.js` starts only when executed as
  the main module. Configuration is read at module load; tests changing environment
  settings need fresh module state or a separate process.

## Change and diagnostic runbook

Work from the [test guide](../test/AGENTS.md) and run commands at the repository root.
Run `npm test` for source changes, then rebuild the local image before assessing
container behavior. Syntax-check changed modules with `node --check src/FILE.js`.
Use `/app/vpn.js healthcheck` for local readiness and `deep-healthcheck` for current
egress, as shown in the README. Do not execute `connect`, `configure-dns`, or
`configure-kill-switch` on the host: they modify resolver or firewall state.

| Symptom | Follow the ownership path |
| --- | --- |
| Login never completes | `authentication.js` form handlers → browser callback → session-specific failure state in `vpn.js`. |
| Tunnel recovery is slow | `keepalive.js` interface/reply timestamps → `vpn.js` startup grace and watchdog → child exit. |
| One proxy fails | `proxies.js` local probe and egress classification → per-proxy counters and restart; inspect the sibling separately. |
| Requests stall before connecting | [Compiled proxy connection logic](../docker/AGENTS.md), then DNS and destination reachability. |
| Unexpected direct egress | `network.js` baseline/provider selection → pushed exclusions → installed routes and UID rules. |
| Health stays stale | Supervisor process and atomic state writer → published path/settings → independent healthcheck reader. |

For a new public setting, update configuration, validation, Compose passthrough,
`.env.sample`, and the relevant operator documentation together. Internal callback
environment such as `VPN_AUTHENTICATION_SESSION` is supervisor-owned and should not
become a user setting. Keep exact default values in configuration and the sample;
describe contracts and ownership here.
