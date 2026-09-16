# Regression and live recovery tests

This directory verifies the runtime in [src](../src/AGENTS.md) and the container
integration in [docker](../docker/AGENTS.md). Run commands from the repository root
unless an example explicitly changes directory. The [root guide](../AGENTS.md)
describes contribution and artifact handling.

## Test map

| File | Coverage | Dependencies and side effects |
| --- | --- | --- |
| [`vpn.test.js`](vpn.test.js) | TOTP reference vector, route parsing, endpoint-pool properties, keepalive settings and freshness. | Node's built-in test runner, Linux loopback/sysfs; overrides environment and module cache within its test process. |
| [`recovery.test.js`](recovery.test.js) | Provider/transport error classification, firewall rule generation, pushed-prefix validation, bounded subprocess cleanup, fragmented protocol responses, atomic state, startup grace, credential-form regressions. | Linux `/proc` and `/sys`, `curl`, `sleep`, `true`, localhost sockets, writable working directory. Starts local fixtures and child processes. |
| [`live-recovery.cjs`](live-recovery.cjs) | Real container faults, HTTP/SOCKS requests, Chrome verification, and sustained traffic. | Docker access, running local VPN stack, host `curl`, `agent-browser`, Chrome, valid runtime credentials, external network access. Opt-in and disruptive. |

`npm test` runs the `*.test.js` files through `node --test`; it does not run the live
harness. The ordinary regression suite needs no VPN credentials, browser download,
or live tunnel. It exercises local fixtures and generated firewall text, not actual
packet filtering or end-to-end SSO. Keep those distinctions in reported evidence.

## Ordinary regression run

```bash
npm ci
npm test
```

Use a Node version compatible with the package lockfile's dependency requirements.
The atomic-state test writes relative `tmp/` and `trash/` directories. For this
checkout, keep those artifacts outside the repository by running the same test
files from a dedicated external working directory:

```bash
repository_directory="$PWD"
validation_directory="$HOME/trash/anyconnect-browser-auth/tmp/$(date -u +%Y%m%d_%H%M%S)_unit_validation"
mkdir -p "$validation_directory"
(
  cd "$validation_directory"
  node --test "$repository_directory/test/vpn.test.js" "$repository_directory/test/recovery.test.js"
)
```

If `npm test` created repository-local artifacts, move them to timestamped external
archive directories after recording the results. Preserve evidence instead of
deleting it. Avoid adding assertions that merely repeat implementation text; prefer
observable behavior through real local sockets, subprocesses, or returned policy.

## Live harness prerequisites

Use a dedicated local stack and run one phase at a time. Verify the container name
with `docker compose ps -q vpn`. The harness's proxy endpoints are fixed to localhost
ports in the source; its fault scenarios also assume `tun0`, conventional container
interfaces, process names, runtime-state paths, and image user IDs. `--container`
alone does not retarget those other assumptions. The firewall phase expects a
particular gateway-pushed Microsoft prefix; inspect `firewallVerification` before
using it against a different gateway. Treat fixture mismatch separately from a
service regression.

Read both installed browser skills (`agent-browser-refs-and-multiagent`, then
`agent-browser`) before browser automation. Pass a unique `--session` and an explicit
`--browser-config` file. Inspect that file for CDP/auto-connect settings: tests need
dedicated browser sessions and must not attach to somebody else's open browser.
The harness appends `-http` and `-socks` to the supplied session name.

This example creates a minimal config in the external evidence directory. Ensure
any `AGENT_BROWSER_*` environment overrides also select a dedicated browser, since
environment values take precedence over the config file.

```bash
container_id="$(docker compose ps -q vpn)"
test_session="$(agent-browser session id --scope worktree --prefix "vpn_validation_$(date -u +%Y%m%d_%H%M%S)")"
evidence_directory="$HOME/trash/anyconnect-browser-auth/tmp/${test_session}"
mkdir -p "$evidence_directory"
browser_configuration="$evidence_directory/browser.json"
printf '%s\n' '{"autoConnect":false,"headed":false}' > "$browser_configuration"
node test/live-recovery.cjs \
  --container "$container_id" \
  --session "$test_session" \
  --browser-config "$browser_configuration" \
  --output "$evidence_directory" \
  --phase browser
```

Set all variables in the same shell. Repeat the invocation with the needed phase;
`--minutes` sets soak duration. The CLI requires session/config even for phases whose
main operation is not browser navigation, and it has no dedicated help command.
Read the `parseArgs` declaration and `run` phase table for the accepted options.

## Phase selection

| Phase | What it establishes |
| --- | --- |
| `browser` | Multiple real sites render through each proxy, with fresh navigation URLs. |
| `proxies` | Killed and frozen proxies recover while the sibling remains usable and liveness publication continues. |
| `keepalive` | Aggregate echo cadence and continued operation when one responder is blocked. |
| `tunnel` | Recovery after complete ICMP loss, interface down, OpenConnect termination, and a frozen OpenConnect process. |
| `transport` | Recovery while incoming VPN UDP transport is interrupted, retaining the OpenConnect session. |
| `firewall` | Proxy UID rejection, atomic refresh under traffic, pushed-exclusion revocation and restoration. |
| `syn` | A lost first TCP connection succeeds through retry, while loss of all attempts fails within a bound. |
| `egress` | HTTP proxy egress failure is detected even when its local health page still responds; SOCKS remains usable. |
| `saturation` | Both proxies remain useful while incomplete HTTP connections occupy client slots. |
| `soak` | Repeated requests to multiple sites with unchanged proxy processes; saves control requests if a request fails. |
| `cleanup` | Each dedicated browser session retains one blank tab and closes the other tabs in that session. |

Most successful fault phases also perform Chrome verification. JSON results are
written to `--output`; stdout carries progress and the final result. Capture complete
stdout/stderr for timing and failed assertions. The egress phase waits for periodic
checks and may take several minutes with default settings. Use current measurements
in PR evidence rather than copying historical timings into these guides.

## Fault cleanup and acceptance

The harness removes many injected rules in `finally` blocks, but an interrupted
process cannot guarantee cleanup. Inspect the affected container's rules and process
state after an interrupted phase. Remove only the specific injected rules and
restore only the test's stopped processes, or recreate the dedicated test stack from
Compose. Never flush a host firewall or another stack to recover a fixture.

Run `healthcheck` and `deep-healthcheck` afterward, verify Chrome through both
proxies, and invoke `--phase cleanup` with the same session/config/output arguments.
Cleanup closes all tabs in those named sessions, which is why session ownership is
required. Browser cleanup does not restore packet-filter rules or processes.

For runtime changes, choose phases based on affected behavior and include a normal
request after each injected fault. Report both assertions and rendered-page evidence;
a process restart alone does not prove restored application traffic. Documentation
changes need link/command verification, regression checks, and rendered-document
inspection; they do not require injecting unrelated live faults.
