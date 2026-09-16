# Container support files

This directory holds inputs consumed by the root [Dockerfile](../Dockerfile).
It is not a separate Compose project. The [root guide](../AGENTS.md) covers build
and repository procedures; [source ownership](../src/AGENTS.md) explains the Node
commands invoked by these files.

## File map and integration

| File | Purpose | Consumer |
| --- | --- | --- |
| [`proxy-connect-recovery.patch`](proxy-connect-recovery.patch) | Changes TCP connection establishment in upstream MicroSocks and Tinyproxy. | The Dockerfile's proxy builder applies it to pinned source checkouts before compilation. |
| [`tinyproxy.conf`](tinyproxy.conf) | HTTP listener, service identity, local statistics responder, idle timeout, logging, and client capacity. | Copied to `/etc/tinyproxy/tinyproxy.conf`; `src/proxies.js` launches Tinyproxy with it. |
| [`vpnc-script`](vpnc-script) | Wraps the distribution route hook, then restores this application's DNS and firewall policy. | Copied to `/app/vpnc-script`; OpenConnect invokes it for network lifecycle events. |

## Proxy build and connection behavior

The Dockerfile checks out both proxy repositories under `/src`, runs
`git apply --check`, applies the diff, and compiles the binaries. Their paths in the
patch are relative to that common parent. The final image replaces the distribution
binaries with the compiled versions; distribution packages still provide service
accounts and Tinyproxy's error/statistics pages. Keep the source pins in the
Dockerfile as the authority for the patch's upstream baseline.

The diff bounds each TCP connect attempt, closes a failed socket, and tries another
resolved address or a fresh socket within a total budget. It can make another pass
through the address list. DNS resolution happens before this budget. MicroSocks
retains address-family/bind constraints; Tinyproxy restores its normal socket
timeouts after connection. Retries occur before forwarding application data.
Established streams cannot resume after a proxy or tunnel dies.

When rebasing this diff, read the complete affected upstream functions at the new
pins. Check address-list lifetime, socket closure, binding, errno handling, and
post-connect timeouts. Patch application alone does not establish equivalent
behavior. Validate both protocols with first-connection loss, all attempts blocked,
and normal traffic using the `syn` and browser phases described in the
[test guide](../test/AGENTS.md).

## HTTP configuration contract

Tinyproxy listens inside the container on all interfaces and accepts reachable
clients without authentication. Host access is controlled by the published address
in [compose.yaml](../compose.yaml), which defaults to localhost. Do not assume a
container-side client IP represents the original host client through rootless port
forwarding.

The `StatHost` and `StatFile` provide the local HTTP health response used by
`probeHttpProxy` in `src/proxies.js`; changing them requires changing that probe.
The service user must agree with the UID resolved by `src/network.js` for firewall
ownership. Listener changes span this config, source constants, Compose targets,
Dockerfile metadata, tests, and operator commands. Read the file for current idle
timeout and capacity values; neither is a total application-request deadline.

## Route-hook contract

`vpnc-script` runs the distribution hook first so routes reflect OpenConnect's
environment. It then invokes `configure-dns` and `configure-kill-switch` through
`/app/vpn.js`. The DNS or firewall error takes precedence; if both succeed, the
wrapper returns the original distribution-hook status. Preserve this ordering and
error propagation.

The `reason` environment and Cisco split-exclusion fields belong to OpenConnect's
hook invocation. `src/network.js` validates the pushed prefixes and intersects them
with installed routes. On disconnect, policy must revoke direct exceptions. Do not
replace this with an allowlist inferred from every host-facing route. IPv4 and IPv6
policy are separate transactions within the container namespace.

## Validation and operations

Run from the repository root:

```bash
sh -n docker/vpnc-script
docker compose config --quiet
```

For changed build inputs, select a local `VPN_IMAGE` and `VPN_PULL_POLICY=never` as
shown in the [README](../README.md), then run `docker compose build` and
`docker compose up -d --wait --wait-timeout 240` against a dedicated local stack.
The build checks patch applicability. Run container self-test, routine and deep
healthchecks, and Chrome through both proxies. Route/firewall changes also need
the live firewall and tunnel phases; proxy changes need connection-loss and
sustained-traffic checks. See the test guide for fixture assumptions and cleanup.

Inspect `/etc/tinyproxy/tinyproxy.conf`, installed binary versions, route tables,
and `VPN_PROXY_KILLSWITCH` in the running container when behavior disagrees with the
checkout. Source edits require a rebuild and container recreation to take effect.
Run the hook and its network-mutating commands only inside the intended container.
Image publication is managed in [.github/workflows](../.github/workflows/AGENTS.md).
