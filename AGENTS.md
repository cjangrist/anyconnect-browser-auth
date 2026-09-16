# Repository map and contributor runbook

This project runs an AnyConnect-compatible VPN, browser SAML/TOTP authentication,
and HTTP/SOCKS proxies in one container. The host keeps its own routes and DNS.
Start with [README.md](README.md) for installation and operation; use this file to
find implementation owners and choose validation for a change.

## Folder guides

Read the guide in the folder you are changing, together with this root guide.

| Folder | Responsibility | Local guide |
| --- | --- | --- |
| `src/` | Node supervisor, authentication, networking, keepalive, health, proxy lifecycle. | [Source map and invariants](src/AGENTS.md) |
| `docker/` | Compiled proxy source changes, Tinyproxy settings, OpenConnect route hook. | [Container integration runbook](docker/AGENTS.md) |
| `test/` | Local regression fixtures and opt-in real recovery validation. | [Test selection and cleanup](test/AGENTS.md) |
| `.github/` | Repository automation and PR/release procedure. | [Automation map](.github/AGENTS.md) |
| `.github/workflows/` | Image build and GHCR publication. | [Publication runbook](.github/workflows/AGENTS.md) |

Git internals, installed dependencies, runtime state, and external evidence archives
are not source folders. Keep navigation guides focused on maintained repository
content.

## Root file map

| File | Authority and relationship |
| --- | --- |
| [Dockerfile](Dockerfile) | Build stages, upstream revision pins, installed tools, runtime paths, container entrypoint. Builds OpenConnect and the patched proxies, then copies source into `/app`. |
| [compose.yaml](compose.yaml) | Service/image selection, restart policy, capabilities, TUN access, host port binding, environment passthrough, healthcheck, and log rotation. |
| [.env.sample](.env.sample) | Secret-free operator configuration template. Private `.env` supplies local credentials and overrides; it is not committed. |
| [package.json](package.json) | Node package metadata, direct dependency requirements, and ordinary test command. |
| [package-lock.json](package-lock.json) | Exact npm dependency resolution used by `npm ci`; keep Playwright aligned with the Docker base image. |
| [.dockerignore](.dockerignore) | Allowlist of files sent to Docker builds. Separate from Git ignore rules. |
| [.gitignore](.gitignore) | Excludes private environment files, dependencies, and local artifacts from Git. |
| [.gitattributes](.gitattributes) | Whitespace treatment for upstream unified diffs. |
| [README.md](README.md) | Operator entry point, architecture, configuration, diagnostics, and maintenance commands. |
| [LICENSE](LICENSE) | Project license; bundled/upstream dependencies retain their own licenses. |

## Architecture and ownership

Docker starts `tini`, which starts `/app/vpn.js connect`. The supervisor installs
resolver/firewall policy, captures the pre-VPN public IP, and starts OpenConnect.
OpenConnect invokes the same executable with an SSO URL to drive Playwright, and
invokes `/app/vpnc-script` to apply routes and refresh local DNS/firewall policy.

Tunnel-bound keepalives feed an independent watchdog. Once liveness and changed
egress establish readiness, the supervisor starts and independently maintains
Tinyproxy and MicroSocks. Clients reach those proxies through localhost-published
ports. Docker's healthcheck reads local published state and probes both protocols;
deeper checks compare direct and proxy egress with the pre-VPN baseline.

Recovery belongs to the supervisor and OpenConnect. Docker's restart policy handles
supervisor exits; Docker does not restart merely because health becomes unhealthy.
The firewall applies to proxy UIDs inside the container and honors validated
gateway split exclusions. It is not a host-wide firewall or a blanket ban on all
non-tunnel container traffic. Existing TCP streams require client retry after a
tunnel or proxy loss; compiled proxy retries cover connection establishment only.

## Working procedure

1. Read the complete files affected by the task, their folder guides, and connected
   configuration/tests. Inspect Git status and current branch/base before edits.
2. Fix behavior at its owner. Keep configuration in `src/config.js`, lifecycle in
   the supervisor, and upstream proxy connection changes in the build-time diff.
   Preserve module imports, bounded operations, credential redaction, and recovery
   invariants documented in the source guide.
3. Keep changes scoped. Preserve unrelated edits; stage individual files. Commit at
   validated breakpoints. Follow the user's current authorization for branch,
   push, PR, merge, and deployment operations.
4. Run applicable checks below and inspect the full diff. Document what the checks
   establish and any environment-specific assumptions in the PR.
5. After an authorized merge, verify the merge and its image-publication run.
   Publication changes `latest`; consumers still need an explicit update/recreation
   to run it. Do not equate publication with deployment.

## Validation by change

| Changed area | Required evidence |
| --- | --- |
| Documentation | Relative links/anchors and file references resolve; examples agree with source; rendered pages are readable; regression suite remains green. |
| Node source or configuration | Regression tests, JavaScript syntax, Compose validation, rebuilt local image, relevant container health and real behavior. |
| Browser authentication | Fresh SSO against the intended gateway plus browser-form regression cases; preserve private authentication evidence. |
| Keepalive, lifecycle, or proxy supervision | Live phases for the affected failures, recovery through both proxies, and Chrome proof after faults. |
| Route hook or firewall | Shell syntax, rebuilt image, live firewall/tunnel checks including exclusion behavior and direct-egress rejection. |
| Compiled proxy code or dependency pins | Successful build/patch application, connection-loss checks, browser traffic through both proxies, and sustained requests. |
| GitHub workflow | `actionlint`, applicable build validation, then inspection of the authorized publication run. |

The [test guide](test/AGENTS.md) supplies commands, live-phase selection, and fixture
limitations. For baseline checks from the root:

```bash
npm ci
npm test
sh -n docker/vpnc-script
docker compose config --quiet
git diff --check
```

Use the test guide's external-working-directory invocation if avoiding test-created
`tmp/` and `trash/` in the checkout. Network-mutating CLI commands run only inside
the intended container. Check current container behavior with the README's routine
and deep healthcheck commands; rebuilding is necessary when runtime inputs change.

## Private state and cleanup

Preserve the private `.env` and its restrictive permissions. Do not include
credentials, authentication URLs/cookies, browser profiles, or raw private logs in
commits or PRs. Compose configuration without `--quiet` can reveal environment
values. Build-context exclusions and Git exclusions are independent protections.

For this workstation checkout, put temporary work under
`~/trash/anyconnect-browser-auth/tmp/<UTC_timestamp>_<snake_case_task>/` and preserved
obsolete material under
`~/trash/anyconnect-browser-auth/trash/<UTC_timestamp>_<snake_case_task>/`.
Move material rather than deleting it, and verify destination contents and source
absence. The ordinary tests still create relative artifact directories; run them
externally or move their output afterward. Do not place new archives in the repo.

## Keeping documentation useful

Folder guides describe ownership, dependencies, invariants, and operational steps.
Keep exact pins, endpoint pools, and default settings in their authoritative files.
Avoid copying test counts, historical recovery timings, container IDs, branch names,
or temporary evidence paths into permanent guides. When behavior or ownership
changes, update its nearest guide and any affected README instructions in the same
change. Keep deeper implementation detail in the folder guides and the root map
focused on finding it.
