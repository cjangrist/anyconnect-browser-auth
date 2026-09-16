# Image publication workflow

This directory defines GitHub Actions execution. Its parent [guide](../AGENTS.md)
covers repository automation; the root [guide](../../AGENTS.md) covers development.

## File and execution path

[`publish-image.yml`](publish-image.yml) builds the root [Dockerfile](../../Dockerfile)
and publishes `ghcr.io/${{ github.repository }}:latest` when a push reaches `main`.
Merging a PR produces such a push, including a documentation-only PR. A PR branch
push does not publish. Read the workflow for the supported platform, action versions,
permissions, tags, and build options before changing release behavior.

The job checks out the triggering revision, prepares Buildx, authenticates to GHCR
with `GITHUB_TOKEN`, then builds and pushes. OCI labels identify the source repository
and revision. `contents: read` supports checkout; `packages: write` supports publication.
Runtime VPN credentials are not build inputs or workflow secrets.

The root [.dockerignore](../../.dockerignore) controls the context sent to the builder.
[Container support](../../docker/AGENTS.md) explains the compiled proxy changes and
route hook. Publication produces an image; this job does not start a VPN, authenticate
to an identity provider, deploy a Compose stack, or run the repository tests.

## Change and validation runbook

1. Read the entire workflow together with the Dockerfile and context allowlist.
   Check triggers and tag ownership before changing when a mutable tag is updated.
2. Run `actionlint .github/workflows/publish-image.yml` from the repository root.
   Validate build changes locally with an explicit local image tag; the root README
   describes how to prevent Compose from pulling over that local image.
3. Run the checks appropriate to changed runtime behavior from the
   [test guide](../../test/AGENTS.md). A successful image build does not establish
   working SSO, tunnel recovery, proxy egress, or firewall isolation.
4. After an authorized merge, inspect the Actions run for the merged revision:

   ```bash
   gh run list --workflow publish-image.yml --branch main
   gh run view RUN_ID
   gh run view RUN_ID --log-failed
   docker buildx imagetools inspect ghcr.io/cjangrist/anyconnect-browser-auth:latest
   ```

   Replace `RUN_ID` with the run for that revision. Record the published digest when
   diagnosing a release; `latest` alone cannot identify the image used by a container.

## Failure ownership

| Failed step | Inspect first |
| --- | --- |
| Checkout or action startup | Action reference, repository access, runner logs. |
| Registry login or push | Job permissions, package access, repository/package association. |
| Source checkout, patch, or compilation | Dockerfile pins and `docker/proxy-connect-recovery.patch`. |
| Dependency installation | Package manifest, lockfile, Playwright base image alignment. |
| Image published but service fails | Actual deployed digest and runtime diagnostics in the root README. |

Keep this guide about the workflow's contract and diagnostics. Keep exact pins in
the workflow and Dockerfile, and keep transient run IDs and results in PR evidence.
