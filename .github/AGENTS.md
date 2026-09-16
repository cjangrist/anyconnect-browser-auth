# Repository automation

This directory owns GitHub-hosted automation. It does not configure a running VPN
or store runtime credentials. Use the [root guide](../AGENTS.md) for the application
map and the [README](../README.md) for operating a local stack.

## Contents and connections

[`workflows/`](workflows/AGENTS.md) contains image publication. Its guide describes
the job, registry permissions, validation, and failure diagnosis. The workflow
builds the root Dockerfile from the context allowed by `.dockerignore`; the image is
then consumed by the root Compose definition or other explicitly managed deployments.

Publication runs on pushes to `main`, including PR merges. Branch pushes do not
publish. There is no deployment job or regression-test job here: tests are run by
the contributor before merging, and consumers update their running containers
separately. Repository-installed review integrations may report PR checks without
being defined in this directory.

## PR and release runbook

1. Start with current base-branch context, inspect the diff, and validate the changed
   behavior. Preserve unrelated working-tree changes and stage named files.
2. Push/open/merge according to the user's authorization. A request to prepare a PR
   alone does not request its merge. Describe the concrete change and test evidence;
   keep private diagnostics, credentials, and browser state outside the PR.
3. Inspect PR checks and review results for the submitted revision:

   ```bash
   gh pr view PR_NUMBER
   gh pr checks PR_NUMBER
   ```

4. After merging, verify the PR state and the `main` revision, then inspect the image
   publication run as described in the [workflow guide](workflows/AGENTS.md).
   A merged PR, successful image publication, and healthy deployed service are
   separate results; report only the ones verified for the task.

## Maintenance boundaries

Keep trigger, permissions, tag, and platform details in the workflow. Link to that
file instead of duplicating action versions or recording successful run IDs here.
When changing automation, inspect root build/configuration files as well as the
workflow. Use the nested guide for `actionlint` and image validation commands.

Do not add VPN secrets to GitHub Actions for image publication. Browser SSO happens
at container runtime using the environment supplied by the operator.
