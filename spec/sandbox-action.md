# Sandbox Action

GitHub Action (`airutorg/sandbox-action`) that wraps `airut-sandbox` for PR
workflows, handling base-branch checkout, PR SHA fetch, and sandboxed execution
in a single `uses:` step.

For usage documentation (inputs, workflow examples, configuration), see the
[sandbox-action README](https://github.com/airutorg/sandbox-action#readme). For
the security model and repository setup requirements, see
[doc/ci-sandbox.md](../doc/ci-sandbox.md). For the maintenance workflow, see
[workflows/sandbox-action.md](../workflows/sandbox-action.md).

## Consumer Interface

```yaml
- uses: airutorg/sandbox-action@v0
  with:
    command: 'uv sync && uv run pytest'
    pr_sha: ${{ github.event.pull_request.head.sha }}
  env:
    GH_TOKEN: ${{ secrets.GH_TOKEN }}
```

### Inputs

| Input           | Required | Default        | Description                                                               |
| --------------- | -------- | -------------- | ------------------------------------------------------------------------- |
| `command`       | Yes      |                | CI command to run inside the sandbox (after PR checkout)                  |
| `pr_sha`        | Yes      |                | PR commit SHA to check out and test                                       |
| `merge`         | No       | `true`         | Merge PR into base branch before running (like GitHub's default behavior) |
| `airut_version` | No       | from `VERSION` | Airut version to install. PyPI version or `main` for GitHub HEAD.         |
| `sandbox_args`  | No       | `--verbose`    | Additional arguments passed to `airut-sandbox run`.                       |
| `cache`         | No       | `true`         | Enable image caching across CI runs.                                      |
| `cache-version` | No       | `""`           | Arbitrary string to force cache invalidation.                             |
| `cache-max-age` | No       | `168`          | Maximum image age (hours) before forced rebuild. Default one week.        |

### Consumer Prerequisites

The consuming repository must have `.airut/container/Dockerfile` on the default
branch. `.airut/sandbox.yaml` and `.airut/network-allowlist.yaml` are optional
(defaults apply). The network allowlist does **not** need to include the
repository's GitHub URL -- the action fetches the PR SHA on the host before
entering the sandbox.

## Security Model

The base branch is trusted; the PR is untrusted. See
[doc/ci-sandbox.md](../doc/ci-sandbox.md#trust-model) for the four trust
invariants and [doc/ci-sandbox.md](../doc/ci-sandbox.md#security-requirements)
for the full security requirements checklist.

**Required external controls** (the action cannot enforce these):

1. The PR author must not be able to modify `.github/workflows/` (omit
   `workflow` PAT scope or use a push ruleset).
2. The workflow must only trigger on PRs targeting protected branches
   (`pull_request: branches: [main]`).

**Tainted workspace**: After sandbox execution, the workspace is tainted (the
sandbox mounts it read-write, and untrusted PR code had full write access). The
sandbox action must be the **final step** of the job.

## Versioning

The `VERSION` file in the action repo controls which `airut-sandbox` version is
installed. Action versions mirror airut releases:

| Action ref | VERSION file | airut-sandbox source   | Use case                         |
| ---------- | ------------ | ---------------------- | -------------------------------- |
| `@main`    | `main`       | `git+.../airut@main`   | Development, airut repo's own CI |
| `@v0`      | latest 0.x.y | PyPI `airut==<latest>` | Stable, auto-updates with minor  |
| `@v0.16.0` | `0.16.0`     | PyPI `airut==0.16.0`   | Pinned to exact version          |

The `v0` branch is the stable release ref. Consumers using `@v0` resolve to this
branch and automatically pick up minor and patch releases when PRs merge.

### Branching Strategy

The `vN` branches are protected and serve as the source of truth for released
versions. There are two development tracks:

- **Action implementation changes** happen on `main` and are cherry-picked to
  `vN` via reviewed PRs when they need to ship.
- **Airut version bumps** happen via PRs directly against `vN` that update the
  `VERSION` file.

Pinned release tags (`vN.x.y`) point to commits on `vN`. The release branch is
never force-pushed or reset to `main`, preserving compatibility within a major
version.

See [workflows/sandbox-action.md](../workflows/sandbox-action.md) for the
release process.

## Image Caching

The action caches repo and proxy container images across CI runs using
`actions/cache`, saving ~50 s per run on cache hit. Caching is enabled by
default and can be disabled with `cache: false`.

See [image.md](image.md#ci-image-caching) for the full design, cache key
structure, step ordering, and security model.

## Design Decisions

### Step Ordering

The action's composite steps run in this order: install uv/Python, install
airut-sandbox, checkout base branch, fetch PR SHA, run sandboxed command. Key
constraints:

- `airut-sandbox` is installed **before** checkout -- if installation fails,
  there is no point checking out the repo.
- The base branch is checked out **before** the PR SHA fetch -- this establishes
  the trusted `.airut/` config on the host.
- The PR SHA fetch runs on the **host** (not inside the container) -- this
  avoids needing GitHub credentials inside the sandbox. The host runner has
  implicit repo access via `actions/checkout`'s GITHUB_TOKEN.

### Inline Command Pattern

The sandbox runs
`bash -c 'git merge --no-edit "$1" && eval "$2"' _ <sha> <command>` (or
`git checkout` when merge is false). This avoids writing an entrypoint script to
the workspace, which would break worktree-clean checks and cannot be safely
cleaned up post-sandbox (tainted workspace).

The SHA and command are passed as positional arguments (`$1`, `$2`), safely
quoted. `eval` is used for command execution to support multi-line commands
naturally. `eval` is safe here because the command value comes from the workflow
YAML (trusted), and the sandbox provides containment regardless.

### Base Branch Checkout

The action uses `github.event.pull_request.base.ref` (not
`github.event.repository.default_branch`) for the checkout ref. This supports
repositories with multiple protected branches (e.g., `main` and `release/*`).
For `push` events (no PR context), the fallback `github.ref_name` resolves to
the branch being pushed to.

**`workflow_dispatch` note:** When triggered via `workflow_dispatch`, there is
no PR context, so the action checks out `github.ref_name` — the dispatched
branch. This means `.airut/` configuration (Dockerfile, network allowlist,
sandbox.yaml) comes from the dispatched branch, not the default branch. This is
safe because a human triggers the dispatch after reviewing the PR, but the
dispatcher should verify the branch's `.airut/` configuration before triggering.
See [doc/ci-sandbox.md](../doc/ci-sandbox.md#trust-model) for details.

### Merge Mode

When `merge` is `true` (default), the container starts on the base branch and
merges the PR commit. This matches GitHub Actions' default `pull_request`
behavior where the checkout ref is a temporary merge commit. When `false`, the
container checks out the PR commit directly.

## Runner Requirements

- **Container runtime**: podman (default) or docker. GitHub-hosted
  `ubuntu-latest` runners include podman.
- **Disk space**: Space for the container image build.
- **Network**: The host needs internet access for checkout, `uv tool install`,
  and image builds. The container's network is controlled by the sandbox.
