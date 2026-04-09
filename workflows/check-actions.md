# Checking and Updating GitHub Actions Pinning

All third-party GitHub Actions are pinned to commit SHAs to prevent supply-chain
attacks via tag mutation. The `scripts/check_actions.py` script verifies that
pinned SHAs are current and can auto-update them.

This workflow covers both the **airut** and **sandbox-action** repositories.

## How It Works

The script scans `.github/workflows/*.yml` and `action.yml` for action
references. It resolves floating tags (e.g., `v4`) to their current commit SHAs
via the GitHub API and compares against what's pinned in the files.

- **SHA-pinned actions** (`@<sha> # v4.3.1`) are checked for freshness
- **Tag-pinned actions** (`@v4`) are reported as unpinned
- **Excluded actions** (`airutorg/sandbox-action`) are skipped — these are
  intentionally unpinned first-party references

## Prerequisites

The script needs GitHub API access to resolve tags. A `GITHUB_TOKEN` or
`GH_TOKEN` environment variable is used if available (increases rate limits from
60 to 5,000 requests/hour). The `gh` CLI typically sets `GH_TOKEN`
automatically.

The network allowlist (`.airut/network-allowlist.yaml`) includes GET-only
entries for all upstream action repos used by either repository.

## Checking Airut

```bash
# Report only — shows outdated and unpinned actions
uv run python scripts/check_actions.py

# Verbose — also shows up-to-date actions
uv run python scripts/check_actions.py --verbose
```

## Checking sandbox-action

The sandbox-action repo must be checked out locally. Use `/storage` so it
persists across sessions.

**First time:**

```bash
git clone https://github.com/airutorg/sandbox-action /storage/sandbox-action
```

**Subsequent sessions:**

```bash
cd /storage/sandbox-action && git fetch origin && git checkout main && git pull
```

**Run the check:**

```bash
uv run python scripts/check_actions.py --repo /storage/sandbox-action
```

## Updating Pinned SHAs

When the script reports outdated or unpinned actions, use `--fix` to update the
files in-place.

### Airut

```bash
uv run python scripts/check_actions.py --fix
```

Review the diff, then commit:

```bash
git diff
git add .github/workflows/
git commit -m "Update pinned action SHAs"
```

### sandbox-action

```bash
uv run python scripts/check_actions.py --fix --repo /storage/sandbox-action
```

Review and commit in the sandbox-action repo:

```bash
cd /storage/sandbox-action
git diff
git checkout -b update-action-pins origin/main
git add action.yml .github/workflows/
git commit -m "Update pinned action SHAs"
git push -u origin HEAD
gh pr create --fill
```

## What Gets Scanned

| Repository     | Files scanned                                                         |
| -------------- | --------------------------------------------------------------------- |
| airut          | `.github/workflows/ci.yml`, `publish.yml`, `screenshots.yml`          |
| sandbox-action | `action.yml`, `.github/workflows/test.yml`, `update-floating-tag.yml` |

## Exclusions

Actions in the `EXCLUDED_ACTIONS` set in `scripts/check_actions.py` are skipped.
Currently this includes `airutorg/sandbox-action`, which is intentionally pinned
to `@main` to test the latest version in CI.
