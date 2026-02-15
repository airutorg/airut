# Release Workflow

Prepare and publish a new version of Airut. This is a multi-step process
involving release notes review, version bump, and GitHub release creation.

## Prerequisites

- All changes for the release are merged to `main`
- You have the previous version tag (e.g., `v0.4.0`) to diff against

## Steps

### 1. Draft Release Notes

Review previous release notes for style:

```bash
gh release view <previous-tag>  # e.g., gh release view v0.4.0
```

Investigate changes since the last release:

```bash
git log <previous-tag>..HEAD --oneline
```

For each PR, review the details:

```bash
gh pr view <number> --json title,body
```

**Style guide** (derived from previous releases):

- **Highlights** section for significant features. Each entry uses bold feature
  name with em-dash intro, a concise description of the change and why it
  matters, and a PR reference in parentheses.
- **Other Changes** section for smaller improvements as a bullet list.
- Keep descriptions user-facing: focus on what changed and why, not
  implementation details.

Send the draft to the user for review over email. Iterate until approved.

### 2. Bump Version

Once release notes are agreed, bump the version in `pyproject.toml`:

```bash
# Update version string
# Edit pyproject.toml: version = "X.Y.Z"

# Update lockfile
uv lock

# Run CI, commit, push, create PR
uv run scripts/ci.py --fix
git add pyproject.toml uv.lock
git commit -m "Bump version to X.Y.Z"
git push -u origin HEAD && gh pr create --fill
uv run scripts/pr.py ci --wait -v
```

Wait for the user to approve and merge the PR before proceeding.

### 3. Create Draft Release

After the version bump PR is merged:

```bash
git checkout main && git pull
```

Create a draft release targeting `main` with the agreed release notes:

```bash
gh release create vX.Y.Z --draft --title "vX.Y.Z" --notes "<release-notes>" --target main
```

Verify the release was created correctly:

```bash
gh release view vX.Y.Z
```

Send the release URL to the user. They will review and publish it.

## How the Release is Consumed

Airut is installed via `uv tool install` and updated manually:

```bash
uv tool upgrade airut
systemctl --user restart airut
```

The update channel depends on how the tool was installed:

- **Dev**:
  `uv tool install airut --from git+https://github.com/airutorg/airut.git` —
  tracks main branch.
- **Release** (future): `uv tool install airut` — installs from PyPI (tagged
  releases only).

After the release is published, users can pull the new version with
`uv tool upgrade airut`.
