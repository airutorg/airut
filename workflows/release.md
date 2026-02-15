# Release Workflow

Prepare and publish a new version of Airut. This is a multi-step process
involving release notes review and GitHub release creation.

## Prerequisites

- All changes for the release are merged to `main`
- You have the previous version tag (e.g., `v0.4.0`) to diff against

## How Versioning Works

The package version is derived automatically from git tags — there is no static
version in `pyproject.toml`. The `scripts/hatch_build.py` metadata hook reads
`git describe --tags --match v*` at build time and converts it to a PEP 440
version string:

- Tag `v0.9.0` → version `0.9.0` (release)
- Tag `v0.9.0-3-gabc1234` → version `0.9.0.dev3+gabc1234` (dev)

This means: **creating a git tag IS the version bump.** No file edits needed.

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

### 2. Create Draft Release

Once release notes are agreed:

```bash
git checkout main && git pull
```

Create a draft release targeting `main` with the agreed release notes. The tag
name determines the package version (e.g., `v0.9.0` → version `0.9.0`):

```bash
gh release create vX.Y.Z --draft --title "vX.Y.Z" --notes "<release-notes>" --target main
```

Verify the release was created correctly:

```bash
gh release view vX.Y.Z
```

Send the release URL to the user. They will review and publish it.

### 3. PyPI Publishing (Automatic)

When the user publishes the GitHub release, the `publish.yml` workflow
automatically builds and uploads the package to PyPI via Trusted Publisher. No
manual intervention is needed.

Verify the package is available:

```bash
uv pip show airut --index-url https://pypi.org/simple/
```

## How the Release is Consumed

Airut is installed via `uv tool install` and updated manually:

```bash
uv tool upgrade airut
systemctl --user restart airut
```

The update channel depends on how the tool was installed:

- **Release**: `uv tool install airut` — installs from PyPI (tagged releases
  only).
- **Dev**:
  `uv tool install airut --from git+https://github.com/airutorg/airut.git` —
  tracks main branch.

After the release is published, the package is automatically uploaded to PyPI.
Users can pull the new version with `uv tool upgrade airut`.
