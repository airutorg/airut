# Maintaining sandbox-action

The `airutorg/sandbox-action` repository contains a reusable GitHub Action that
wraps `airut-sandbox` for CI. See `spec/sandbox-action.md` for design decisions
and `doc/ci-sandbox.md` for the user-facing setup guide.

## Repository

`https://github.com/airutorg/sandbox-action`

## Setup (First Time Per Session)

Clone the sandbox-action repo to persistent storage:

```bash
git clone https://github.com/airutorg/sandbox-action /storage/sandbox-action
```

If already cloned from a previous session:

```bash
cd /storage/sandbox-action && git fetch origin && git checkout main && git pull
```

## Making Changes

1. Create a feature branch:

   ```bash
   cd /storage/sandbox-action
   git checkout -b feature/description origin/main
   ```

2. Edit files (`action.yml`, `VERSION`, `README.md`, etc.).

3. Commit and push:

   ```bash
   git add -A
   git commit -m "Description of change"
   git push -u origin HEAD
   ```

4. Create a PR:

   ```bash
   gh pr create --fill
   ```

5. Test the change by temporarily pointing the airut repo's CI workflow to the
   PR branch:

   ```yaml
   # In airut's .github/workflows/ci.yml (temporary, for testing)
   - uses: airutorg/sandbox-action@feature/description
   ```

6. After the PR is merged, revert the airut CI workflow back to `@main`.

## Branching Model

The repository uses a release branch to separate development from tagged
releases:

| Ref              | VERSION file | airut-sandbox source | Purpose                          |
| ---------------- | ------------ | -------------------- | -------------------------------- |
| `main`           | `main`       | `git+.../airut@main` | Development, airut repo's own CI |
| `releases/v0`    | `0.15.0`     | PyPI `airut==0.15.0` | Current release branch           |
| `@v0.15.0` (tag) | `0.15.0`     | PyPI `airut==0.15.0` | Pinned version                   |
| `@v0` (tag)      | `0.15.0`     | PyPI `airut==0.15.0` | Floating major (latest 0.x)      |

**`main` is never modified during releases.** The `VERSION` file on `main`
always contains `main`. Only the `releases/v0` branch has a PyPI version in
`VERSION`.

## Releasing (After Airut Release)

When a new airut version is published to PyPI (e.g., `v0.16.0`):

1. Update the release branch:

   ```bash
   cd /storage/sandbox-action
   git fetch origin
   git checkout releases/v0
   git reset --hard origin/main
   echo "0.16.0" > VERSION
   git add VERSION
   git commit -m "Release v0.16.0"
   git push --force-with-lease origin releases/v0
   ```

   This resets `releases/v0` to the latest `main` and only changes `VERSION`.

2. Create draft releases via `gh release create`:

   ```bash
   # Exact version tag
   gh release create v0.16.0 --draft --title "v0.16.0" \
     --target releases/v0 --notes "Release notes here..."

   # Floating major tag (delete old release first if it exists)
   gh release delete v0 --yes 2>/dev/null || true
   gh release create v0 --draft --title "v0 (latest)" \
     --target releases/v0 --notes "Latest stable v0.x release..."
   ```

   Draft releases create tags when published. The tag ruleset blocks direct
   `git push` of tags — use `gh release create` instead.

3. Publish both releases from the GitHub UI. The user must approve and publish
   each draft.

4. Verify consumers using `@v0` pick up the new version on their next CI run.

## Initialization (First Time Only)

To bootstrap the empty `airutorg/sandbox-action` repository:

1. Clone it:

   ```bash
   git clone https://github.com/airutorg/sandbox-action /storage/sandbox-action
   cd /storage/sandbox-action
   ```

2. Create the action files: `action.yml`, `VERSION`, `README.md`, `LICENSE`.

3. Set `VERSION` to `main` (the main branch always installs from GitHub HEAD).

4. Commit and push:

   ```bash
   git add -A
   git commit -m "Initial sandbox action"
   git push origin main
   ```

5. Test by pointing the airut repo's CI workflow to `sandbox-action@main`.

6. After validation, proceed with the first versioned release (see Releasing
   above).

## Files Overview

| File         | Purpose                                      |
| ------------ | -------------------------------------------- |
| `action.yml` | Composite action definition (steps, inputs)  |
| `VERSION`    | Airut version to install (`main` or `0.x.y`) |
| `README.md`  | Consumer-facing documentation                |
| `LICENSE`    | License file                                 |
