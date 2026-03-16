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

The repository uses `vN` branches as protected release branches. Consumers using
`@v0` resolve to the `v0` branch directly (no floating tag). There are two
independent development tracks:

**(a) Action implementation changes** -- developed on `main`, cherry-picked to
`vN` as needed via reviewed PRs.

**(b) Airut version bumps** -- happen directly on `vN` via PRs that update the
`VERSION` file.

| Ref             | VERSION file | airut-sandbox source | Purpose                             |
| --------------- | ------------ | -------------------- | ----------------------------------- |
| `main`          | `main`       | `git+.../airut@main` | Development, airut repo's own CI    |
| `v0` (branch)   | `0.16.1`     | PyPI `airut==0.16.1` | Stable release; `@v0` resolves here |
| `v0.16.1` (tag) | `0.16.1`     | PyPI `airut==0.16.1` | Pinned version                      |

**`main` is never modified during releases.** The `VERSION` file on `main`
always contains `main`. Only `vN` branches have PyPI versions in `VERSION`.

**`vN` branches are protected** and only advance through merged PRs. They are
never force-pushed or reset to `main`.

**Why branches, not floating tags?** GitHub Actions resolves `@v0` to both tags
and branches (tags take priority). Using a branch means consumers automatically
get updates when PRs merge -- no tag deletion/recreation needed. This avoids
race conditions and simplifies the release process.

## Cherry-Picking Action Changes to a Release Branch

When an action implementation change on `main` needs to ship to consumers:

1. Identify the commit(s) to cherry-pick from `main`.

2. Create a branch off the release branch and cherry-pick:

   ```bash
   cd /storage/sandbox-action
   git fetch origin
   git checkout -b cherry-pick/description origin/v0
   git cherry-pick <commit-sha>
   ```

   Resolve any conflicts (the release branch may diverge from `main` in
   `VERSION` and potentially other files).

3. Push and create a PR **targeting `v0`**:

   ```bash
   git push -u origin HEAD
   gh pr create --base v0 --fill
   ```

4. After review and merge, consumers using `@v0` pick up the change on their
   next CI run. If the change warrants a pinned release, tag it (see Releasing).

## Releasing (After Airut Release)

When a new airut version is published to PyPI (e.g., `v0.17.0`):

1. Create a branch off the release branch and update `VERSION`:

   ```bash
   cd /storage/sandbox-action
   git fetch origin
   git checkout -b bump/v0.17.0 origin/v0
   echo "0.17.0" > VERSION
   git add VERSION
   git commit -m "Bump airut to v0.17.0"
   git push -u origin HEAD
   ```

2. Create a PR **targeting `v0`**:

   ```bash
   gh pr create --base v0 --title "Bump airut to v0.17.0" \
     --body "Updates VERSION to 0.17.0 for the new airut release."
   ```

3. After the PR is merged, consumers using `@v0` immediately get the new
   version. Create a pinned release tag:

   ```bash
   gh release create v0.17.0 --draft --title "v0.17.0" \
     --target v0 --notes "Bump airut to v0.17.0."
   ```

4. Publish the draft release from the GitHub UI.

## Files Overview

| File         | Purpose                                      |
| ------------ | -------------------------------------------- |
| `action.yml` | Composite action definition (steps, inputs)  |
| `VERSION`    | Airut version to install (`main` or `0.x.y`) |
| `README.md`  | Consumer-facing documentation                |
| `LICENSE`    | License file                                 |
