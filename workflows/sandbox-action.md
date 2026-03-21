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

3. Run CI checks locally:

   ```bash
   uv run scripts/ci.py --fix
   ```

4. Commit and push:

   ```bash
   git add -A
   git commit -m "Description of change"
   git push -u origin HEAD
   ```

5. Create a PR:

   ```bash
   gh pr create --fill
   ```

## Branching Model

Consumers reference the action via `@v0`, which resolves to a **floating tag**
that is automatically updated to point at the latest `vX.Y.Z` release tag. The
`releases/v0` branch holds the release-track source and `VERSION` file.

There are two independent development tracks:

**(a) Action implementation changes** -- developed on `main`, cherry-picked to
`releases/vN` as needed via reviewed PRs.

**(b) Airut version bumps** -- happen directly on `releases/vN` via PRs that
update the `VERSION` file.

| Ref                    | VERSION file | airut-sandbox source | Purpose                               |
| ---------------------- | ------------ | -------------------- | ------------------------------------- |
| `main`                 | `main`       | `git+.../airut@main` | Development, airut repo's own CI      |
| `releases/v0` (branch) | `X.Y.Z`      | PyPI `airut==X.Y.Z`  | Release branch; PRs for version bumps |
| `v0` (floating tag)    | `X.Y.Z`      | PyPI `airut==X.Y.Z`  | Consumer ref; auto-updated on release |
| `vX.Y.Z` (tag)         | `X.Y.Z`      | PyPI `airut==X.Y.Z`  | Pinned version                        |

_(e.g., `X.Y.Z` = `0.18.0`)_

**`main` is never modified during releases.** The `VERSION` file on `main`
always contains `main`. Only `releases/vN` branches have PyPI versions in
`VERSION`.

**`releases/vN` branches are protected** and only advance through merged PRs.
They are never force-pushed or reset to `main`.

### Floating Tag Workflow

The `update-floating-tag.yml` workflow runs on `release: published` events (and
supports `workflow_dispatch` as a fallback). It extracts the major version from
the release tag (e.g., `v0.18.0` -> `v0`) and force-pushes the floating tag to
point at the release tag.

The workflow uses a dedicated **`airut-release-bot`** GitHub App for tag push
permissions, since `GITHUB_TOKEN` cannot bypass repository tag rulesets. The App
ID is stored in repository variables (`vars.RELEASE_BOT_APP_ID`) and the private
key in secrets (`secrets.RELEASE_BOT_PRIVATE_KEY`).

## Cherry-Picking Action Changes to a Release Branch

When an action implementation change on `main` needs to ship to consumers:

1. Identify the commit(s) to cherry-pick from `main`.

2. Create a branch off the release branch and cherry-pick:

   ```bash
   cd /storage/sandbox-action
   git fetch origin
   git checkout -b cherry-pick/description origin/releases/v0
   git cherry-pick <commit-sha>
   ```

   Resolve any conflicts (the release branch may diverge from `main` in
   `VERSION` and potentially other files).

3. Push and create a PR **targeting `releases/v0`**:

   ```bash
   git push -u origin HEAD
   gh pr create --base releases/v0 --fill
   ```

4. After review and merge, create a pinned release tag to ship the change (see
   Releasing). The floating `v0` tag is updated automatically when the release
   is published.

## Releasing (After Airut Release)

When a new airut version is published to PyPI (e.g., `v0.18.0`):

1. Create a branch off the release branch and update `VERSION`:

   ```bash
   cd /storage/sandbox-action
   git fetch origin
   git checkout -b bump/v0.18.0 origin/releases/v0
   echo "0.18.0" > VERSION
   git add VERSION
   git commit -m "Bump airut to v0.18.0"
   git push -u origin HEAD
   ```

2. Create a PR **targeting `releases/v0`**:

   ```bash
   gh pr create --base releases/v0 --title "Bump airut to v0.18.0" \
     --body "Updates VERSION to 0.18.0 for the new airut release."
   ```

3. After the PR is merged, draft release notes and create a release. Publishing
   the release triggers the `update-floating-tag` workflow, which automatically
   updates the `v0` floating tag so consumers pick up the new version.

   **Writing release notes:** Analyze changes in the **airut** repo between the
   previous sandbox-action version and the new one to identify what matters for
   sandbox-action consumers. Not every airut change is relevant — focus on
   changes that affect the sandbox, container execution, network proxy, image
   building, or the `airut-sandbox` CLI interface.

   a. Find the previous sandbox-action release version:

   ```bash
   gh release list --repo airutorg/sandbox-action --limit 5
   ```

   b. Review airut changes between the two versions:

   ```bash
   # In the airut repo
   git log v<previous>..v<new> --oneline
   ```

   c. For each PR, review details to assess relevance:

   ```bash
   gh pr view <number> --json title,body
   ```

   d. Write release notes covering only changes relevant to sandbox-action
   users. **Relevant categories:** sandbox behavior, container/image changes,
   network allowlist or proxy changes, `airut-sandbox` CLI options, action
   inputs, security model changes, runner compatibility. **Irrelevant
   categories:** gateway/email/Slack channel changes, dashboard, server
   configuration, internal refactoring with no user-visible effect.

   e. Follow the airut release notes style (see `workflows/release.md`):
   **Highlights** section with bold feature names and em-dash intros for
   significant changes, **Other Changes** bullet list for smaller items,
   user-facing descriptions focused on what changed and why.

   f. Create the draft release:

   ```bash
   gh release create v0.18.0 --draft --title "v0.18.0" \
     --target releases/v0 --notes "<release-notes>"
   ```

4. Publish the draft release from the GitHub UI. The `update-floating-tag`
   workflow will automatically update the `v0` tag. Verify it ran successfully
   in the Actions tab.

## Files Overview

| File                                        | Purpose                                      |
| ------------------------------------------- | -------------------------------------------- |
| `action.yml`                                | Composite action definition (steps, inputs)  |
| `VERSION`                                   | Airut version to install (`main` or `0.x.y`) |
| `.github/workflows/update-floating-tag.yml` | Auto-updates `v0` tag on release publish     |
| `README.md`                                 | Consumer-facing documentation                |
| `LICENSE`                                   | License file                                 |
