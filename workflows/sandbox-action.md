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

## Releasing (After Airut Release)

When a new airut version is published to PyPI (e.g., `v0.16.0`):

1. Update the VERSION file:

   ```bash
   cd /storage/sandbox-action
   git checkout main && git pull
   echo "0.16.0" > VERSION
   ```

2. Update `action.yml` if the new airut version requires changes to the action
   (usually not needed).

3. Commit:

   ```bash
   git add VERSION
   git commit -m "Release v0.16.0"
   git push origin main
   ```

4. Create the version tag and move the major tag:

   ```bash
   git tag v0.16.0
   git tag -f v0
   git push origin v0.16.0
   git push -f origin v0
   ```

5. Verify consumers using `@v0` pick up the new version on their next CI run.

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
