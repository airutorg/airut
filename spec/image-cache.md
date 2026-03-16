# Image Caching for CI

Caches the sandbox container images across GitHub Actions runs using
`actions/cache`, eliminating redundant image builds on ephemeral runners.

For the image build architecture, see [image.md](image.md). For the sandbox
action interface, see [sandbox-action.md](sandbox-action.md). For the CI
security model, see [doc/ci-sandbox.md](../doc/ci-sandbox.md).

## Problem

The sandbox builds three container images on every `airut-sandbox run`
invocation, managed by the unified `ImageCache` via content-addressed
`ImageBuildSpec` objects:

1. **Repo image** (`airut-cli-repo:<hash>`): Ubuntu 24.04, system packages, uv,
   Python 3.13, Claude Code CLI. Cold build: ~40--50 s.
2. **Proxy image** (`airut-cli-proxy:<hash>`): `python:3.13-slim`, mitmproxy,
   DNS responder, proxy filter. Cold build: ~20--35 s.
3. **Overlay image** (`airut-cli-overlay:<hash>`): Thin layer adding the
   entrypoint on top of the repo image. Cold build: ~2--3 s.

On the Airut gateway server, persistent age detection via `podman image inspect`
and the local Podman store keep images warm across tasks. On GitHub Actions,
every CI run gets a fresh ephemeral runner with an empty image store, so **all
images are rebuilt from scratch every time** -- adding 60--85 s of pure build
overhead before the actual CI command runs.

## Design

### Overview

The design has two parts:

1. **New `airut-sandbox image` subcommands** (`hash`, `save`, `load`) that
   encapsulate all image tarball operations in the CLI, keeping the action
   simple.
2. **`actions/cache` integration** in the sandbox action's composite steps,
   using the CLI subcommands for save/load and the hash output for cache keys.

On cache hit, `airut-sandbox image load` restores images from tarballs. On cache
miss, `airut-sandbox image save` builds the images and exports them for future
runs. In both cases, the subsequent `airut-sandbox run` finds the images already
present in the local Podman store. All cache operations run **before** the
sandbox executes untrusted code.

Two independent cache entries are maintained:

| Image       | Cache key                                              | Invalidates when                           |
| ----------- | ------------------------------------------------------ | ------------------------------------------ |
| Repo image  | `airut-repo-<dockerfile-hash>-cc<claude-code-version>` | Dockerfile changes or Claude Code releases |
| Proxy image | `airut-proxy-<proxy-files-hash>`                       | Airut updates that change proxy code       |

Independent entries ensure that a Claude Code release only rebuilds the repo
image (not the proxy), and an airut update that only touches proxy code only
rebuilds the proxy image (not the repo image).

### CLI Subcommands

The `airut-sandbox` CLI gains an `image` subcommand group with three commands.
These encapsulate all image tarball operations so the sandbox action (and other
CI systems) never interact with `podman` directly for caching.

#### `airut-sandbox image hash`

Compute content hashes for all image specs without building. The hashes match
those used by `ImageCache.tag_for()` -- they are the SHA-256 of each
`ImageBuildSpec`'s Dockerfile and context files.

```
airut-sandbox image hash [--dockerfile PATH] [--context-dir PATH]
```

Output (one `key=value` pair per line):

```
repo=abc123def456...
proxy=789xyz012abc...
```

The repo hash requires the Dockerfile and context files (defaults to
`.airut/container/Dockerfile` and `.airut/container/`). The proxy hash is
computed from the bundled `airut._bundled.proxy` package files.

The overlay hash is not output because the overlay image is not cached (it is
cheap to rebuild and depends on the repo image).

**Why `hash` is a separate command**: The action needs content hashes to
construct `actions/cache` keys **before** attempting cache restore. Computing
hashes in shell would be fragile and duplicate the `_content_hash()` logic from
`ImageCache`. The CLI has direct access to `ImageBuildSpec` and
`_content_hash()`. While `save` also computes hashes internally, the action
cannot call `save` first -- it needs the hashes to decide whether to restore
from cache or build from scratch.

#### `airut-sandbox image save`

Build (if needed) and export repo and proxy images to a directory.

```
airut-sandbox image save DIR [--dockerfile PATH] [--context-dir PATH]
```

For each image (repo, proxy): if the image does not exist in the local Podman
store, build it first via `ImageCache.ensure()`, then export it via
`podman save`. Creates `DIR/repo.tar` and `DIR/proxy.tar`.

The build-if-missing behavior is the key property that enables **pre-sandbox
caching**: on cache miss, `save` runs before the sandbox, builds the images,
exports them for upload, and the subsequent `airut-sandbox run` finds them
already in the store. No post-sandbox steps are needed.

The `--dockerfile` and `--context-dir` options use the same defaults as `run`.
They are needed to construct the repo `ImageBuildSpec` (which determines both
the build and the content-addressed tag).

#### `airut-sandbox image load`

Import images from a directory into the local Podman store.

```
airut-sandbox image load DIR
```

Loads `DIR/repo.tar` and `DIR/proxy.tar` via `podman load`. Missing tarballs are
silently skipped. On load failure (corrupted tarball), the error is logged but
execution continues -- `airut-sandbox run` will rebuild the image from scratch.

**Tag preservation**: `podman save` produces a docker-archive tarball that
embeds the image tag in its `manifest.json` → `RepoTags` field. When
`podman load` imports the tarball, the image appears in the local store with the
original content-addressed tag (e.g., `airut-cli-repo:<hash>`). No re-tagging is
needed.

**Why save/load instead of just podman**: The CLI knows the exact image tags
(computed from `ImageBuildSpec`), tarball naming convention, and which images to
save/load. The action doesn't need to discover tags via `podman images | grep`
or know about the `{prefix}-{kind}:{hash}` naming scheme. If the tagging scheme
changes, only the CLI needs updating.

### How Loaded Images Interact with `ImageCache.ensure()`

When `airut-sandbox image load` restores cached images, they appear in the local
Podman store with their original content-addressed tags (see "Tag preservation"
above). When `airut-sandbox run` subsequently calls `ImageCache.ensure()`:

1. `get_image_created(tag)` queries `podman image inspect` and returns the
   image's **original build timestamp** -- not the time the image was loaded.
   The `Created` field is part of the OCI image config JSON, which `podman load`
   imports verbatim without rewriting any metadata.
2. If the image is younger than `max_age_hours`, it is reused.
3. If the image is older than `max_age_hours`, it is rebuilt with `--no-cache`.

**Staleness interaction with CI caching**: Cached images may be older than the
gateway's default 24-hour `max_age_hours`. The sandbox action passes the
`cache-max-age` input (default: 168 hours / one week) as `--max-image-age` to
`airut-sandbox run`. This provides a time-based safety net for base image
freshness, while the content-addressed cache key handles correctness (Dockerfile
changes, Claude Code version). The `cache-version` input provides manual
invalidation for edge cases.

### Cache Key Design

#### Repo Image Key

```
airut-repo-<dockerfile-hash>-cc<claude-code-version>[-v<cache-version>]
```

Components:

- **`<dockerfile-hash>`**: First 16 hex chars of the hash from
  `airut-sandbox image hash` (repo component). Matches the content hash used by
  `ImageCache` internally.
- **`cc<claude-code-version>`**: Current Claude Code release version, fetched
  from the distribution endpoint. This is the most volatile component in the
  Dockerfile -- the `curl ... | bash` installer fetches whatever version is
  current.
- **`v<cache-version>`**: Optional, appended only when the `cache-version`
  action input is non-empty.

**Claude Code version source**: The action fetches
`https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/latest`
which returns a bare version string (e.g., `2.1.76`). This is the same endpoint
the installer script uses internally.

**Fallback**: If the version endpoint is unreachable, the version component is
set to `unknown`, producing a unique key that does not match any cached entry.
This is fail-safe: the image is rebuilt from scratch rather than using a
potentially stale cache.

**Other tools in the Dockerfile** (uv, system packages, gh CLI) change
infrequently. They are not included in the cache key. When an update to these
tools is needed, the `cache-version` action input provides a manual
cache-busting mechanism.

#### Proxy Image Key

```
airut-proxy-<proxy-files-hash>[-v<cache-version>]
```

Components:

- **`<proxy-files-hash>`**: First 16 hex chars of the hash from
  `airut-sandbox image hash` (proxy component).

The proxy image depends entirely on files bundled with the airut package, not on
anything in the consuming repository. The hash changes only when an airut update
modifies proxy code or dependencies.

### Consumer Interface

New action inputs:

| Input           | Required | Default | Description                                                                                                                             |
| --------------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `cache`         | No       | `true`  | Enable image caching. Set to `false` to force fresh builds.                                                                             |
| `cache-version` | No       | `""`    | Manual cache-buster appended to cache keys. For cases where automatic invalidation is insufficient (e.g., dynamically-installed tools). |
| `cache-max-age` | No       | `168`   | Maximum image age in hours before forced rebuild. Default 168 (one week). Set to `0` to always rebuild.                                 |

The `cache-version` input is appended to both the repo and proxy cache keys.
Changing it invalidates all cached images.

The `cache-max-age` input is passed as `--max-image-age` to `airut-sandbox run`.
On a cache hit, if the loaded image is older than this threshold,
`ImageCache.ensure()` will rebuild it with `--no-cache`. This provides a
time-based safety net for picking up base image security patches, independent of
the content-addressed cache key. The default of 168 hours (one week) aligns with
the typical Claude Code release cadence.

### Action Step Ordering

All cache steps run **before** the sandbox. The sandbox action remains the
**terminal step** of the job (see
[doc/ci-sandbox.md](../doc/ci-sandbox.md#4-terminal-step)), with no post-sandbox
steps. This is possible because `airut-sandbox image save` builds images that
don't exist yet (see above).

```
1.  Install uv and Python               (existing)
2.  Install airut-sandbox                (existing)
3.  Checkout base branch                 (existing)
4.  Fetch PR objects                     (existing)
5.  [NEW] Compute image hashes           (airut-sandbox image hash)
6.  [NEW] Fetch Claude Code version      (curl version endpoint)
7.  [NEW] Restore repo image cache       (actions/cache/restore)
8.  [NEW] Restore proxy image cache      (actions/cache/restore)
9.  [NEW] Load cached images             (airut-sandbox image load, if hit)
10. [NEW] Build and save images          (airut-sandbox image save, if miss)
11. [NEW] Upload repo image cache        (actions/cache/save, if miss)
12. [NEW] Upload proxy image cache       (actions/cache/save, if miss)
13. Run sandboxed command                (existing: airut-sandbox run)
```

On cache hit (steps 7--8 match): step 9 loads tarballs into the Podman store,
steps 10--12 are skipped, and step 13 finds the images already present.

On cache miss: step 9 is skipped (no tarballs to load), step 10 builds the
images and exports tarballs, steps 11--12 upload the tarballs to GitHub cache,
and step 13 finds the images already present.

On partial miss (e.g., repo miss + proxy hit): step 9 loads the proxy tarball,
step 10 builds the missing repo image and exports both tarballs (the proxy
export is fast since the image already exists), and only step 11 uploads (the
repo cache that missed).

### Cache Sizes and Limits

GitHub Actions provides 10 GB of cache storage per repository, shared across all
workflows. Estimated tarball sizes:

| Image       | Estimated tarball size (compressed) |
| ----------- | ----------------------------------- |
| Repo image  | 800 MB -- 1.5 GB                    |
| Proxy image | 300 -- 500 MB                       |

With two cache entries, one unique key combination consumes ~1.1--2.0 GB. GitHub
evicts least-recently-used cache entries when the limit is reached.

For repos with stable Dockerfiles, the repo image key changes only when Claude
Code releases a new version (~weekly). The proxy key changes only when airut
releases update proxy code (~monthly or less). This means at most 2--3 active
cache entries at any time, well within the 10 GB limit.

### CA Certificate

The mitmproxy CA certificate (`~/.airut-mitmproxy/`) is **not cached**. It is
generated from the proxy image in ~3--5 s and contains the CA private key. The
small time saving does not justify persisting a private key in GitHub's cache
storage.

## Performance

### Estimated Savings

| Scenario                            | Pre-sandbox overhead                       | Net CI time change |
| ----------------------------------- | ------------------------------------------ | ------------------ |
| No caching (baseline)               | ~73 s build                                | --                 |
| Cold (first run, cache miss + save) | ~73 s build + ~20 s save/upload            | +20 s              |
| Warm: both images cached            | ~16 s load                                 | **-57 s**          |
| Partial: repo miss, proxy hit       | ~6 s proxy load + ~45 s repo build + ~10 s | **-12 s**          |

The first CI run after a cache invalidation is ~20 s slower (image save + upload
overhead). All subsequent runs save ~57 s. Since all cache operations are
pre-sandbox, the sandbox step sees images already present in the store and skips
building entirely.

### Invalidation Frequency

| Event                            | Repo cache  | Proxy cache |
| -------------------------------- | ----------- | ----------- |
| Claude Code release (~weekly)    | Invalidated | Unaffected  |
| Dockerfile change                | Invalidated | Unaffected  |
| Airut release (proxy changes)    | Unaffected  | Invalidated |
| Airut release (no proxy changes) | Unaffected  | Unaffected  |
| Manual `cache-version` bump      | Invalidated | Invalidated |

## Security

### Threat Model

Image caching introduces a new attack surface: **cache poisoning**. If an
attacker can write a malicious image tarball to the cache, all subsequent CI
runs would load and execute it. The attacker's image could:

- Bypass network sandbox restrictions (modified proxy filter)
- Exfiltrate masked secrets (modified proxy replacement logic)
- Execute arbitrary code during image setup (modified entrypoint or system
  binaries)
- Install persistent backdoors in the build environment

### GitHub Actions Cache Isolation

GitHub Actions caches are scoped by **repository** and **branch hierarchy**:

- **Fork PRs**: Cannot access or write to the upstream repository's cache.
- **Feature branch PRs**: Can **read** caches from the base branch (e.g.,
  `main`) but can only **write** caches scoped to their own branch ref.
- **Base branch pushes**: Can read and write caches scoped to the base branch.

This means a malicious PR cannot poison the cache that other PRs read from. The
base branch cache is only writable by pushes to the base branch itself, which
requires passing branch protection (PR review + approval).

**Cache key integrity**: The cache key includes content hashes (Dockerfile,
proxy files) and the Claude Code version. A PR that modifies `.airut/container/`
files cannot change the base branch cache -- the action reads `.airut/` from the
base branch checkout, not the PR branch.

### No Secrets in Images

Neither the repo image nor the proxy image contains secrets:

- **Repo image**: Contains only the runtime environment (OS, tools, Claude Code
  CLI). No API keys, tokens, or credentials.
- **Proxy image**: Contains mitmproxy, DNS responder, and Python scripts. The
  network allowlist, masked secret replacement map, and CA certificate are all
  **mounted at runtime** via bind mounts -- they are never baked into the image.

Caching the image tarballs in GitHub's cache storage does not expose secrets.

### Pre-Sandbox Cache Operations

All cache operations (hash, restore, load, build, save, upload) run **before**
the sandbox executes untrusted code. The sandbox step is the last step in the
composite action. This means:

- The workspace is untainted when `airut-sandbox image save` runs -- no PR code
  has executed yet.
- No commands run after the sandbox, so there is no post-sandbox tampering
  vector.
- `airut-sandbox` is a system-installed binary (installed via `uv tool install`
  before checkout), so the workspace cannot shadow it.

### Terminal Step Preservation

The cache steps are **inside the composite action**, not separate workflow
steps. The action remains a single `uses:` step in the consumer's workflow. The
"terminal step" requirement (no steps after the sandbox action) is preserved.
Consumers do not need to add any post-sandbox steps.

### Base Image Staleness

Both images use mutable base image tags (`ubuntu:24.04`, `python:3.13-slim`).
With caching, the base image is pinned to whatever version was current when the
cache was created. Security patches to the base OS or Python runtime are only
picked up when the cache invalidates.

This is acceptable because:

- The repo image cache invalidates on Claude Code releases (~weekly), providing
  a natural refresh cadence.
- The proxy image cache invalidates on airut releases that update proxy code,
  which are also the releases most likely to update proxy dependencies
  (including security patches to mitmproxy and cryptography).
- The `cache-version` input provides a manual escape hatch for urgent security
  patches.
- Both containers run with minimal privileges (`--cap-drop=ALL`) and are
  ephemeral, limiting the impact window of unpatched base images.

### Residual Risks

| Risk                                         | Severity | Mitigation                                                              |
| -------------------------------------------- | -------- | ----------------------------------------------------------------------- |
| GitHub cache storage compromise              | Low      | Images contain no secrets; cache keys are content-addressed             |
| Stale base image with security vulnerability | Low      | Weekly invalidation (Claude Code releases); manual `cache-version` bump |
| Cache eviction causes unexpected rebuild     | None     | Fail-safe: cache miss triggers normal build                             |
| Tarball corruption in cache                  | Low      | `podman load` fails gracefully; `run` rebuilds from scratch             |
| Version endpoint returns wrong version       | Low      | Worst case: stale cache hit (old Claude Code) or unnecessary rebuild    |

## Implementation Notes

### CLI Subcommand Implementation

The `image` subcommand group is added to `airut/sandbox_cli.py` using `argparse`
sub-sub-parsers. Each command constructs `ImageBuildSpec` objects using the same
logic as the `run` command:

- **Repo spec**: Read from `--dockerfile` / `--context-dir` (same defaults as
  `run`)
- **Proxy spec**: Read from bundled `airut._bundled.proxy` package directory
- **Overlay spec**: Not used by `hash` or `save`/`load` (too cheap to cache)

The `hash` and `save` commands share a helper that constructs both specs. The
`save` command calls `ImageCache.ensure()` to build missing images, then
`podman save` to export them.

### Claude Code Version Fetch

```bash
CC_VERSION=$(curl -fsSL --max-time 5 \
  "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/latest" \
  2>/dev/null || echo "unknown")
```

The `--max-time 5` prevents the step from blocking on a slow or unreachable
endpoint. The `|| echo "unknown"` fallback ensures a cache miss (not a stale
hit) on failure.

### Using `actions/cache/restore` and `actions/cache/save`

The action uses the split restore/save pattern (not the combined
`actions/cache`) because:

1. **Save only on miss**: The combined action saves on every run, which wastes
   bandwidth when the cache was already populated.
2. **Conditional save**: Tarballs are only created on cache miss (by
   `airut-sandbox image save`). The combined action's post-job save hook would
   run unconditionally, even when the cache was already populated.

### Conditional Steps

All cache steps are conditioned on the `cache` input:

```yaml
- name: Compute image hashes
  if: inputs.cache == 'true'
  run: ...
```

Upload steps additionally check for cache miss:

```yaml
- name: Upload repo image cache
  if: inputs.cache == 'true' && steps.repo-cache.outputs.cache-hit != 'true'
  uses: actions/cache/save@v4
  ...
```

## Scope

This spec covers:

- New `airut-sandbox image` subcommands (`hash`, `save`, `load`) in the
  `airut-sandbox` CLI
- Cache integration in `airutorg/sandbox-action` (GitHub Actions)

The `airut-sandbox image` subcommands are CI-agnostic -- other CI systems
(GitLab CI, Buildkite) can use them with their own cache backends. Only the
`actions/cache` integration is GitHub-specific.

The Airut gateway server is unaffected. Its `ImageCache` with persistent
staleness detection via `podman image inspect` continues to work as described in
[image.md](image.md).
