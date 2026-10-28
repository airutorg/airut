# Container Image Management

Manages the two-layer container image build for Airut: a **repo-defined base
image** (sourced from the git mirror) and a **server-defined overlay** (with the
Airut entrypoint).

## Design Goals

1. **Repo controls its environment**: The target repository defines what tools
   and dependencies it needs (Python, Claude Code, ripgrep, etc.) via a
   Dockerfile. By default Airut reads from `.airut/container/Dockerfile`, but
   the directory is configurable per-repo via `container_path` in the server
   config (e.g., `.devcontainer` to reuse an existing Dockerfile). Changes take
   effect after merging to main — no server restart required.
2. **Server controls the entrypoint**: The sandbox library generates the
   container entrypoint in code (`airut/sandbox/_entrypoint.py`). Two variants
   exist -- agent (for `AgentTask`) and passthrough (for `CommandTask`). This is
   the interface contract between Airut and the container.
3. **Content-addressed caching with staleness**: Images are cached by full
   SHA-256 hex digest (64 hex chars) of their content inputs. A staleness check
   (24 hours) ensures periodic rebuilds to pick up upstream tool updates (new
   Claude Code versions, security patches) even when the Dockerfile itself
   hasn't changed.

## Architecture

### Two-Layer Image Build

```
Layer 1: Repo Image (from git mirror)
  Source: .airut/container/Dockerfile (read from mirror's main branch)
  Tag:    airut-repo:<sha256-of-dockerfile>
  Contains: Ubuntu, system deps, Python, uv, etc.

Layer 2: Server Overlay (generated in code)
  Source: airut/sandbox/_entrypoint.py (generated entrypoint script)
  Tag:    airut-overlay:<sha256-of-repo-tag-plus-entrypoint-content>
  Contains: FROM repo image + COPY entrypoint + ENTRYPOINT directive
  Note:   Agent and passthrough entrypoints have different content,
          so they produce different overlay image hashes/tags.
```

### File Locations

```
# In the target repository (read from git mirror at task start)
.airut/
  network-allowlist.yaml          # network sandbox allowlist config
  container/
    Dockerfile                    # repo-defined base image
    <other files, subdirectories> # additional build context
    flake.nix -> ../../flake.nix  # symlinks to files elsewhere in the repo

# On the Airut server (generated in code)
airut/sandbox/
  _entrypoint.py                  # generated entrypoint script
  _image_cache.py                 # unified image cache (ImageCache, ImageBuildSpec)

airut/_bundled/proxy/
  proxy.dockerfile                # proxy container image
  pyproject.toml                  # proxy dependency declarations
  uv.lock                         # pinned transitive proxy dependencies
  requirements.txt                # exported from uv.lock for pip install
  proxy_filter.py                 # mitmproxy allowlist/URL-prefix addon
  proxy-entrypoint.sh             # proxy container entrypoint
  dns_responder.py                # allowlist-enforcing DNS responder
  aws_signing.py                  # AWS SigV4/SigV4A request re-signing
```

Everything in `.airut/container/` is copied to the build context, allowing the
Dockerfile to use `COPY` instructions to include additional files (e.g.,
configuration files, scripts) in the image:

- **Subdirectories** are included recursively.
- **Symlinks** are replaced by their targets, which may be files or directories
  anywhere in the repository. This lets an image be built from files that live
  elsewhere, e.g. `flake.nix -> ../../flake.nix`, without making the whole
  repository the build context (which would rebuild the image on every commit).
  Targets are resolved within the repository, like the OS would: absolute
  targets, targets outside it, dangling links, paths through anything but a
  directory (a file, a missing entry, a submodule) and links that would include
  an enclosing directory (cycles) are errors, as are other entry types such as
  submodules.
- **The executable bit** of files is preserved.
- **`.git` is never included**, even when the context is the repository root.
- **Size is limited** to 10,000 files and directories (each path through a
  symlink counts) and 256 MiB, so directory symlinks that fan out cannot exhaust
  the server while the mirror is locked.

The gateway reads the context from the git mirror's default branch and the CLI
from disk (symlinks may point anywhere in the enclosing git repository, i.e. the
nearest ancestor with a `.git` entry, or the context directory itself if there
is none). Both use the same collection code (`airut/sandbox/build_context.py`),
so they produce the same build context and image hash. Because the hash covers
the targets' content, changing a linked file (e.g. `flake.lock`) rebuilds the
image.

## Build Flow

### Per-Task Build (at task start)

```
1. Collect .airut/container/ from git mirror (main branch), following
   subdirectories and symlinks
2. Separate the Dockerfile from the other context files
3. Compute repo_hash = sha256(Dockerfile + sorted context file paths, contents
   and executable bits)
4. Compute overlay_hash = sha256(overlay Dockerfile + entrypoint filename + entrypoint content)

5. Check repo image: airut-repo:<repo_hash>
   EXISTS and age < max_age_hours → reuse
   OTHERWISE → build from Dockerfile with context files, tag with repo_hash

6. Check overlay image: airut-overlay:<overlay_hash>
   EXISTS and repo image was reused → reuse
   OTHERWISE → build overlay (FROM repo image + entrypoint), tag

7. Run container from airut-overlay:<overlay_hash>
```

### Build Details

**Repo image build** (step 5):

- Collect the context via `GitMirrorCache.default_branch_tree()` (one commit of
  the default branch, read under the mirror's shared lock)
- Write all files to a temporary directory (build context), recreating
  subdirectories and executable bits
- Build with `podman build -t airut-repo:<hash> -f <tmpdir>/Dockerfile <tmpdir>`
- The Dockerfile can use `COPY` to include any files from the container
  directory

**Overlay image build** (step 6):

- The entrypoint script is generated in code by `airut/sandbox/_entrypoint.py`
- Generate a minimal Dockerfile in memory:
  ```dockerfile
  FROM airut-repo:<repo_hash>
  COPY airut-entrypoint.sh /entrypoint.sh
  RUN chmod +x /entrypoint.sh
  ENTRYPOINT ["/entrypoint.sh"]
  ```
- Build with the generated entrypoint copied into a temporary build context

### Staleness and Caching

All image management is handled by `ImageCache`
(`airut/sandbox/_image_cache.py`) — a unified cache that manages repo, overlay,
and proxy images through a single interface. Each image is described by an
`ImageBuildSpec` (frozen dataclass with `kind`, `dockerfile`, and optional
`context_files` and `executable_files`), and tagged as
`{resource_prefix}-{kind}:{sha256}`.

| Condition                                        | Action                                               |
| ------------------------------------------------ | ---------------------------------------------------- |
| Image does not exist (first build)               | Build without `--no-cache` (leverage layer caching)  |
| Image exists, age < `max_age_hours`              | Reuse (fast path)                                    |
| Image exists, age >= `max_age_hours`             | Rebuild with `--no-cache` (pick up upstream updates) |
| `max_age_hours=0`                                | Always rebuild with `--no-cache`                     |
| `force=True` passed to `ensure()`                | Rebuild with `--no-cache` regardless of age          |
| Dockerfile or context files changed (diff hash)  | New tag → fresh build (no `--no-cache`)              |
| Generated entrypoint changed                     | Rebuild overlay only (repo image reused)             |
| Different entrypoint variant (agent/passthrough) | Different overlay tag (repo image reused)            |

Image age is detected persistently via `podman image inspect` (querying the
image's `Created` timestamp), not tracked in memory. This means image age
survives service restarts and is shared across gateway and CLI instances.

**Force cascade**: When `ensure_image()` detects that the repo image was rebuilt
(by comparing its creation timestamp before and after `ensure()`), the overlay
image is force-rebuilt to incorporate the new base. This ensures upstream
updates always propagate through both layers.

### Concurrent Build Safety

`ImageCache` is protected by a `threading.Lock`. When multiple tasks need a
build simultaneously:

- First task acquires lock, builds
- Subsequent tasks wait, then find the image already exists and reuse it

Builds produce new tags (content-addressed), so they don't affect running
containers.

## Proxy Dependency Management

The proxy container's Python dependencies (`mitmproxy`, `cryptography`, and
their transitive closure) are managed via a standalone `pyproject.toml` and
`uv.lock` in `airut/_bundled/proxy/`.

**Files:**

- `pyproject.toml` — declares top-level proxy dependencies
- `uv.lock` — pinned transitive dependency graph (scanned by `uv-secure`)
- `requirements.txt` — exported from `uv.lock` for `pip install` in the
  Dockerfile

**Updating proxy dependencies:**

```bash
cd airut/_bundled/proxy
uv lock --upgrade                    # resolve latest versions
uv export --format requirements-txt --no-dev --frozen --no-emit-project --no-header > requirements.txt
```

Both `uv.lock` and `requirements.txt` must be committed together. CI runs
`uv-secure` against the proxy lockfile to detect known vulnerabilities, and a
drift check verifies `requirements.txt` matches `uv.lock`.

**Security overrides:** mitmproxy pins several transitive dependencies to ranges
that exclude their security fixes, so `uv lock --upgrade` alone cannot resolve
those advisories. `[tool.uv] override-dependencies` in the proxy
`pyproject.toml` raises those floors. Each entry carries a comment naming the
advisories it fixes and, where the override crosses a major version, the
compatibility evidence for keeping mitmproxy on it. Entries are removed once
mitmproxy's own pins admit the fixed release. The Dockerfile installs with
`pip install --no-deps`, so the overridden versions are what ship.

## Image Requirements

The repo image may be based on any distribution (Debian, Ubuntu, Alpine, Nix,
...). Airut relies only on:

- **bash** 4.4 or later, reachable as `/usr/bin/env bash`, and basic file
  utilities (`cat`, `mkdir`, `mv`, `rm`) -- the entrypoint is a bash script.
- **`/bin/sh` and `chmod`** -- the overlay build runs `chmod` on the entrypoint.
- **A writable `/tmp`** (or absolute `$TMPDIR`) if the image provides an
  environment hook.
- **For agent tasks:** the dynamic loader of the bind-mounted Claude Code binary
  at its standard path. On glibc hosts Airut uses the glibc build, which needs
  `/lib64/ld-linux-x86-64.so.2` (x86_64) or `/lib/ld-linux-aarch64.so.1`
  (arm64); on musl hosts it uses the musl build. Glibc-based distributions
  (Debian, Ubuntu, Fedora) have the loader; Nix images need a symlink at the
  standard path; musl-based images such as Alpine need glibc installed when the
  host uses glibc. The agent entrypoint points this out if the binary cannot be
  executed, including when the loader path is a dangling symlink. `git` is also
  expected (and `gh` for GitHub repos), see
  [doc/repo-onboarding.md](../doc/repo-onboarding.md).
- **For agent tasks, `/bin/bash`:** Claude Code's shell tool finds bash on
  `PATH`, but other parts of Claude Code run `/bin/bash` directly. Images that
  keep bash elsewhere (Nix) should link it there.

Everything else the repo needs, including how its tools are put on `PATH`, is up
to the image. Tools set up by an activation step rather than installed
system-wide (a Nix devShell, conda, mise) can use the environment hook below.

[doc/nix-images.md](../doc/nix-images.md) gives a recipe for Nix-based images.

## Entrypoint Contract

The entrypoint script (generated by `airut/sandbox/_entrypoint.py`) has two
variants, selected via `ensure_image(passthrough_entrypoint=...)`. Both run the
same setup before starting the command:

1. Set `IS_SANDBOX=1`
2. Trust the mitmproxy CA certificate (for network sandbox), via
   `update-ca-certificates` or, when the image lacks it, by appending the CA to
   the system bundle (see
   [network-sandbox.md](network-sandbox.md#ca-certificate-trust))
3. Load the image's environment hook, if present (see below)
4. Re-apply `IS_SANDBOX=1`, the proxy CA environment variables when the network
   sandbox is active, and (agent entrypoint) the forced Claude environment (see
   [sandbox.md](sandbox.md)), so the hook cannot override them

CA trust setup is silent unless `AIRUT_VERBOSE=1` is set in the container
environment, in which case its output goes to stderr. The environment hook's
output and warnings (e.g. a failing hook) always go to stderr. Setup never
touches the command's stdin or stdout.

### Environment Hook

If the image contains `/etc/airut/env.sh`, both entrypoints load it before
running the command, so its environment applies to Claude Code, every command
Claude runs, and `CommandTask` commands alike. It is the place for activation
steps, e.g. a Nix devShell captured at image build time with
`nix print-dev-env > /etc/airut/env.sh`.

Contract:

- The hook is sourced by bash in a subshell, without arguments, after CA trust
  is set up. Its **exported** variables are imported into the entrypoint (as
  plain exports, never readonly); unexported variables, shell functions, unset
  variables and directory changes are not carried over.
- Its stdin is `/dev/null` and its stdout goes to stderr, including from its own
  traps, so it can neither consume the command's input (the agent prompt) nor
  corrupt its output.
- It cannot prevent the command from starting: a non-zero exit status, `exit`,
  `exec`, `set -e`/`set -u` failures and similar only produce a warning on
  stderr. Exports made before an early exit still apply, unless the hook used
  `exec` or replaced the `EXIT` trap. The rest of setup does not depend on the
  hook's `PATH`.
- The hook's own `EXIT` traps do not run when it returns normally, so services
  it starts (and would stop on exit, as in an interactive devShell) keep running
  for the command. Like everything in the container, they end with it.
- It runs on every container start, so it should be fast. It can reach the
  network through the proxy but should not need to: building the environment
  belongs in the image build.
- `IS_SANDBOX`, the proxy CA variables and the forced Claude environment are
  re-applied after it.

The hook comes from the repo image, which is built from the default branch and
already fully controls the container environment, so it adds no new trust
boundary.

### Agent Entrypoint (default)

Used by `AgentTask`. After setup, runs `exec /opt/claude/claude "$@"`
(bind-mounted from host cache). `IS_SANDBOX=1` makes Claude Code run in
permissive mode. If the binary cannot be executed, the entrypoint adds to bash's
error message, pointing out a missing dynamic loader (see
[Image Requirements](#image-requirements)) when the binary exists but its loader
does not, and exits with the exec status.

The Claude Code binary is not installed inside the container image. Instead,
`AgentTask` bind-mounts the host-cached binary at `/opt/claude/claude`
(read-only). The version is controlled by the `claude_version` config field.

`ClaudeBinaryCache` downloads the binary from `downloads.claude.ai` and caches
it per version. Because the binary is several hundred megabytes, transfers fail
mid-body often enough to matter: each attempt verifies the transferred byte
count against the manifest `size` and the SHA-256 digest against the manifest
`checksum`, and the whole download is retried (bypassing intermediary caches) on
transport error, truncation, or checksum mismatch. The byte count is checked
because `HTTPResponse.read()` reports a dropped connection as a normal EOF, so a
truncated download is otherwise indistinguishable from a complete one. Only a
fully verified binary is moved into the cache, so a partial download can never
be bind-mounted.

Failures that will not fix themselves -- an HTTP status error, a platform
missing from the manifest, a full or unwritable disk -- are reported immediately
without retrying. All of them surface as `ClaudeBinaryError`, which the gateway
turns into a "try again later" reply rather than an internal error.

Channel resolution (`latest`, `stable` -> a concrete version) happens on the
task-startup path whenever the cached resolution expires, so an unreachable CDN
would fail tasks that have a perfectly good binary cached already. Resolutions
are therefore persisted to `.resolutions.json` in the cache directory, and a
failed refresh falls back to the last known version for that channel with a
warning -- a task starts on a slightly stale Claude rather than not at all.
While a fallback is available the refresh uses a short timeout and is not
re-attempted for a minute, so an outage costs one task a few seconds instead of
every task the full retry budget. With no previous resolution to fall back on
(first run on a cold cache), resolution failure is still fatal.

All Claude Code CLI flags (`--dangerously-skip-permissions`, `--model`,
`--resume`, `--output-format`, etc.) are passed through as arguments by the
executor -- the entrypoint does not add any flags. The container command holds
only Claude's options, with no positional arguments: the entrypoint supplies the
binary and the prompt is sent on stdin (Claude would prepend any positional
argument to it).

### Passthrough Entrypoint

Used by `CommandTask`. After the same setup, runs `exec "$@"`.

The command and arguments are passed through from
`CommandTask.execute(command)`.

### Overlay Image Hashing

The overlay image hash is computed via `content_hash()` over the full overlay
`ImageBuildSpec`: the generated overlay Dockerfile (which includes
`FROM <repo_tag>`) plus the entrypoint file name and content. Because the agent
and passthrough entrypoint scripts have different content, they produce
different overlay image tags even when built from the same repo image. Both
variants benefit from the same repo image cache.

## CI Image Caching

On ephemeral CI runners (GitHub Actions), the local image store is empty on
every run. The sandbox action uses `actions/cache` to persist image tarballs
across runs, restoring them via `airut-sandbox image load` before
`airut-sandbox run`. The existing build code benefits automatically from the
pre-populated local image store -- no changes to `ImageCache` are needed.

### Cached Images

Two images are cached independently. The overlay image is not cached (it is too
cheap to rebuild and depends on the repo image tag).

| Image       | Cache key                        | Invalidates when                     |
| ----------- | -------------------------------- | ------------------------------------ |
| Repo image  | `airut-repo-<dockerfile-hash>`   | Dockerfile or context files change   |
| Proxy image | `airut-proxy-<proxy-files-hash>` | Airut updates that change proxy code |

Independent entries ensure that an airut update that only touches proxy code
only rebuilds the proxy image (not the repo image), and vice versa.

### Cache Key Design

**Repo image key:** `airut-repo-<dockerfile-hash>[-v<cache-version>]`

- `<dockerfile-hash>`: First 16 hex chars of `airut-sandbox image hash` (repo
  component). Matches the content hash used by `ImageCache` internally.
- `v<cache-version>`: Optional, appended only when the `cache-version` action
  input is non-empty.

**Proxy image key:** `airut-proxy-<proxy-files-hash>[-v<cache-version>]`

- `<proxy-files-hash>`: First 16 hex chars of `airut-sandbox image hash` (proxy
  component). Changes only when an airut update modifies proxy code or
  dependencies.

### How Loaded Images Interact with `ImageCache.ensure()`

When `airut-sandbox image load` restores cached images, they appear in the local
Podman store with their original content-addressed tags. When
`airut-sandbox run` subsequently calls `ImageCache.ensure()`:

1. `get_image_created(tag)` queries `podman image inspect` and returns the
   image's **original build timestamp** -- not the load time. The `Created`
   field is part of the OCI image config JSON, which `podman load` imports
   verbatim.
2. If the image is younger than `max_age_hours`, it is reused.
3. If the image is older than `max_age_hours`, it is rebuilt with `--no-cache`.

The sandbox action passes `cache-max-age` (default: 168 hours / one week) as
`--max-image-age` to `airut-sandbox run`. This provides a time-based safety net
for base image freshness, while the content-addressed cache key handles
correctness.

### Action Step Ordering

All cache steps run **before** the sandbox. The sandbox action remains the
**terminal step** of the job, with no post-sandbox steps.

```
1.  Install uv and Python               (existing)
2.  Install airut-sandbox                (existing)
3.  Checkout base branch                 (existing)
4.  Fetch PR objects                     (existing)
5.  Compute image hashes                 (airut-sandbox image hash)
6.  Restore repo image cache             (actions/cache/restore)
7.  Restore proxy image cache            (actions/cache/restore)
8.  Load cached images                   (airut-sandbox image load, if hit)
9.  Build and save images                (airut-sandbox image save, if miss)
10. Upload repo image cache              (actions/cache/save, if miss)
11. Upload proxy image cache             (actions/cache/save, if miss)
12. Run sandboxed command                (existing: airut-sandbox run)
```

On cache hit: step 8 loads tarballs, steps 9--11 are skipped, step 12 finds
images present. On cache miss: step 8 is skipped, step 9 builds and exports,
steps 10--11 upload, step 12 finds images present.

### Security

The primary threat is **cache poisoning**: a malicious PR writes a tampered
image tarball to the cache so that a subsequent run (on main or another PR)
loads the poisoned image. This is especially concerning for the proxy image,
which has unrestricted network access and handles credential replacement.

Four independent defenses prevent this:

1. **Step ordering (structural guarantee)**: All cache operations (steps 5--11)
   run **before** the sandbox (step 12). The sandbox is the terminal step -- no
   workflow steps execute after it. A compromised container cannot tamper with
   tarballs, call cache APIs, or influence upload steps because those steps have
   already completed.

2. **No cache API credentials in the container**: The GitHub Actions cache API
   (`ACTIONS_CACHE_URL`) is authenticated by a short-lived JWT
   (`ACTIONS_RUNTIME_TOKEN`). The sandbox container receives only explicitly
   declared environment variables via `ContainerEnv` -- it does not inherit the
   runner's environment. Neither token is passed unless a user explicitly adds
   them to `pass_env` in `.airut/sandbox.yaml` (which would be a
   misconfiguration).

3. **Branch-scoped cache isolation (platform guarantee)**: GitHub Actions caches
   are scoped by branch. PR branches can read the base branch's cache but cannot
   write to it. Cache entries created during a PR run are scoped to that PR's
   branch and discarded when the branch is deleted.

4. **Cache key immutability (platform guarantee)**: Once saved, a cache entry
   cannot be overwritten -- subsequent saves with the same key are silently
   rejected. Deletion requires the GitHub REST API with `GITHUB_TOKEN` having
   `actions: write` permission (a different credential than the cache runtime
   token). Note that cache keys are content-addressed based on build *inputs*
   (Dockerfile hash, proxy file hash), not build *outputs* -- two builds from
   the same Dockerfile produce the same key even if the resulting image differs.

**No secrets in images**: Neither image contains credentials. Secrets are
injected at runtime via environment variables (surrogates for masked secrets)
and proxy-level bind mounts (CA certificates).

**Defense in depth**: For cache poisoning to succeed, an attacker would need to
simultaneously bypass step ordering, obtain cache API credentials not passed to
the container, write to a branch scope they don't control, and overwrite an
immutable cache entry.

### Performance

| Scenario              | Pre-sandbox overhead            | Net CI time change |
| --------------------- | ------------------------------- | ------------------ |
| No caching (baseline) | ~73 s build                     | --                 |
| Cold (first run)      | ~73 s build + ~20 s save/upload | +20 s              |
| Warm (both cached)    | ~16 s load                      | **-57 s**          |
| Partial (repo miss)   | ~6 s proxy load + ~45 s build   | **-12 s**          |

The CA certificate is **not cached** -- it is generated from the proxy image in
~3--5 s and contains the CA private key. The small time saving does not justify
persisting a private key in GitHub's cache storage.

## Image Cleanup

The gateway's housekeeping thread automatically prunes container images every 24
hours (controlled by `execution.image_prune`, default `true`). Each cycle:

1. Removes dangling (untagged) images via `<container_command> image prune -f`.
2. Lists images matching the `{resource_prefix}-*` naming pattern and removes
   any older than the internal staleness threshold (24 h, same as the rebuild
   threshold in `ensure()`).

Pruning runs in the background without holding the image build lock, so
concurrent task startups are not blocked.

Manual cleanup is also possible: `podman image prune -a`.
