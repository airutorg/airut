# Container Image Management

Manages the two-layer container image build for Airut: a **repo-defined base
image** (sourced from the git mirror) and a **server-defined overlay** (with the
Airut entrypoint).

## Design Goals

1. **Repo controls its environment**: The target repository defines what tools
   and dependencies it needs (Python, Claude Code, ripgrep, etc.) via a
   Dockerfile in `.airut/container/Dockerfile`. Changes take effect after
   merging to main — no server restart required.
2. **Server controls the entrypoint**: The sandbox library generates the
   container entrypoint in code (`airut/sandbox/_entrypoint.py`). This is the
   interface contract between Airut and the container.
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
  Contains: Ubuntu, system deps, Python, Claude Code, uv, etc.

Layer 2: Server Overlay (generated in code)
  Source: airut/sandbox/_entrypoint.py (generated entrypoint script)
  Tag:    airut:<sha256-of-repo-tag-plus-entrypoint>
  Contains: FROM repo image + COPY entrypoint + ENTRYPOINT directive
```

### File Locations

```
# In the target repository (read from git mirror at task start)
.airut/
  network-allowlist.yaml          # network sandbox allowlist config
  container/
    Dockerfile                    # repo-defined base image
    <other files>                 # additional files for build context

# On the Airut server (generated in code)
airut/sandbox/
  _entrypoint.py                  # generated entrypoint script
  _image.py                       # two-layer image build logic

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

All files in `.airut/container/` are copied to the build context, allowing the
Dockerfile to use `COPY` instructions to include additional files (e.g.,
configuration files, scripts) in the image.

## Build Flow

### Per-Task Build (at task start)

```
1. List all files in .airut/container/ from git mirror (main branch)
2. Read Dockerfile and any additional context files
3. Compute repo_hash = sha256(Dockerfile + sorted context files)
4. Compute overlay_hash = sha256(repo_tag + entrypoint content)

5. Check repo image: airut-repo:<repo_hash>
   EXISTS and age < 24 hours → reuse
   OTHERWISE → build from Dockerfile with context files, tag with repo_hash

6. Check overlay image: airut:<overlay_hash>
   EXISTS and repo image was reused → reuse
   OTHERWISE → build overlay (FROM repo image + entrypoint), tag

7. Run container from airut:<overlay_hash>
```

### Build Details

**Repo image build** (step 5):

- List all files in `.airut/container/` via `GitMirrorCache.list_directory()`
- Read each file's content via `GitMirrorCache.read_file()`
- Write all files to a temporary directory (build context)
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

| Condition                                       | Action                                   |
| ----------------------------------------------- | ---------------------------------------- |
| Container dir unchanged, image < 24h old        | Reuse (fast path)                        |
| Container dir unchanged, image >= 24h old       | Rebuild to pick up upstream updates      |
| Dockerfile or context files changed (diff hash) | Build new image (new tag)                |
| Generated entrypoint changed                    | Rebuild overlay only (repo image reused) |

Image age is tracked by recording build timestamps in memory. On service
restart, images without a recorded build time are treated as stale.

### Concurrent Build Safety

The build is protected by a lock. When multiple tasks need a build
simultaneously:

- First task acquires lock, builds
- Subsequent tasks wait, then find the image already exists and reuse it

Builds produce new tags, so they don't affect running containers.

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

## Entrypoint Contract

The entrypoint script (generated by `airut/sandbox/_entrypoint.py`) performs two
tasks before running Claude Code:

1. Sets `IS_SANDBOX=1` so Claude Code runs in permissive mode
2. Trusts the mitmproxy CA certificate (for network sandbox)

All Claude Code CLI flags (`--dangerously-skip-permissions`, `--model`,
`--resume`, `--output-format`, etc.) are passed through as arguments by the
executor — the entrypoint does not add any flags.

## Image Cleanup

Old images accumulate as Dockerfile content changes. Podman's
`podman image prune` can be run periodically to reclaim space.
