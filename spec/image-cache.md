# Unified Image Cache

Replaces the current split image management (`_image.py` for execution
containers, `_proxy.py._build_image()` for the proxy) with a single `ImageCache`
that handles all container image builds: repo layer, overlay layer, and proxy.

**Supersedes:** `spec/image.md` sections on staleness/caching and build flow.
The two-layer build strategy, entrypoint contract, and proxy dependency
management sections of `spec/image.md` remain valid.

## Table of Contents

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=1 -->

- [Unified Image Cache](#unified-image-cache)
  - [Table of Contents](#table-of-contents)
  - [Motivation](#motivation)
  - [Design Goals](#design-goals)
  - [Architecture](#architecture)
    - [ImageCache](#imagecache)
    - [ImageBuildSpec](#imagebuildspec)
    - [Tag Naming](#tag-naming)
    - [Content Hashing](#content-hashing)
    - [Age Detection via Podman](#age-detection-via-podman)
    - [Build Logic](#build-logic)
    - [The ensure() Flow](#the-ensure-flow)
    - [Thread Safety](#thread-safety)
  - [Integration](#integration)
    - [SandboxConfig Changes](#sandboxconfig-changes)
    - [Sandbox Changes](#sandbox-changes)
    - [ProxyManager Changes](#proxymanager-changes)
    - [Sandbox CLI Changes](#sandbox-cli-changes)
  - [Proxy Image Context Files](#proxy-image-context-files)
  - [Edge Cases](#edge-cases)
    - [Overlay Depends on Repo Tag](#overlay-depends-on-repo-tag)
    - [Proxy Rebuild During Active Tasks](#proxy-rebuild-during-active-tasks)
    - [First Build vs Stale Rebuild](#first-build-vs-stale-rebuild)
    - [Clock Skew](#clock-skew)
    - [Podman Timestamp Parsing](#podman-timestamp-parsing)
  - [Migration](#migration)
    - [Deleted Code](#deleted-code)
    - [Renamed Images](#renamed-images)
    - [Spec Updates Required](#spec-updates-required)
    - [.dockerignore](#dockerignore)
    - [Test Changes](#test-changes)

<!-- mdformat-toc end -->

## Motivation

Three problems with the current implementation:

1. **Stale rebuilds do not pick up upstream changes.** The 24-hour staleness
   check calls `podman build` without `--no-cache`. Podman's layer cache serves
   the old `RUN curl .../install.sh | bash` layer, so Claude Code is never
   updated. The staleness check is a no-op in practice.

2. **Proxy image has no content hash or staleness logic.**
   `ProxyManager._build_image()` unconditionally calls
   `podman build -t airut-proxy` with a static tag. In the gateway, this runs
   once at `startup()` — the proxy image is never refreshed until process
   restart. In the CLI, it runs every invocation (wasteful, though fast due to
   layer cache).

3. **In-memory-only age tracking.** Image build timestamps live in Python dicts
   (`_repo_images`, `_overlay_images`). The CLI starts a fresh process per run,
   so the cache is always cold — the 24-hour optimization has no effect. The
   gateway loses timestamps on restart, rebuilding everything.

## Design Goals

1. **Single module** for all image builds (repo, overlay, proxy).
2. **Content-hash tags** for all images, including proxy.
3. **Persistent age detection** via `podman image inspect` — no in-memory state
   needed.
4. **Effective staleness rebuilds** using `--no-cache` to defeat podman layer
   caching.
5. **Configurable staleness** via `max_image_age_hours` (0 = force rebuild every
   time).
6. **Thread-safe** with serialized builds.
7. **Clean break** — no backwards compatibility shims.

## Architecture

### ImageCache

The central class. One instance per `Sandbox`, shared by execution image builds
and proxy image builds.

```
class ImageCache:
    """Thread-safe container image cache with staleness checking.

    All builds are serialized via a lock. Image age is determined
    by `podman image inspect`, not in-memory state.
    """

    def __init__(
        self,
        container_command: str = "podman",
        resource_prefix: str = "airut",
        max_age_hours: int = 24,
    ) -> None

    def ensure(self, spec: ImageBuildSpec, *, force: bool = False) -> str
        """Build or reuse an image. Returns the image tag.

        Args:
            spec: What to build.
            force: If True, rebuild with --no-cache regardless of age.
        """

    def tag_for(self, spec: ImageBuildSpec) -> str
        """Compute the tag for a spec without building.

        Useful for pre-build inspection (e.g., checking whether a
        rebuild was triggered).
        """

    def get_image_created(self, tag: str) -> datetime | None
        """Query podman for image creation timestamp (public).

        Exposed so callers can detect whether ensure() triggered a
        rebuild (by comparing timestamps before and after).
        """
```

### ImageBuildSpec

Describes what to build. Immutable value object.

```python
@dataclass(frozen=True)
class ImageBuildSpec:
    """Everything needed to build a container image.

    Attributes:
        kind: Image kind, used as the middle segment of the tag
            (e.g. "repo", "overlay", "proxy").
        dockerfile: Dockerfile content (bytes).
        context_files: Additional files for build context. Mapping
            of filename to content bytes. All files are written to
            a temporary directory alongside the Dockerfile for the
            build.
    """

    kind: str
    dockerfile: bytes
    context_files: dict[str, bytes] = field(default_factory=dict)
```

All inputs are materialized as `bytes` — no `Path` references. This ensures the
content hash captures the actual build inputs, and the spec is self-contained
and testable without filesystem dependencies.

### Tag Naming

All images use `{resource_prefix}-{kind}:{content_hash}`:

| Image      | Current tag            | New tag                   |
| ---------- | ---------------------- | ------------------------- |
| Repo layer | `airut-repo:{hash}`    | `{prefix}-repo:{hash}`    |
| Overlay    | `airut:{hash}`         | `{prefix}-overlay:{hash}` |
| Proxy      | `airut-proxy` (static) | `{prefix}-proxy:{hash}`   |

Examples with default gateway prefix `airut`:

```
airut-repo:a1b2c3d4...
airut-overlay:e5f6a7b8...
airut-proxy:c9d0e1f2...
```

Examples with CLI prefix `airut-cli`:

```
airut-cli-repo:a1b2c3d4...
airut-cli-overlay:e5f6a7b8...
airut-cli-proxy:c9d0e1f2...
```

This prevents collisions between the gateway and CLI running on the same host.
The content hash is the full 64-character SHA-256 hex digest.

### Content Hashing

```python
def _content_hash(spec: ImageBuildSpec) -> str:
    """SHA-256 of dockerfile + sorted context file names and contents."""
    h = hashlib.sha256()
    h.update(spec.dockerfile)
    for name in sorted(spec.context_files):
        h.update(name.encode())
        h.update(spec.context_files[name])
    return h.hexdigest()
```

The hash is deterministic: same inputs always produce the same tag. When any
input changes (Dockerfile content, context file names, context file contents),
the tag changes and a fresh image is built.

### Age Detection via Podman

Instead of in-memory timestamps, query podman for the image creation time:

```python
def _get_image_created(self, tag: str) -> datetime | None:
    """Query podman for image creation timestamp.

    Returns:
        Image creation time (timezone-aware), or None if the image
        does not exist or the timestamp cannot be parsed.
    """
    result = subprocess.run(
        [self._cmd, "image", "inspect", tag, "--format", "{{.Created}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        return datetime.fromisoformat(result.stdout.strip())
    except ValueError:
        logger.warning(
            "Cannot parse image timestamp for %s: %r",
            tag,
            result.stdout.strip(),
        )
        return None
```

If `fromisoformat()` fails (unexpected format from podman), the image is treated
as non-existent and rebuilt. This degrades gracefully to a rebuild rather than
crashing.

This works identically for long-lived gateway processes and one-shot CLI
invocations — the image creation time is stored by podman itself, surviving
process restarts.

### Build Logic

```python
def _build(
    self,
    spec: ImageBuildSpec,
    tag: str,
    *,
    no_cache: bool,
) -> None:
    """Execute podman build.

    Raises:
        ImageBuildError: If the build fails.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = Path(tmpdir) / "Dockerfile"
        df_path.write_bytes(spec.dockerfile)

        for name, content in spec.context_files.items():
            (Path(tmpdir) / name).write_bytes(content)

        cmd = [self._cmd, "build", "-t", tag, "-f", str(df_path)]
        if no_cache:
            cmd.append("--no-cache")
        cmd.append(tmpdir)

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise ImageBuildError(
                f"Image build failed for {tag}: {e.stderr.strip()}"
            ) from e
```

### The ensure() Flow

```python
def ensure(self, spec: ImageBuildSpec, *, force: bool = False) -> str:
    content_hash = _content_hash(spec)
    tag = f"{self._resource_prefix}-{spec.kind}:{content_hash}"

    with self._lock:
        created = self._get_image_created(tag)

        if created is None:
            # Image does not exist — first build.
            # Podman layer cache is fine here (nothing stale to bust).
            self._build(spec, tag, no_cache=False)

        elif force or self._max_age_hours == 0:
            # Force-rebuild mode (explicit force, or --max-image-age 0).
            self._build(spec, tag, no_cache=True)

        elif self._is_stale(created):
            # Image exists but is stale — rebuild with --no-cache
            # to pick up upstream changes (new Claude Code, etc.).
            self._build(spec, tag, no_cache=True)

        else:
            logger.debug("Reusing %s (created %s)", tag, created)

    return tag
```

Decision table:

| Image exists? | force | max_age_hours | Age vs max | Action  | `--no-cache`? |
| ------------- | ----- | ------------- | ---------- | ------- | ------------- |
| No            | any   | any           | N/A        | Build   | No            |
| Yes           | True  | any           | N/A        | Rebuild | Yes           |
| Yes           | False | 0             | N/A        | Rebuild | Yes           |
| Yes           | False | > 0           | Fresh      | Reuse   | N/A           |
| Yes           | False | > 0           | Stale      | Rebuild | Yes           |

### Thread Safety

`ImageCache` uses a single `threading.Lock` to serialize all builds. This
prevents:

- Two threads building the same image concurrently.
- Race between `_get_image_created()` and `_build()`.

The lock is held for the duration of `ensure()` (inspect + optional build).
Builds are typically fast (cache hit or incremental), and contention is low
because:

- Repo + overlay builds happen per-task but are typically cache hits.
- Proxy builds happen once at startup.

A per-tag lock is a possible future optimization but not needed given current
concurrency patterns.

## Integration

### SandboxConfig Changes

```python
@dataclass(frozen=True)
class SandboxConfig:
    container_command: str = "podman"
    proxy_dir: Path = field(default_factory=_default_proxy_dir)
    upstream_dns: str = "1.1.1.1"
    max_image_age_hours: int = 24
    resource_prefix: str = "airut"
```

No changes to `SandboxConfig`. The existing `max_image_age_hours` field now
controls staleness for all image types (repo, overlay, proxy) instead of just
repo and overlay.

### Sandbox Changes

`Sandbox.__init__()` creates `ImageCache` and injects it into `ProxyManager`:

```python
class Sandbox:
    def __init__(
        self,
        config: SandboxConfig,
        *,
        egress_network: str | None = None,
    ) -> None:
        self._image_cache = ImageCache(
            container_command=config.container_command,
            resource_prefix=config.resource_prefix,
            max_age_hours=config.max_image_age_hours,
        )
        self._proxy_manager = ProxyManager(
            container_command=config.container_command,
            proxy_dir=config.proxy_dir,
            egress_network=egress_network,
            upstream_dns=config.upstream_dns,
            resource_prefix=config.resource_prefix,
            image_cache=self._image_cache,
        )
```

`Sandbox.ensure_image()` delegates to `ImageCache.ensure()`:

```python
def ensure_image(
    self,
    dockerfile: bytes,
    context_files: dict[str, bytes],
    *,
    passthrough_entrypoint: bool = False,
) -> str:
    repo_spec = ImageBuildSpec(
        kind="repo",
        dockerfile=dockerfile,
        context_files=context_files,
    )

    # Detect whether repo was rebuilt (for force-cascading to overlay).
    repo_tag = self._image_cache.tag_for(repo_spec)
    repo_created_before = self._image_cache.get_image_created(repo_tag)
    repo_tag = self._image_cache.ensure(repo_spec)
    repo_rebuilt = (
        repo_created_before is None
        or self._image_cache.get_image_created(repo_tag) != repo_created_before
    )

    entrypoint = get_entrypoint_content(
        passthrough=passthrough_entrypoint,
    )
    overlay_df = (
        f"FROM {repo_tag}\n"
        f"COPY airut-entrypoint.sh /entrypoint.sh\n"
        f"RUN chmod +x /entrypoint.sh\n"
        f'ENTRYPOINT ["/entrypoint.sh"]\n'
    ).encode()
    overlay_spec = ImageBuildSpec(
        kind="overlay",
        dockerfile=overlay_df,
        context_files={"airut-entrypoint.sh": entrypoint},
    )
    overlay_tag = self._image_cache.ensure(
        overlay_spec,
        force=repo_rebuilt,
    )

    return overlay_tag
```

**Removed from Sandbox:**

- `_build_lock` — replaced by `ImageCache._lock`.
- `_repo_images` / `_overlay_images` — no in-memory cache needed.

### ProxyManager Changes

`ProxyManager` receives `ImageCache` via constructor injection instead of
building the proxy image itself:

```python
class ProxyManager:
    def __init__(
        self,
        container_command: str = "podman",
        proxy_dir: Path | None = None,
        egress_network: str | None = None,
        *,
        upstream_dns: str,
        resource_prefix: str = "airut",
        image_cache: ImageCache,
    ) -> None:
        self._image_cache = image_cache
        self._proxy_dir = proxy_dir or Path(str(files("airut._bundled.proxy")))
        self._proxy_image_tag: str | None = None

    def startup(self) -> None:
        self._cleanup_orphans()
        self._ensure_proxy_image()
        self._ensure_ca_cert()
        self._recreate_egress_network()

    def _ensure_proxy_image(self) -> None:
        """Build or reuse proxy image via ImageCache."""
        spec = self._build_proxy_spec()
        self._proxy_image_tag = self._image_cache.ensure(spec)

    def _build_proxy_spec(self) -> ImageBuildSpec:
        """Construct ImageBuildSpec for the proxy image."""
        proxy_dir = self._proxy_dir
        dockerfile = (proxy_dir / "proxy.dockerfile").read_bytes()
        context_files: dict[str, bytes] = {}
        for child in sorted(proxy_dir.iterdir()):
            if child.is_file() and child.name != "proxy.dockerfile":
                context_files[child.name] = child.read_bytes()
        return ImageBuildSpec(
            kind="proxy",
            dockerfile=dockerfile,
            context_files=context_files,
        )
```

**Removed from ProxyManager:**

- `_build_image()` method — replaced by `_ensure_proxy_image()` delegating to
  `ImageCache`.
- `PROXY_IMAGE_NAME` constant — the tag is now dynamic (content-hashed).

**Changed in ProxyManager:**

- `_run_proxy_container()` uses `self._proxy_image_tag` (set during `startup()`)
  instead of the `PROXY_IMAGE_NAME` constant.
- `_ensure_ca_cert()` uses `self._proxy_image_tag` for the `podman run` command
  that generates the CA certificate.

**Thread safety of `_proxy_image_tag`:** The field is set once during
`startup()` (which must complete before any tasks start) and is read-only
thereafter. Concurrent reads from task threads are safe without a lock.

### Sandbox CLI Changes

New `--max-image-age` argument:

```
airut-sandbox run [OPTIONS] -- COMMAND [ARGS...]

Options:
  --max-image-age HOURS   Max image age before rebuild with --no-cache.
                          Default: 24. Set to 0 to force rebuild every time.
```

Wired into `SandboxConfig`:

```python
sandbox_config = SandboxConfig(
    container_command=container_command,
    resource_prefix="airut-cli",
    max_image_age_hours=args.max_image_age,
)
```

Setting `--max-image-age 0` forces `--no-cache` rebuild of both the execution
container and the proxy on every run. This is useful for CI environments where
you always want the latest Claude Code.

## Proxy Image Context Files

The proxy `ImageBuildSpec` materializes all files from `proxy_dir` into
`context_files`. The Dockerfile is separated out as the `dockerfile` field;
every other file in the directory becomes a context file entry.

Files included (from `airut/_bundled/proxy/`):

| File                  | Role                                                        |
| --------------------- | ----------------------------------------------------------- |
| `proxy.dockerfile`    | Dockerfile (the `dockerfile` field, not in `context_files`) |
| `requirements.txt`    | Pinned pip dependencies                                     |
| `proxy_filter.py`     | mitmproxy allowlist addon                                   |
| `dns_responder.py`    | Custom DNS server                                           |
| `aws_signing.py`      | AWS SigV4/SigV4A re-signing                                 |
| `proxy-entrypoint.sh` | Container entrypoint                                        |
| `pyproject.toml`      | Dependency declarations (not used in build, but hashed)     |
| `uv.lock`             | Pinned dependency graph (not used in build, but hashed)     |
| `__init__.py`         | Python package marker (not used in build, but hashed)       |

Including all files in the hash is deliberate — any change to any file in the
proxy directory produces a new tag, triggering a fresh build. Files not
referenced by the Dockerfile (like `uv.lock`) are harmless in the build context
but contribute to the content hash, ensuring that dependency updates are
reflected.

## Edge Cases

### Overlay Depends on Repo Tag

The overlay Dockerfile contains `FROM {repo_tag}`. If the repo image is rebuilt
due to staleness (same tag, new content because `--no-cache` re-runs upstream
fetches), the overlay should also be rebuilt.

In the common case, the overlay and repo images share the same `max_age_hours`
and were built at roughly the same time, so when the repo is stale, the overlay
is also stale. Both get rebuilt with `--no-cache`, and the overlay's `FROM`
picks up the freshly rebuilt repo image.

**Edge case:** If a previous run was interrupted between the repo and overlay
builds (e.g., process killed after repo build but before overlay build), they
may have different creation timestamps. The overlay could appear "fresh" while
the repo is "stale", causing the overlay to miss the repo update. To handle
this, `Sandbox.ensure_image()` tracks whether the repo was rebuilt and, if so,
forces the overlay rebuild by temporarily using `max_age_hours=0`:

```python
# In Sandbox.ensure_image():
repo_created_before = self._image_cache.get_image_created(repo_tag)
repo_tag = self._image_cache.ensure(repo_spec)
repo_rebuilt = (
    repo_created_before is None
    or self._image_cache.get_image_created(repo_tag) != repo_created_before
)

if repo_rebuilt:
    # Force overlay rebuild to pick up the new repo image.
    overlay_tag = self._image_cache.ensure(overlay_spec, force=True)
else:
    overlay_tag = self._image_cache.ensure(overlay_spec)
```

This requires `ensure()` to accept an optional `force: bool = False` parameter
that behaves like `max_age_hours=0` for that single call.

### Proxy Rebuild During Active Tasks

The proxy image is built during `startup()`, before any tasks start. Active
proxy containers use the image they were started with. If the image is rebuilt
(e.g., a long-running gateway restarts), only newly created proxy containers use
the new image. This is the same behavior as today.

### First Build vs Stale Rebuild

When an image does not exist at all (`_get_image_created` returns `None`),
`--no-cache` is **not** passed. This is intentional: on first build, there is no
stale layer cache to bust. Allowing podman's layer cache to work on first build
is faster (e.g., if a base image was previously pulled).

When an image exists but is stale, `--no-cache` **is** passed. This forces
podman to re-run every layer, including `RUN curl .../install.sh` which fetches
the latest Claude Code.

### Clock Skew

The staleness check compares `datetime.now(UTC)` with the image creation
timestamp from podman. If the system clock is wrong, staleness detection may be
inaccurate. This is the same risk as any time-based cache and is not specific to
this design.

### Podman Timestamp Parsing

Podman's `--format '{{.Created}}'` returns an RFC 3339 timestamp. Python's
`datetime.fromisoformat()` handles this format since Python 3.11. The
implementation must handle timezone-aware comparison (podman may return UTC or
local time depending on version).

## Migration

### Deleted Code

| File / symbol                        | Replacement                                                                           |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| `_image.py` (entire module)          | `_image_cache.py` (`ImageBuildError` moves here; update `sandbox/__init__.py` import) |
| `_image._ImageInfo`                  | `podman image inspect` (no in-memory tracking)                                        |
| `_image._content_hash()`             | `_image_cache._content_hash()`                                                        |
| `_image._is_image_fresh()`           | `ImageCache._is_stale()` + podman inspect                                             |
| `_image.build_repo_image()`          | `ImageCache.ensure()` with `kind="repo"`                                              |
| `_image.build_overlay_image()`       | `ImageCache.ensure()` with `kind="overlay"`                                           |
| `_proxy.PROXY_IMAGE_NAME`            | Dynamic tag from `ImageCache.ensure()`                                                |
| `_proxy.ProxyManager._build_image()` | `ProxyManager._ensure_proxy_image()` via `ImageCache`                                 |
| `sandbox.Sandbox._build_lock`        | `ImageCache._lock`                                                                    |
| `sandbox.Sandbox._repo_images`       | Removed (no in-memory cache)                                                          |
| `sandbox.Sandbox._overlay_images`    | Removed (no in-memory cache)                                                          |

### Renamed Images

| Old tag pattern     | New tag pattern                                                     |
| ------------------- | ------------------------------------------------------------------- |
| `airut-repo:{hash}` | `airut-repo:{hash}` (gateway) / `airut-cli-repo:{hash}` (CLI)       |
| `airut:{hash}`      | `airut-overlay:{hash}` (gateway) / `airut-cli-overlay:{hash}` (CLI) |
| `airut-proxy`       | `airut-proxy:{hash}` (gateway) / `airut-cli-proxy:{hash}` (CLI)     |

Repo image hashes are unchanged (same hashing algorithm over same inputs), so
the gateway prefix `airut-repo:{hash}` produces the same `{hash}` as before.
Overlay hashes change because the Dockerfile content now includes the full
`FROM` line as bytes rather than being hashed separately from the entrypoint.
All old overlay and proxy images are orphaned after migration.

Old images are not cleaned up automatically. Users can run `podman image prune`
to reclaim space.

### Spec Updates Required

The following existing specs must be updated alongside implementation:

- **`spec/image.md`** — Remove or rewrite the "Staleness and Caching", "Build
  Flow", and "Concurrent Build Safety" sections. Point to this spec. Keep the
  two-layer strategy description, entrypoint contract, and proxy dependency
  management sections.
- **`spec/sandbox-cli.md`** — Update the "Resource Isolation" section: proxy
  images are no longer shared between gateway and CLI (they use different
  `resource_prefix` values and produce separate images). Add the
  `--max-image-age` CLI argument to the interface documentation.
- **`spec/sandbox.md`** — Minor: update the architecture section to mention
  `ImageCache` instead of "Container image cache (two-layer,
  content-addressed)".

### .dockerignore

The new build approach writes all `context_files` to a temporary directory used
as the build context. Any `.dockerignore` files in the original source directory
are not copied to this tmpdir and therefore have no effect. This is not an issue
currently (no `.dockerignore` exists in `_bundled/proxy/` or in any known
`.airut/container/` directory), but is a behavioral change from the previous
proxy build which used the source directory directly as context.

If `.dockerignore` support becomes necessary, the implementation could filter
`context_files` entries against the ignore rules before writing them. This is
out of scope for the initial implementation.

### Test Changes

Tests for `_image.py` (`test_image.py`) are rewritten to test `ImageCache`
directly. The testing approach changes:

- **No in-memory cache mocking.** Tests mock `subprocess.run` for podman
  commands (`image inspect`, `build`).
- **Staleness tests** mock `_get_image_created()` to return specific timestamps
  rather than manipulating in-memory `_ImageInfo` objects.
- **Proxy image tests** in `test_proxy.py` are updated: `TestBuildImage` is
  replaced with tests for `_ensure_proxy_image()` and `_build_proxy_spec()`.
- **Sandbox tests** in `test_sandbox.py` mock `ImageCache.ensure()` instead of
  `build_repo_image()` / `build_overlay_image()`.
- **CLI tests** in `test_sandbox_cli.py` continue to mock `Sandbox` at the class
  level — no changes needed.
