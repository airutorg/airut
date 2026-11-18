# Updating Dependencies

Airut pins its dependencies in three uv lockfiles and the proxy's base image by
digest. A dependency update refreshes all of them in one PR, so the proxy, which
holds every task's real credentials, never builds on stale or unpinned inputs.

## Steps

Start from latest main on a feature branch (see `CLAUDE.md`).

### 1. Main lock

```bash
uv lock --upgrade
```

### 2. Proxy lock and requirements

```bash
cd airut/_bundled/proxy
uv lock --upgrade
uv export --format requirements-txt --no-dev --frozen --no-emit-project --no-header > requirements.txt
cd -
```

Commit `uv.lock` and `requirements.txt` together. Check whether each
`override-dependencies` entry in the proxy `pyproject.toml` is still needed; the
policy is in [spec/image.md](../spec/image.md#proxy-dependency-management).

If the mitmproxy version changed, re-check the patch in
`airut/_bundled/proxy/connection_reuse.py`;
`tests/proxy/test_connection_reuse.py` fails until you do. The patch changes how
mitmproxy picks the upstream connection for a request, and only a missing
`GetHttpConnection.connection_spec_matches` stops the proxy from starting. Read
`HttpLayer.get_connection` in the new release, which answers a request with an
earlier connection's `error` in two places: the loop over existing connections
and the check of the layer's own context server.

- If neither place does so any more, delete the module, its call in
  `ProxyFilter.load()`, its tests, the `GetHttpConnection` mock in
  `tests/proxy/conftest.py`, its `COPY` entry in `proxy.dockerfile`, and its
  paragraph and Components row in `spec/network-sandbox.md`.
- Otherwise confirm that both places still decide through
  `connection_spec_matches`.

Then set `VERIFIED_MITMPROXY_VERSION` in the test to the new version.

### 3. Screenshots lock

```bash
cd screenshots && uv lock --upgrade && cd -
```

### 4. Proxy base image digest

```bash
uv run python -m scripts.check_image_pins --fix
```

This looks up the current digest of each base image tag in the bundled
Dockerfiles (`docker.io/library/python:3.13-slim` for the proxy) and rewrites
outdated digests. Review the diff: only the `sha256:` digest should change. It
needs read access to Docker Hub's registry, which
`.airut/network-allowlist.yaml` grants for `library/python` manifests. A new
Python minor version (a new tag) is a deliberate change made by hand, not part
of a routine update; see [spec/image.md](../spec/image.md#proxy-base-image).

### 5. Verify and commit

```bash
uv run scripts/ci.py --fix
```

Fix any breakage the new versions cause in the same PR. List every version and
digest change in the commit message (old -> new, per lockfile), as earlier
`chore: bump dependencies to latest` commits do, and note why any override or
pin stays.

GitHub Actions pins are updated separately, see
[check-actions.md](check-actions.md).
