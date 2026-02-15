# Airut Repo Configuration

This directory contains repo-specific Airut configuration. Files here are read
from the git mirror's default branch at task start, so changes take effect after
merging to main without server restart.

For a minimal working example of `.airut/` configuration, see the
[airut.org website repository](https://github.com/airutorg/website).

## Files

### `airut.yaml` — Repo Config

Controls repo-specific behavior:

```yaml
default_model: opus         # Claude model when not specified via subaddressing
timeout: 6000               # Max container execution time (seconds)

network:
  sandbox_enabled: true     # Enable network allowlist enforcement

container_env:              # Environment variables for containers
  GH_TOKEN: !secret GH_TOKEN              # Required secret from server pool
  API_KEY: !secret? API_KEY               # Optional secret (skip if missing)
  BUCKET_NAME: "my-bucket"                # Inline value (non-secret)
```

**YAML Tags:**

- `!secret NAME` — resolve from server's secrets pool (error if missing)
- `!secret? NAME` — optional secret (skip entry if missing)
- `!env` is NOT allowed in repo config (security: prevents reading server env)

### `network-allowlist.yaml` — Network Sandbox

Defines which hosts containers can access. All HTTP(S) traffic is proxied and
checked against this allowlist. See `doc/network-sandbox.md`.

```yaml
# Full-domain entries: all paths and methods allowed
domains:
  - api.anthropic.com
  - pypi.org

# URL prefix entries: host + path required, optional method filter
url_prefixes:
  - host: api.github.com
    path: /repos/owner/repo*
  - host: api.github.com
    path: /graphql
    methods: [POST]              # optional: restrict to specific HTTP methods
```

**Self-service workflow:** When the agent encounters a blocked request, it can
edit this file and submit a PR. A human must review and merge before the change
takes effect.

### `container/Dockerfile` — Container Image

Repo-defined base image. Controls what tools and dependencies are available in
the Claude Code container. See `spec/image.md`.

The server adds an overlay with the entrypoint script, so the repo Dockerfile
doesn't need to define `ENTRYPOINT`.

## Server Config

Server-side configuration lives in `~/.config/airut/airut.yaml` (not in this
directory). Run `airut init` to create a stub, or see
`config/airut.example.yaml` in the repository for a documented example. It
handles:

- Mail server credentials (IMAP/SMTP) — **each repo needs a dedicated inbox**
- Authorized senders and trusted authserv_id
- Storage directory and git repo URL
- Secrets pool (values that `!secret` tags reference)

> **Note:** Airut treats the IMAP inbox as a work queue. It polls for messages,
> processes every email, and permanently deletes messages after processing.
> Never use a shared or personal email account.

See `spec/repo-config.md` for the full schema.
