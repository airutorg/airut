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
default_model: opus         # Claude model (overridable via email subaddressing)

resource_limits:            # Container resource limits (all optional)
  timeout: 6000             # Max execution time in seconds (>= 10)
  memory: "4g"              # Memory limit, e.g. "2g", "512m"
  cpus: 2                   # CPU limit (float, e.g. 1.5 for 1.5 cores)
  pids_limit: 256           # Process limit (fork bomb protection)

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
# URL prefix entries: host + path required, optional method filter
url_prefixes:
  # Anthropic API — path-restricted to prevent exfiltration via /v1/files
  # (attacker can use their own API key to upload/fetch material)
  - host: api.anthropic.com
    path: /v1/messages*
    methods: [POST]
  - host: api.anthropic.com
    path: /api/oauth/*
    methods: [GET]
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

- Channel credentials (email: IMAP/SMTP; Slack: bot and app tokens)
- Authorization configuration (email: sender allowlist; Slack: rules)
- Git repo URL and storage directory
- Secrets pool (values that `!secret` tags reference)

A repo can have email, Slack, or both channels active simultaneously. See
`doc/email-setup.md` and `doc/slack-setup.md` for channel-specific guides.

See `spec/repo-config.md` for the full schema.
