# Airut Repo Configuration

This directory contains repo-specific Airut configuration. Files here are read
from the git mirror's default branch at task start, so changes take effect after
merging to main without server restart.

For a minimal working example of `.airut/` configuration, see the
[airut.org website repository](https://github.com/airutorg/website).

## Files

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

### `sandbox.yaml` — Sandbox CLI Config

Configuration for `airut-sandbox run`, used by CI pipelines and other
environments that run agent-steerable code inside the sandbox. Not used by the
Airut gateway service (gateway sandbox is configured in server `airut.yaml`).
See `spec/sandbox-cli.md`.

```yaml
env:                              # Static environment variables
  CI: "true"

pass_env: [TERM]                  # Host env vars passed through (no masking)

masked_secrets:                   # Credentials with proxy-level token replacement
  GH_TOKEN:
    value: !env GH_TOKEN
    scopes: [api.github.com, "*.githubusercontent.com"]
    headers: [Authorization]

signing_credentials:              # AWS SigV4 re-signing credentials
  AWS_BEDROCK:
    type: aws-sigv4
    access_key_id: !env AWS_ACCESS_KEY_ID
    secret_access_key: !env AWS_SECRET_ACCESS_KEY
    scopes: ["*.amazonaws.com"]

network_sandbox: true             # Enforce network allowlist (default: true)

resource_limits:                  # Container resource limits (all optional)
  timeout: 600
  memory: "4g"
```

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
- Secrets pool (auto-injected as container env vars)
- Model, effort, resource limits, container env, network sandbox
- GitHub App credentials — proxy-managed token rotation
- Masked secrets — surrogate token replacement for scoped hosts
- Signing credentials — AWS SigV4 re-signing

A repo can have email, Slack, or both channels active simultaneously. See
`doc/email-setup.md` and `doc/slack-setup.md` for channel-specific guides.

See `spec/repo-config.md` for the full schema.
