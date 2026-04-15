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
    methods: [POST]
    graphql:                     # optional: filter GraphQL operations
      queries:
        - "*"                    # allow all queries
      mutations:                 # allow only specific mutations (default-deny)
        - createPullRequest
        - updatePullRequest
        - mergePullRequest
      # subscriptions: omitted = all blocked
```

**GraphQL operation filtering:** URL prefix entries for GraphQL endpoints can
include an optional `graphql` block that filters operations by type (query,
mutation, subscription) and top-level field name. Omitted operation types are
blocked (default-deny). Pattern matching uses fnmatch wildcards (`*`, `?`). See
`doc/network-sandbox.md` for full details and
`spec/graphql-operation-allowlist.md` for the specification.

**Wildcard host:** For repositories that need broad network access but still
want credential protection, use `host: "*"` with method restrictions:

```yaml
url_prefixes:
  - host: "*"
    path: ""
    methods: [GET, HEAD]         # read-only access to all domains
  - host: api.github.com
    path: /graphql
    methods: [POST]              # write access only where needed
```

This opens read access to all domains while credential masking still prevents
exfiltration of real credentials (tokens, API keys). Repository data can still
be exfiltrated via GET parameters, so this is only appropriate when the
repository contains public material. See `doc/network-sandbox.md` for security
implications.

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

GitHub App credentials (`github_app_credentials`) are supported in server config
(`airut.yaml`) but not in `sandbox.yaml`. For CI pipelines, use `masked_secrets`
for GitHub tokens instead. See `spec/github-app-credential.md` for GitHub App
credential details and `spec/sandbox-cli.md` for the sandbox CLI credential
handling guide.

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
- Per-repo settings (model, effort, resource limits, container environment
  variables, network sandbox toggle)
- Credential pools per repo:
  - `secrets` — plain values injected as container environment variables
  - `masked_secrets` — surrogate token replacement for scoped hosts
  - `signing_credentials` — AWS SigV4 re-signing
  - `github_app_credentials` — proxy-managed GitHub App token rotation

All credential pool entries (secrets, masked secrets, signing credentials,
GitHub App credentials) auto-inject into the container as environment variables
by their key name.

A repo can have email, Slack, or both channels active simultaneously. See
`doc/email-setup.md` and `doc/slack-setup.md` for channel-specific guides.

See `spec/repo-config.md` for the full schema.
