# Gerrit Repository Onboarding

The [main onboarding guide](repo-onboarding.md) assumes GitHub. If your
repository is hosted on a Gerrit code review server, the same overall flow
applies but the authentication, container setup, and workflow tooling differ.
This guide walks through the Gerrit-specific pieces.

Follow the [main onboarding guide](repo-onboarding.md) for the general steps,
then apply the Gerrit-specific overrides below.

## Server-Side: Git Credentials

Airut fetches from configured repositories to maintain git mirrors. For Gerrit,
use HTTP credentials with the git credential store:

```bash
git config --global credential.helper store

# Clone once to store the HTTP credentials (can be removed afterward)
git clone https://gerrit.example.com/a/my-project
```

When prompted, enter your Gerrit username and **HTTP password** (generated under
Settings > HTTP Credentials in the Gerrit web UI). Once credentials are stored,
verify access:

```bash
git ls-remote https://gerrit.example.com/a/my-project
```

Using HTTP credentials (rather than SSH) is recommended because it enables
Airut's masked-secret credential injection — the proxy can swap surrogate tokens
for the real password only when requests target the Gerrit host.

## Repo Settings (`.airut/airut.yaml`)

The Gerrit HTTP password should be passed through `container_env` as a masked
secret reference so the container can push changes:

```yaml
default_model: opus
timeout: 300

network:
  sandbox_enabled: true

container_env:
  ANTHROPIC_API_KEY: !secret ANTHROPIC_API_KEY
  GERRIT_USER: !secret GERRIT_USER
  GERRIT_HTTP_PASSWORD: !secret GERRIT_HTTP_PASSWORD
```

## Network Allowlist

Add your Gerrit server to `.airut/network-allowlist.yaml`:

```yaml
domains:
  - api.anthropic.com

url_prefixes:
  # Claude telemetry and error reporting (POST-only)
  - host: statsig.anthropic.com
    path: ""
    methods: [POST]
  - host: sentry.io
    path: ""
    methods: [POST]

  # Gerrit (git smart HTTP uses GET, HEAD, and POST)
  - host: gerrit.example.com
    path: ""
    methods: [GET, HEAD, POST]
```

## Container Setup

Gerrit does not use `gh` CLI. Instead, authentication is handled via a custom
git credential helper that reads from environment variables injected by Airut.

**`.airut/container/gerrit-credential-helper`:**

```sh
#!/bin/sh
# Git credential helper that supplies Gerrit HTTP credentials
# from environment variables.

test "$1" = "get" || exit 0

while read -r line; do
    case "$line" in
        host=gerrit.example.com) match=1 ;;
        "") break ;;
    esac
done

if [ "$match" = "1" ]; then
    echo "username=$GERRIT_USER"
    echo "password=$GERRIT_HTTP_PASSWORD"
fi
```

**`.airut/container/gitconfig`:**

```ini
[user]
    name = My Repo Agent
    email = agent@example.com
[credential "https://gerrit.example.com"]
    helper = /usr/local/bin/gerrit-credential-helper
```

**`.airut/container/Dockerfile`:**

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Python (if needed)
RUN uv python install 3.13

# Claude Code
RUN mkdir /tmp/claude-install && cd /tmp/claude-install \
    && curl -fsSL https://claude.ai/install.sh | bash \
    && rm -rf /tmp/claude-install

# Gerrit credential helper
COPY gitconfig /root/.gitconfig
COPY gerrit-credential-helper /usr/local/bin/gerrit-credential-helper
RUN chmod +x /usr/local/bin/gerrit-credential-helper

WORKDIR /workspace
```

Note that `gh` CLI is **not** installed — it is not needed for Gerrit workflows.

## Server Configuration

```yaml
repos:
  my-project:
    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: my-project-bot
      password: !env MY_PROJECT_EMAIL_PASSWORD
      from: "My Project Bot <my-project-bot@example.com>"

    authorized_senders:
      - you@example.com

    trusted_authserv_id: mail.example.com

    git:
      repo_url: https://gerrit.example.com/a/my-project

    imap:
      use_idle: true

    # Plain secrets (injected directly into container)
    secrets:
      GERRIT_USER: !env GERRIT_USER

    # Masked secrets (surrogate injected, real value swapped at proxy)
    masked_secrets:
      ANTHROPIC_API_KEY:
        value: !env ANTHROPIC_API_KEY
        scopes:
          - "api.anthropic.com"
          - "statsig.anthropic.com"
        headers:
          - "x-api-key"
          - "Authorization"

      GERRIT_HTTP_PASSWORD:
        value: !env GERRIT_HTTP_PASSWORD
        scopes:
          - "gerrit.example.com"
        headers:
          - "Authorization"
```

The Gerrit HTTP password is a `masked_secret` so the real credential never
reaches the container — the proxy injects it only for requests to the Gerrit
host. The `GERRIT_USER` is a plain secret since usernames are not sensitive.

## CLAUDE.md Adjustments

Gerrit workflows differ from GitHub PRs. Your `CLAUDE.md` should instruct the
agent to push changes for review using Gerrit's `refs/for/` ref syntax rather
than creating pull requests:

```markdown
## Git Workflow

Push changes for review (do NOT use `gh` or create GitHub PRs):

    git push origin HEAD:refs/for/main
```

## Branch Protection

On Gerrit, configure submit rules to require code review:

1. Go to **Projects > your-project > Access**
2. Ensure `refs/heads/main` requires `Code-Review +2` before submit
3. Consider adding verified labels if CI is configured
