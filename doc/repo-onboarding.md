# Repository Onboarding

This guide explains how to onboard a new repository to Airut, enabling
email-based Claude Code interaction.

## Prerequisites

- Airut server deployed (see [deployment.md](deployment.md))
- **Dedicated email account** for the repository (see
  [Dedicated Inbox Requirement](deployment.md#dedicated-inbox-requirement) —
  Airut deletes processed messages)
- Repository access for the agent's GitHub account
- Claude API credentials

## Example Project

The [airut.org website repository](https://github.com/airutorg/website) is a
minimal Airut-managed project. Its `.airut/` directory and `CLAUDE.md` serve as
a practical reference for the steps below.

## Onboarding Steps

### 1. Create `.airut/` Directory

Add the configuration directory to your repository:

```bash
mkdir -p .airut/container
```

### 2. Configure Repo Settings

Create `.airut/airut.yaml`:

```yaml
# Claude model (opus, sonnet, haiku)
default_model: opus

# Max execution time in seconds
timeout: 300

network:
  # Enable network allowlist enforcement
  sandbox_enabled: true

container_env:
  # Claude authentication (required)
  ANTHROPIC_API_KEY: !secret ANTHROPIC_API_KEY

  # GitHub token for git/gh operations (optional, but required for
  # pushing branches, creating PRs, and using gh CLI)
  GH_TOKEN: !secret? GH_TOKEN
```

**YAML tags:**

- `!secret NAME` — Required secret from server pool (error if missing)
- `!secret? NAME` — Optional secret (skip if missing)

### 3. Configure Network Allowlist

Create `.airut/network-allowlist.yaml`:

```yaml
# Domains: all paths and methods allowed
domains:
  - api.anthropic.com

# URL patterns: domain + path + optional method filter
url_prefixes:
  # Claude telemetry and error reporting (POST-only)
  - host: statsig.anthropic.com
    path: ""
    methods: [POST]
  - host: sentry.io
    path: ""
    methods: [POST]

  # Python packages — read-only (if using Python)
  - host: pypi.org
    path: ""
    methods: [GET, HEAD]
  - host: files.pythonhosted.org
    path: ""
    methods: [GET, HEAD]

  # GitHub — restrict to your repository
  - host: github.com
    path: /your-org/your-repo*
    methods: [GET, HEAD, POST]
  - host: api.github.com
    path: /repos/your-org/your-repo*
  - host: api.github.com
    path: /graphql
    methods: [POST]
  - host: uploads.github.com
    path: /repos/your-org/your-repo*
    methods: [POST]
```

Start restrictive and add hosts as needed. The agent will tell you when it
encounters blocked requests.

### 4. Create Container Dockerfile

Create `.airut/container/Dockerfile`. This can be based on an existing
development Dockerfile for your project.

**Key requirements:**

- `claude` must be installed and in PATH (Claude Code CLI)
- `git` should be installed for version control operations
- `gh` (GitHub CLI) is recommended if using GitHub for git authentication and PR
  operations

The Airut server adds an entrypoint overlay — don't define `ENTRYPOINT`.

Example Dockerfile:

```dockerfile
FROM ubuntu:24.04

# System dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI (for git authentication)
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh

# uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Python (if needed)
RUN uv python install 3.13

# Claude Code
RUN mkdir /tmp/claude-install && cd /tmp/claude-install \
    && curl -fsSL https://claude.ai/install.sh | bash \
    && rm -rf /tmp/claude-install

# Git config (optional - example uses gh credential helper)
COPY gitconfig /root/.gitconfig

WORKDIR /workspace
```

If using GitHub with `gh` for authentication, create
`.airut/container/gitconfig`:

```ini
[user]
    name = Your Bot Name
    email = bot@your-domain.com
[credential "https://github.com"]
    helper = !gh auth git-credential
```

See the Airut repository's `.airut/container/` directory for a working example.

### 5. Write CLAUDE.md

Create a `CLAUDE.md` in your repository root with operating instructions for the
agent. The key goal is to instruct the agent to autonomously create PRs after
completing work, enabling the email-to-PR workflow.

See [agentic-operation.md](agentic-operation.md) for detailed guidance on
writing effective agent instructions, including:

- PR creation mandates
- Git workflow instructions
- Spec adherence guidelines
- Workflow tooling recommendations

The Airut repository's own `CLAUDE.md` serves as a reference implementation and
can be used as inspiration.

### 6. Configure Server

Add the repository to your Airut server config (`config/airut.yaml`).

> **Note:** The email account must be dedicated to this repository. Airut treats
> the inbox as a work queue and permanently deletes messages after processing.

```yaml
repos:
  your-repo:
    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: your-repo-bot
      password: !env YOUR_REPO_EMAIL_PASSWORD
      from: "Your Repo Bot <your-repo-bot@example.com>"

    authorized_senders:
      - you@example.com
      - *@your-company.com

    trusted_authserv_id: mail.example.com

    git:
      repo_url: https://github.com/your-org/your-repo.git

    storage_dir: ~/airut-storage/your-repo

    imap:
      use_idle: true

    # Plain secrets (injected directly into container)
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    # Masked secrets (surrogate injected, real value only at proxy for scoped hosts)
    # Prevents credential exfiltration even if container is compromised
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN_YOUR_REPO
        scopes:
          - "api.github.com"
          - "*.githubusercontent.com"
        headers:
          - "Authorization"
```

For credentials that should only be usable with specific services, prefer
`masked_secrets` over `secrets`. Headers use fnmatch patterns (`*` for all). For
AWS credentials, use `signing_credentials` — the proxy re-signs requests instead
of replacing header tokens. See
[network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement) for
masked secrets and
[network-sandbox.md](network-sandbox.md#signing-credentials-aws-sigv4-re-signing)
for signing credentials.

Add secrets to `.env`:

```bash
YOUR_REPO_EMAIL_PASSWORD=password
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN_YOUR_REPO=ghp_...
```

Restart the service:

```bash
systemctl --user restart airut
```

### 7. Set Up Branch Protection

On GitHub, configure branch protection for `main`:

1. Go to Settings → Branches → Add rule
2. Branch name pattern: `main`
3. Enable:
   - Require a pull request before merging
   - Require approvals (1+)
   - Require status checks to pass
4. Save changes

### 8. Test the Setup

Send a test email:

```
To: your-repo-bot@example.com
Subject: Test task

Please verify you can access the repository by listing the files in the
root directory.
```

Expected response:

- Acknowledgment email with dashboard link
- Reply with file listing
- No errors in service logs

## Alternative: Gerrit-Based Repositories

The steps above assume GitHub. If your repository is hosted on a Gerrit code
review server, the same overall flow applies but the authentication, container
setup, and workflow tooling differ. This section walks through the Gerrit-
specific pieces.

### Server-Side: Git Credentials

Airut fetches from configured repositories to maintain git mirrors. For Gerrit,
use HTTP credentials with the git credential store:

```bash
git config --global credential.helper store

# Clone once to store the HTTP credentials (can be removed afterward)
git clone https://gerrit.example.com/a/my-project
```

When prompted, enter your Gerrit username and **HTTP password** (generated under
Settings → HTTP Credentials in the Gerrit web UI). Once credentials are stored,
verify access:

```bash
git ls-remote https://gerrit.example.com/a/my-project
```

Using HTTP credentials (rather than SSH) is recommended because it enables
Airut's masked-secret credential injection — the proxy can swap surrogate tokens
for the real password only when requests target the Gerrit host.

### Repo Settings (`.airut/airut.yaml`)

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

### Network Allowlist

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

### Container Setup

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

### Server Configuration

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

    storage_dir: ~/airut-storage/my-project

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

### CLAUDE.md Adjustments

Gerrit workflows differ from GitHub PRs. Your `CLAUDE.md` should instruct the
agent to push changes for review using Gerrit's `refs/for/` ref syntax rather
than creating pull requests:

```markdown
## Git Workflow

Push changes for review (do NOT use `gh` or create GitHub PRs):

    git push origin HEAD:refs/for/main
```

### Branch Protection

On Gerrit, configure submit rules to require code review:

1. Go to **Projects → your-project → Access**
2. Ensure `refs/heads/main` requires `Code-Review +2` before submit
3. Consider adding verified labels if CI is configured

## Configuration Reference

### `.airut/airut.yaml`

| Field                     | Type   | Default  | Description                  |
| ------------------------- | ------ | -------- | ---------------------------- |
| `default_model`           | string | `"opus"` | Claude model                 |
| `timeout`                 | int    | `300`    | Max execution time (seconds) |
| `network.sandbox_enabled` | bool   | `true`   | Enable network allowlist     |
| `container_env`           | map    | `{}`     | Environment variables        |

### `.airut/network-allowlist.yaml`

```yaml
domains:
  - exact.domain.com           # All paths, all methods
  - "*.wildcard.com"           # Matches subdomains, not bare domain

url_prefixes:
  - host: api.example.com
    path: /allowed/path*
    methods: [GET, POST]       # Optional: restrict HTTP methods
```

### `.airut/container/Dockerfile`

Requirements:

- Claude Code installed (`claude` command available)
- `git` for version control operations
- `gh` CLI recommended for GitHub authentication and PR operations
- Any project-specific dependencies

The Airut server adds an entrypoint overlay — don't define `ENTRYPOINT`.

## Troubleshooting

### Container Build Failures

```bash
# Check service logs
journalctl --user -u airut | grep -i build

# Common issues:
# - Network access blocked during build
# - Missing dependencies in Dockerfile
```

### Network Requests Blocked

1. Check the 403 response for the blocked host
2. Add to `.airut/network-allowlist.yaml`
3. Commit, push, and merge to main
4. Next task will use updated allowlist

### Git Authentication Failures

Verify:

- `GH_TOKEN` has repo access
- Token is passed via `!secret GH_TOKEN`
- `gitconfig` uses `gh auth git-credential`

### Session Not Resuming

Check:

- Conversation ID in subject (`[ID:xyz123]`)
- Session directory exists in storage
- `conversation.json` has valid session ID
