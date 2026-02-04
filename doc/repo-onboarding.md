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
# Domains: all paths allowed
domains:
  # Claude API
  - api.anthropic.com
  - statsig.anthropic.com
  - sentry.io

  # Python packages (if using Python)
  - pypi.org
  - files.pythonhosted.org

# URL patterns: specific paths only
url_prefixes:
  # GitHub - restrict to your repository
  - host: github.com
    path: /your-org/your-repo*
  - host: api.github.com
    path: /repos/your-org/your-repo*
  - host: api.github.com
    path: /graphql
  - host: uploads.github.com
    path: /repos/your-org/your-repo*
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

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN_YOUR_REPO
```

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
  - exact.domain.com
  - "*.wildcard.com"    # Matches subdomains, not bare domain

url_prefixes:
  - host: api.example.com
    path: /allowed/path*
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
- `session.json` has valid session ID
