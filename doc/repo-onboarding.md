# Repository Onboarding

This guide explains how to onboard a new repository to Airut, enabling Claude
Code interaction via email and/or Slack.

## Prerequisites

- Airut server deployed (see [deployment.md](deployment.md))
- **At least one channel configured:**
  - **Email**: Dedicated email account (see [email-setup.md](email-setup.md) —
    Airut deletes processed messages)
  - **Slack**: Slack app installed to your workspace (see
    [slack-setup.md](slack-setup.md))
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
  - host: raw.githubusercontent.com
    path: /your-org/your-repo*
    methods: [GET, HEAD]
  - host: objects.githubusercontent.com
    path: /your-org/your-repo*
    methods: [GET, HEAD]
  - host: results-receiver.actions.githubusercontent.com
    path: /rest/runs*
    methods: [GET, POST]
```

Start restrictive and add hosts as needed. The agent will tell you when it
encounters blocked requests.

### 4. Create Container Dockerfile

Create `.airut/container/Dockerfile`. This can be based on an existing
development Dockerfile for your project.

**Key requirements:**

- `claude` must be installed and in PATH (Claude Code CLI)
- `git` should be installed for version control operations

**For GitHub repositories:** Install `gh` (GitHub CLI) in the container and use
the `gh auth git-credential` credential helper. This ensures all git operations
use HTTPS, and authentication is handled by the `GH_TOKEN` environment variable.
Pass `GH_TOKEN` as a
[masked secret](network-sandbox.md#masked-secrets-token-replacement) so the real
token never enters the container — the proxy injects it only for scoped hosts.

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
agent. A well-crafted `CLAUDE.md` enables the message-to-PR workflow — the agent
autonomously creates PRs, follows your project's conventions, and iterates on
review feedback.

See [agentic-operation.md](agentic-operation.md) for detailed guidance on
writing effective agent instructions, including:

- PR creation mandates
- Git workflow instructions
- Spec adherence guidelines
- Workflow tooling recommendations

The Airut repository's own `CLAUDE.md` serves as a reference implementation and
can be used as inspiration.

### 6. Configure Server

Add the repository to your Airut server config (`~/.config/airut/airut.yaml`).
Configure at least one channel (email, Slack, or both).

**Email channel** (see [email-setup.md](email-setup.md) for full guide):

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
      imap:
        use_idle: true

    git:
      repo_url: https://github.com/your-org/your-repo.git

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

**Slack channel** (see [slack-setup.md](slack-setup.md) for full guide):

```yaml
repos:
  your-repo:
    slack:
      bot_token: !env SLACK_BOT_TOKEN
      app_token: !env SLACK_APP_TOKEN
      authorized:
        - workspace_members: true

    git:
      repo_url: https://github.com/your-org/your-repo.git

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN_YOUR_REPO
        scopes:
          - "api.github.com"
          - "*.githubusercontent.com"
        headers:
          - "Authorization"
```

Both channels can coexist — include both `email:` and `slack:` blocks under the
same repo. See [slack-setup.md](slack-setup.md) for the full Slack setup guide.

For credentials that should only be usable with specific services, prefer
`masked_secrets` over `secrets`. Headers use fnmatch patterns (`*` for all). For
AWS credentials, use `signing_credentials` — the proxy re-signs requests instead
of replacing header tokens. See
[network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement) for
masked secrets and
[network-sandbox.md](network-sandbox.md#signing-credentials-aws-sigv4-re-signing)
for signing credentials.

Add secrets to `~/.config/airut/.env`:

```bash
YOUR_REPO_EMAIL_PASSWORD=password
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
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

**Email:** Send a test email:

```
To: your-repo-bot@example.com
Subject: Test task

Please verify you can access the repository by listing the files in the
root directory.
```

Expected: acknowledgment email with dashboard link, then a reply with file
listing.

**Slack:** Open the Airut app in Slack and click the **Chat tab**:

```
Please verify you can access the repository by listing the files in the
root directory.
```

Expected: status indicator ("is getting ready..."), acknowledgment message, then
a reply with file listing and thread title set.

In both cases, check the service logs for errors:

```bash
journalctl --user -u airut -f
```

## Alternative: Gerrit-Based Repositories

For Gerrit repositories, see [gerrit-onboarding.md](gerrit-onboarding.md) for
the complete guide covering HTTP credentials, credential helper setup, container
configuration, and Gerrit-specific workflow instructions.

## Configuration Reference

See [spec/repo-config.md](../spec/repo-config.md) for the full
`.airut/airut.yaml` schema and [network-sandbox.md](network-sandbox.md) for the
network allowlist format.

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

- **Email**: Conversation ID in subject (`[ID:xyz123]`)
- **Slack**: Thread-to-conversation mapping in `slack_threads.json`
- Session directory exists in storage
- `conversation.json` has valid session ID
