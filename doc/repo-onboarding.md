# Repository Onboarding

This guide explains how to onboard a new repository to Airut, enabling Claude
Code interaction via email and/or Slack.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Prerequisites](#prerequisites)
- [Example Project](#example-project)
- [Onboarding Steps](#onboarding-steps)
  - [1. Create `.airut/` Directory](#1-create-airut-directory)
  - [2. Configure Network Allowlist](#2-configure-network-allowlist)
  - [3. Create Container Dockerfile](#3-create-container-dockerfile)
  - [4. Write CLAUDE.md](#4-write-claudemd)
  - [5. Configure Server](#5-configure-server)
    - [Using the Config Editor (Recommended)](#using-the-config-editor-recommended)
    - [Manual Configuration (Alternative)](#manual-configuration-alternative)
  - [6. Set Up Branch Protection](#6-set-up-branch-protection)
  - [7. Set Up CI Sandbox (Recommended)](#7-set-up-ci-sandbox-recommended)
  - [8. Test the Setup](#8-test-the-setup)
- [Alternative: Gerrit-Based Repositories](#alternative-gerrit-based-repositories)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
  - [Container Build Failures](#container-build-failures)
  - [Network Requests Blocked](#network-requests-blocked)
  - [Git Authentication Failures](#git-authentication-failures)
  - [Session Not Resuming](#session-not-resuming)

<!-- mdformat-toc end -->

## Prerequisites

- Airut server deployed (see [deployment.md](deployment.md))
- **At least one channel configured:**
  - **Email**: Dedicated email account (see [email-setup.md](email-setup.md) —
    Airut deletes processed messages)
  - **Slack**: Slack app installed to your workspace (see
    [slack-setup.md](slack-setup.md))
- **GitHub authentication** for the agent: either a GitHub App (recommended) or
  a dedicated machine user with a classic PAT. See
  [deployment.md](deployment.md#github-app-recommended) for setup options. If
  using a PAT, it should **not** include the `workflow` scope -- see
  [ci-sandbox.md](ci-sandbox.md#1-protecting-workflow-files)
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

### 2. Configure Network Allowlist

Create `.airut/network-allowlist.yaml`:

```yaml
# URL patterns: domain + path + optional method filter
url_prefixes:
  # Anthropic API — path-restricted to prevent exfiltration via /v1/files
  # (attacker can use their own API key to upload/fetch material)
  - host: api.anthropic.com
    path: /v1/messages*
    methods: [POST]
  - host: api.anthropic.com
    path: /api/oauth/*
    methods: [GET]
  - host: api.anthropic.com
    path: /api/event_logging/*
    methods: [POST]
  - host: api.anthropic.com
    path: /api/eval/*
    methods: [POST]
  - host: api.anthropic.com
    path: /api/claude_code_*
    methods: [GET]

  # Claude telemetry and error reporting (POST-only)
  - host: statsig.anthropic.com
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

### 3. Create Container Dockerfile

Create `.airut/container/Dockerfile`. This can be based on an existing
development Dockerfile for your project.

**Using an existing Dockerfile:** If your repository already has a Dockerfile
(e.g., in `.devcontainer/`), you can point Airut at it instead of creating a new
one. Set `container_path` in the server config to the directory containing the
Dockerfile:

```yaml
repos:
  my-project:
    container_path: .devcontainer   # use existing devcontainer Dockerfile
```

This works with any directory that contains a `Dockerfile` and optional context
files. Note that Airut reads only the `Dockerfile` and sibling files — it does
not parse `devcontainer.json` features, lifecycle scripts, or pre-built image
references.

**Key requirements:**

- `git` should be installed for version control operations
- The Claude Code binary does **not** need to be installed in the image — Airut
  downloads and caches it on the host, then bind-mounts it read-only into each
  container at `/opt/claude/claude`. The version is controlled by the
  `claude_version` per-repo config field.

**For GitHub repositories:** Install `gh` (GitHub CLI) in the container and use
the `gh auth git-credential` credential helper. This ensures all git operations
use HTTPS, and authentication is handled by the `GH_TOKEN` environment variable.
Pass `GH_TOKEN` as a
[GitHub App credential](network-sandbox.md#github-app-credentials-proxy-managed-token-rotation)
(recommended) or
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

# Claude Code binary is bind-mounted by Airut at /opt/claude/claude.
# No need to install it in the image.

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

### 4. Write CLAUDE.md

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

### 5. Configure Server

Add the repository to your Airut server configuration. Configure at least one
channel (email, Slack, or both). All per-repo settings (model, effort, resource
limits, secrets, network sandbox) are configured here.

#### Using the Config Editor (Recommended)

Open the dashboard at `http://localhost:5200` and click **Configure**. Under the
**Repositories** section, click **Add Repository** and fill in:

1. **`repos.<repo>.repo_url`** — your repository URL (e.g.,
   `https://github.com/your-org/your-repo.git`)
2. **Channel settings** — click **Add Email Channel** or **Add Slack Channel**
   to configure at least one channel:
   - **Email**: Set the email channel fields under `repos.<repo>.email`:
     `imap.server`, `smtp.server`, `account.username`, `account.password`,
     `account.from`, `auth.authorized_senders`, and `auth.trusted_authserv_id`.
     See [email-setup.md](email-setup.md) for details on each field. The email
     account must be dedicated to this repository — Airut permanently deletes
     messages after processing.
   - **Slack**: Set the Slack channel fields under `repos.<repo>.slack`:
     `bot_token`, `app_token`, and `authorized` rules. See
     [slack-setup.md](slack-setup.md) for details.
3. **Credentials** — under the repo's **Credentials** section:
   - Add `ANTHROPIC_API_KEY` as a plain secret
     (`repos.<repo>.secrets.ANTHROPIC_API_KEY`)
   - Add `GH_TOKEN` as a GitHub App credential (recommended) or masked secret.
     See [github-app-setup.md](github-app-setup.md) for the GitHub App setup
     guide.

For secrets, use the **Environment** source type on each field to reference
variables from `~/.config/airut/.env` (e.g., set the source to
`!env ANTHROPIC_API_KEY`). This keeps sensitive values out of the config file.

Click **Review & Save** to preview changes and apply. The config is saved to
`~/.config/airut/airut.yaml` and reloaded automatically — no service restart
needed.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://screenshots.airut.org/config-repo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://screenshots.airut.org/config-repo-light.png">
    <img src="https://screenshots.airut.org/config-repo-light.png" alt="Config editor — repository settings" width="640">
  </picture>
</p>

#### Manual Configuration (Alternative)

You can also edit `~/.config/airut/airut.yaml` directly. The YAML field paths
match the labels shown in the config editor.

**Email channel** (see [email-setup.md](email-setup.md) for full guide):

> **Note:** The email account must be dedicated to this repository. Airut treats
> the inbox as a work queue and permanently deletes messages after processing.

```yaml
repos:
  your-repo:
    email:
      account:
        username: your-repo-bot
        password: !env YOUR_REPO_EMAIL_PASSWORD
        from: "Your Repo Bot <your-repo-bot@example.com>"
      imap:
        server: mail.example.com
        port: 993
        use_idle: true
      smtp:
        server: mail.example.com
        port: 587
      auth:
        authorized_senders:
          - you@example.com
          - *@your-company.com
        trusted_authserv_id: mail.example.com

    git:
      repo_url: https://github.com/your-org/your-repo.git

    # Plain secrets (injected directly into container)
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    # GitHub App credentials (recommended) — proxy manages short-lived tokens
    github_app_credentials:
      GH_TOKEN:
        app_id: !env GH_APP_ID
        private_key: !env GH_APP_PRIVATE_KEY
        installation_id: !env GH_APP_INSTALLATION_ID
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
```

If using a classic PAT instead of a GitHub App, use `masked_secrets`:

```yaml
    # Alternative: masked secrets with classic PAT
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN_YOUR_REPO
        scopes:
          - "github.com"
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

    # GitHub App credentials (recommended)
    github_app_credentials:
      GH_TOKEN:
        app_id: !env GH_APP_ID
        private_key: !env GH_APP_PRIVATE_KEY
        installation_id: !env GH_APP_INSTALLATION_ID
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
```

Both channels can coexist — include both `email:` and `slack:` blocks under the
same repo. See [slack-setup.md](slack-setup.md) for the full Slack setup guide.

For GitHub API access, prefer `github_app_credentials` (short-lived tokens,
automatic rotation) over `masked_secrets` with a classic PAT. See
[github-app-setup.md](github-app-setup.md) for the full setup guide. For other
credentials that should only be usable with specific services, use
`masked_secrets`. For AWS credentials, use `signing_credentials`. See
[network-sandbox.md](network-sandbox.md) for details on all credential types.

Add secrets to `~/.config/airut/.env`:

```bash
YOUR_REPO_EMAIL_PASSWORD=password
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
ANTHROPIC_API_KEY=sk-ant-...
# GitHub App credentials (recommended)
GH_APP_ID=Iv23liXXXXXXXXXX
GH_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"
GH_APP_INSTALLATION_ID=12345678
# Or classic PAT (alternative)
# GH_TOKEN_YOUR_REPO=ghp_...
```

If editing YAML directly, restart the service to pick up changes (or rely on the
file watcher for automatic reload):

```bash
systemctl --user restart airut
```

### 6. Set Up Branch Protection

On GitHub, configure branch protection for `main`:

1. Go to Settings → Branches → Add rule
2. Branch name pattern: `main`
3. Enable:
   - Require a pull request before merging
   - Require approvals (1+)
   - Require status checks to pass
4. Save changes

### 7. Set Up CI Sandbox (Recommended)

If the repository uses GitHub Actions for CI, configure
[`airutorg/sandbox-action`](ci-sandbox.md) to run CI commands inside the Airut
sandbox. This prevents the agent from escaping containment via CI workflows --
test suites, build scripts, and linters run inside the same container isolation
and network sandbox that the Airut gateway uses.

**Quick setup:**

1. Add `.airut/sandbox.yaml` to your repository (optional -- defaults work for
   CI that needs no credentials):

   ```yaml
   env:
     CI: "true"
   network_sandbox: true
   ```

2. Create `.github/workflows/ci.yml`:

   ```yaml
   name: CI
   on:
     pull_request:
       branches: [main]

   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: airutorg/sandbox-action@v0
           with:
             command: '<your CI command>'
             pr_sha: ${{ github.event.pull_request.head.sha }}
   ```

3. Ensure the agent cannot modify workflow files: use a GitHub App without
   `Workflows` permission, omit the `workflow` scope from a classic PAT, or add
   a repository ruleset blocking `.github/workflows/**` changes. See
   [ci-sandbox.md](ci-sandbox.md#1-protecting-workflow-files).

This is the recommended configuration. Without CI sandboxing, auto-triggered
workflows that execute repository code (which most CI workflows do) allow the
agent to run unsandboxed code on GitHub Actions runners. See
[ci-sandbox.md](ci-sandbox.md) for the full guide and security requirements.

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

See [spec/repo-config.md](../spec/repo-config.md) for the full per-repo schema
in the server config and [network-sandbox.md](network-sandbox.md) for the
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

- `GH_TOKEN` is configured in the server config — via `github_app_credentials`
  (recommended) or `masked_secrets` with a classic PAT
- `gitconfig` uses `gh auth git-credential`
- If using a GitHub App, check that the app is installed on the target
  repository

### Session Not Resuming

Check:

- **Email**: Conversation ID in subject (`[ID:xyz123]`)
- **Slack**: Thread-to-conversation mapping in `slack_threads.json`
- Session directory exists in storage
- `conversation.json` has valid session ID
