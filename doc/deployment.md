# Deployment

This guide covers deploying Airut on a fresh Linux VM. The service runs as a
regular user (not root) using systemd user services and rootless Podman.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Prerequisites](#prerequisites)
- [Installation Steps](#installation-steps)
  - [1. Install System Dependencies](#1-install-system-dependencies)
  - [2. Install uv](#2-install-uv)
  - [3. Install Airut](#3-install-airut)
  - [4. Configure Git Credentials](#4-configure-git-credentials)
    - [GitHub App (Recommended)](#github-app-recommended)
    - [Alternative: Dedicated Machine User with Classic PAT](#alternative-dedicated-machine-user-with-classic-pat)
  - [5. Enable Linger](#5-enable-linger)
  - [6. Configure Airut](#6-configure-airut)
  - [7. Validate Configuration](#7-validate-configuration)
  - [8. Install Services](#8-install-services)
  - [9. Verify Installation](#9-verify-installation)
- [Configuration](#configuration)
  - [Server Config (`~/.config/airut/airut.yaml`)](#server-config-configairutairutyaml)
  - [Secrets](#secrets)
  - [Masked Secrets](#masked-secrets)
  - [Signing Credentials (AWS)](#signing-credentials-aws)
  - [GitHub App Credentials](#github-app-credentials)
- [Channel Setup](#channel-setup)
  - [Email](#email)
  - [Slack](#slack)
- [Service Management](#service-management)
  - [Commands](#commands)
  - [Updating](#updating)
- [Dashboard](#dashboard)
  - [Exposing Externally](#exposing-externally)
- [Troubleshooting](#troubleshooting)
  - [Service Won't Start](#service-wont-start)
  - [Git Mirror Failures](#git-mirror-failures)
  - [Container Build Failures](#container-build-failures)
  - [Network Sandbox Issues](#network-sandbox-issues)
  - [Linger Not Enabled](#linger-not-enabled)
- [Emergency Recovery (Break Glass)](#emergency-recovery-break-glass)
  - [Common Recovery Scenarios](#common-recovery-scenarios)
  - [Prevention](#prevention)
- [Storage Cleanup](#storage-cleanup)
- [Upgrading](#upgrading)

<!-- mdformat-toc end -->

## Prerequisites

- **Linux** (dedicated VM recommended, Debian 13 tested)
- **[uv](https://docs.astral.sh/uv/)**, **Git**, and **Podman** (rootless)
- **At least one channel** per repository:
  - **Email**: Dedicated email account with IMAP/SMTP access — one per
    repository (see [email-setup.md](email-setup.md))
  - **Slack**: Slack workspace with app installation permissions (see
    [slack-setup.md](slack-setup.md))
- **Git credentials** for fetching configured repositories (see below)

## Installation Steps

### 1. Install System Dependencies

```bash
# Debian
sudo apt update
sudo apt install -y podman git curl
```

### 2. Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc  # or restart shell
```

### 3. Install Airut

```bash
uv tool install airut
```

This installs the latest release from PyPI to `~/.local/bin/airut`. The package
also provides the `airut-sandbox` CLI for running commands in the sandbox from
CI pipelines (see [ci-sandbox.md](ci-sandbox.md)).

To install from the main branch (latest development version):

```bash
uv tool install airut --from git+https://github.com/airutorg/airut.git
```

For development, you can also run from a local clone using `uv run airut`.

### 4. Configure Git Credentials

The Airut server fetches from configured repositories to maintain git mirrors.
The user running the service must have git credentials that allow fetching from
all configured repos.

**Important:** The `GH_TOKEN` and other secrets in `~/.config/airut/airut.yaml`
are only passed to containers — they don't affect the server's git operations.

For GitHub repositories, the recommended approach is to install
[GitHub CLI](https://cli.github.com/) (`gh`) and authenticate:

```bash
gh auth login
```

This stores credentials that `git` will use via the credential helper. Verify
access:

```bash
git ls-remote https://github.com/your-org/your-repo.git
```

For private repositories, ensure the authenticated account has read access to
all repos configured in `~/.config/airut/airut.yaml`.

#### GitHub App (Recommended)

A GitHub App provides the agent with a dedicated bot identity, short-lived
tokens, and fine-grained permissions -- without consuming an organization seat.
This is the recommended approach for new deployments.

See [github-app-setup.md](github-app-setup.md) for the full step-by-step guide
covering app creation, permissions, private key generation, installation, and
Airut configuration.

**Key advantages over a classic PAT:**

- Short-lived tokens (1 hour, auto-rotated by proxy) instead of long-lived PATs
- Cannot create repositories (eliminates a data exfiltration vector)
- Granular permissions (e.g., `Contents` without `Workflows`)
- No dedicated user account needed (no seat consumed)

#### Alternative: Dedicated Machine User with Classic PAT

If you cannot create a GitHub App (e.g., insufficient org permissions), create a
dedicated machine user account (e.g., `your-org-airut-bot`) with a classic PAT.

**Setup:**

1. Create a new GitHub account for the agent
2. Grant the account **collaborator access** to only the repositories the agent
   will operate on (write access for pushing branches and creating PRs)
3. Generate a **classic personal access token** for this account:
   - Grant the **`repo`** scope. For organization-owned repositories, also grant
     **`read:org`** — without it, `gh pr edit` and other GraphQL-based
     operations fail because the GitHub API requires organization read access to
     resolve org context. **Do not enable the `workflow` scope** — omitting it
     prevents the agent from modifying `.github/workflows/` files, blocking a
     [sandbox escape vector](security.md#github-actions-workflow-escape).
     Existing classic PATs may have `workflow` enabled by default — audit at
     GitHub → Settings → Developer settings → Personal access tokens. On
     Teams/Enterprise plans, a
     [push ruleset](ci-sandbox.md#1-protecting-workflow-files) can additionally
     block workflow file changes.
   - **Why not fine-grained PATs?** Fine-grained PATs can only access
     repositories owned by the token's account. Since the dedicated bot account
     is a **collaborator** on target repositories (not the owner), fine-grained
     PATs cannot be used to grant access to those repositories.
4. Use this token as the `GH_TOKEN` in your server configuration (as a
   [masked secret](network-sandbox.md#masked-secrets-token-replacement) to
   prevent exfiltration)

**Limitation:** Classic PATs cannot prevent repository creation. Even with the
network allowlist restricting which hosts the agent can push to, the agent could
create public repositories via the GraphQL endpoint and leak limited information
through repository names or descriptions. GitHub Apps eliminate this risk
entirely.

The server's own git credentials (for fetching mirrors) can use a separate
account or the same bot account with read access.

**For Gerrit repositories**, use HTTP credentials with the git credential store
instead of `gh`:

```bash
git config --global credential.helper store

# Clone once to store credentials (can be removed afterward)
git clone https://gerrit.example.com/a/my-project
```

When prompted, enter your Gerrit username and HTTP password (generated under
Settings → HTTP Credentials in the Gerrit web UI). Verify access:

```bash
git ls-remote https://gerrit.example.com/a/my-project
```

See
[repo-onboarding.md](repo-onboarding.md#alternative-gerrit-based-repositories)
for the full Gerrit setup including container credential helpers and masked
secrets configuration.

### 5. Enable Linger

Systemd user services require linger to run without an active login session:

```bash
sudo loginctl enable-linger $USER
```

### 6. Configure Airut

Create an initial configuration using the `init` command:

```bash
airut init
```

This creates a stub config at `~/.config/airut/airut.yaml`. For all available
options, see the
[documented example](https://github.com/airutorg/airut/blob/main/config/airut.example.yaml).

Edit `~/.config/airut/airut.yaml` with your settings. Secrets can be specified
inline or loaded from environment variables. The inline approach keeps
everything in one file:

```yaml
repos:
  my-project:
    secrets:
      ANTHROPIC_API_KEY: sk-ant-...  # Inline secret
      GH_TOKEN: ghp_...
    email:
      password: your-email-password  # Inline secret
    slack:
      bot_token: xoxb-...
      app_token: xapp-...
```

Alternatively, use `!env` tags to load secrets from environment variables:

```yaml
repos:
  my-project:
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
    email:
      password: !env EMAIL_PASSWORD  # From environment
    slack:
      bot_token: !env SLACK_BOT_TOKEN
      app_token: !env SLACK_APP_TOKEN
```

Environment variables can be set in `~/.config/airut/.env` (next to
`airut.yaml`), which is automatically loaded by the service:

```bash
cat > ~/.config/airut/.env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN=ghp_your-github-token
EMAIL_PASSWORD=your-email-password   # If using email channel
SLACK_BOT_TOKEN=xoxb-...            # If using Slack channel
SLACK_APP_TOKEN=xapp-...
EOF
chmod 600 ~/.config/airut/.env
```

When running `airut` interactively, a `.env` file in the current working
directory is also loaded (after the XDG file). Variables already set by the XDG
`.env` are not overwritten.

See [Configuration](#configuration) for full details.

**Important:** The target repository must also be configured for Airut. See
[repo-onboarding.md](repo-onboarding.md) for setting up the `.airut/` directory,
`CLAUDE.md`, and the message-to-PR workflow in the target repo.

### 7. Validate Configuration

```bash
airut check
```

This verifies the config file can be parsed and that required system
dependencies (git, podman) are installed and meet minimum version requirements.

### 8. Install Services

```bash
airut install-service
```

This installs and starts `airut.service` — the gateway service.

### 9. Verify Installation

```bash
# Check service status
systemctl --user status airut

# View logs
journalctl --user -u airut -f
```

## Configuration

### Server Config (`~/.config/airut/airut.yaml`)

The server config uses a **multi-repo structure** where each repository is
configured under the `repos:` mapping. This is the only supported format — there
is no "flat" single-repo configuration.

```yaml
execution:
  max_concurrent: 3          # Parallel task limit
  shutdown_timeout: 60       # Graceful shutdown wait
  conversation_max_age_days: 7

dashboard:
  enabled: true
  host: 127.0.0.1            # Localhost only
  port: 5200
  base_url: dashboard.example.com  # For email links

container_command: podman    # or docker

# Server-wide resource limit defaults (all optional).
# Per-repo values override these. Omitted fields mean no default.
# resource_limits:
#   timeout: 7200       # Default timeout (seconds)
#   memory: "8g"        # Default memory limit
#   cpus: 4             # Default CPU limit
#   pids_limit: 1024    # Default process limit

repos:
  my-project:
    # Channel configuration (at least one required)
    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: airut
      password: !env EMAIL_PASSWORD
      from: "Airut <airut@example.com>"
      authorized_senders:
        - you@example.com
      trusted_authserv_id: mail.example.com
      imap:
        poll_interval: 30
        use_idle: true
        idle_reconnect_interval: 1740

    slack:
      bot_token: !env SLACK_BOT_TOKEN
      app_token: !env SLACK_APP_TOKEN
      authorized:
        - workspace_members: true

    git:
      repo_url: https://github.com/your-org/repo.git

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
```

### Secrets

Secrets can be specified inline in `~/.config/airut/airut.yaml` or loaded from
environment variables using `!env` tags. If using environment variables, set
them in `~/.config/airut/.env` — automatically loaded by the service.

Example `~/.config/airut/.env` file:

```bash
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN=ghp_...
EMAIL_PASSWORD=your-password       # If using email channel
SLACK_BOT_TOKEN=xoxb-...          # If using Slack channel
SLACK_APP_TOKEN=xapp-...
```

Keep `.env` secure (`chmod 600`). The file should never be committed to version
control.

The service also loads `.env` from the current working directory (if present),
so you can provide per-invocation overrides when running interactively.

### Masked Secrets

For credentials that should only be usable with specific services, use
`masked_secrets` instead of plain `secrets`. The container receives a surrogate
token; the proxy swaps it for the real value only when the request host matches
the scopes.

```yaml
repos:
  my-project:
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY  # Plain (body tokens)

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
```

Real credentials never enter the container. See
[network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement) for
the security model and [spec/masked-secrets.md](../spec/masked-secrets.md) for
the full specification.

### Signing Credentials (AWS)

For AWS credentials (or any S3-compatible API), use `signing_credentials`
instead of plain `secrets`. The container receives surrogate credentials; the
proxy re-signs requests with the real credentials when the host matches scopes.

```yaml
repos:
  my-project:
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY  # Plain (not AWS)

    signing_credentials:
      AWS_PROD:
        type: aws-sigv4
        access_key_id:
          name: AWS_ACCESS_KEY_ID
          value: !env AWS_ACCESS_KEY_ID
        secret_access_key:
          name: AWS_SECRET_ACCESS_KEY
          value: !env AWS_SECRET_ACCESS_KEY
        session_token:                           # optional
          name: AWS_SESSION_TOKEN
          value: !env AWS_SESSION_TOKEN
        scopes:
          - "*.amazonaws.com"
```

Credential keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`) are auto-injected into the container as environment
variables. The container receives surrogate values; the proxy re-signs requests
with the real credentials when the host matches scopes. See
[network-sandbox.md](network-sandbox.md#signing-credentials-aws-sigv4-re-signing)
for an overview and
[spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) for the full
specification.

### GitHub App Credentials

For GitHub API access, `github_app_credentials` is the recommended alternative
to `masked_secrets`. The proxy manages the full token lifecycle — generating
short-lived installation tokens from a GitHub App private key, rotating them
automatically, and replacing the container's surrogate token transparently.

```yaml
repos:
  my-project:
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY  # Plain (body tokens)

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

Real credentials never enter the container — installation tokens are short-lived
(1 hour) and auto-rotated. See [github-app-setup.md](github-app-setup.md) for
the full setup guide and
[network-sandbox.md](network-sandbox.md#github-app-credentials-proxy-managed-token-rotation)
for the security model.

## Channel Setup

Each repository needs at least one channel configured. Both can run
simultaneously for the same repo — include both `email:` and `slack:` blocks to
enable dual-channel operation.

### Email

Email uses IMAP/SMTP with DMARC-based sender verification. Each repository
requires a dedicated email account (Airut deletes messages after processing).

See [email-setup.md](email-setup.md) for the complete setup guide covering
provider selection, DMARC configuration, authorization, and troubleshooting.

**Quick reference** — add the `email:` block to your server config:

```yaml
repos:
  my-project:
    email:
      imap_server: mail.example.com
      smtp_server: mail.example.com
      username: airut
      password: !env EMAIL_PASSWORD
      from: "Airut <airut@example.com>"
      authorized_senders:
        - you@example.com
      trusted_authserv_id: mail.example.com

    git:
      repo_url: https://github.com/your-org/repo.git
```

For Microsoft 365 with OAuth2, see [m365-oauth2.md](m365-oauth2.md).

### Slack

Slack uses Socket Mode (outbound WebSocket) — no inbound endpoints, public DNS,
or TLS certificates needed. Each repository gets its own Slack app.

See [slack-setup.md](slack-setup.md) for the complete setup guide covering app
creation, token generation, authorization rules, and troubleshooting.

**Quick reference** — add the `slack:` block to your server config:

```yaml
repos:
  my-project:
    slack:
      bot_token: !env SLACK_BOT_TOKEN
      app_token: !env SLACK_APP_TOKEN
      authorized:
        - workspace_members: true

    git:
      repo_url: https://github.com/your-org/repo.git
```

## Service Management

### Commands

```bash
# View status
systemctl --user status airut

# View logs (follow)
journalctl --user -u airut -f

# Restart service
systemctl --user restart airut

# Stop service
systemctl --user stop airut

# Uninstall all services
airut uninstall-service
```

### Updating

Use the built-in update command to upgrade airut. It handles stopping the
service, applying the upgrade, and restarting the service automatically:

```bash
airut update
```

If already up to date, the command exits without touching the service. When an
upgrade is applied and the systemd service is installed, `airut update` will:

1. Run `uv tool upgrade airut`
2. Stop and uninstall the service
3. Reinstall and start the service using the updated binary

If the service is not installed, only the upgrade step is performed. See
[spec/cli.md](../spec/cli.md) for the full update workflow including task
blocking (`--wait`, `--force`).

The update channel is determined by how the tool was originally installed:

- **Release channel**: `uv tool install airut` — installs from PyPI (tagged
  releases only).
- **Dev channel**:
  `uv tool install airut --from git+https://github.com/airutorg/airut.git` —
  tracks the main branch.

## Dashboard

The dashboard provides task monitoring at `http://localhost:5200`.

### Exposing Externally

For external access, consider:

- **Cloudflare Tunnel** or **Tailscale Funnel** — Zero-config secure tunnels
  without exposing ports
- **Caddy** or **nginx** — Self-hosted reverse proxy with TLS termination

Whichever method you use, add authentication to protect the dashboard.

Set `dashboard.base_url` in config to enable task links in acknowledgment
messages.

## Troubleshooting

### Service Won't Start

```bash
# Check for configuration errors
journalctl --user -u airut -n 50

# Common issues:
# - Missing ~/.config/airut/.env or secrets
# - Invalid YAML in ~/.config/airut/airut.yaml
# - Podman not installed or not rootless
```

### Git Mirror Failures

```bash
# Symptom: "Authentication failed" or "Repository not found" in logs
# The server user needs git credentials to fetch from configured repos

# Verify credentials work
git ls-remote https://github.com/your-org/your-repo.git

# Re-authenticate if needed
gh auth login
```

The `GH_TOKEN` in config only affects containers, not the server's git
operations.

### Container Build Failures

```bash
# Check Podman works
podman run --rm hello-world

# View build logs in service output
journalctl --user -u airut | grep -i build
```

### Network Sandbox Issues

```bash
# Check egress network exists
podman network ls | grep airut

# View proxy logs (during task execution)
podman logs airut-proxy-<task-id>
```

### Linger Not Enabled

```bash
# Symptom: Services stop when you log out
# Fix:
sudo loginctl enable-linger $USER
```

## Emergency Recovery (Break Glass)

If the agent gets into a broken state that prevents channel-driven recovery
(e.g., corrupted configuration, broken allowlist, expired tokens), you'll need
to intervene manually via SSH.

### Common Recovery Scenarios

**Network allowlist blocks recovery:**

If the agent accidentally committed a broken `.airut/network-allowlist.yaml`
that prevents GitHub access:

```bash
# SSH into the server
ssh your-server

# Navigate to the git mirror for the affected repo
cd ~/.local/state/airut/my-project/git-mirror

# Reset to a known-good state (find the commit hash)
git fetch origin
git log --oneline origin/main  # Find last good commit
git reset --hard <good-commit-hash>

# Or fix the file directly and push from your local machine
```

**Service stuck or unresponsive:**

```bash
# Check service status
systemctl --user status airut
journalctl --user -u airut -n 100

# Restart service
systemctl --user restart airut

# If stuck on a specific task, check running containers
podman ps
podman kill <container-id>
```

**Corrupted session state:**

```bash
# List conversations for a repo
ls ~/.local/state/airut/my-project/conversations/

# Remove a specific corrupted session
rm -rf ~/.local/state/airut/my-project/conversations/<session-id>

# Or remove all conversations (forces fresh starts)
rm -rf ~/.local/state/airut/my-project/conversations/
```

**Token expired or credentials invalid:**

```bash
# Update credentials in .env
nano ~/.config/airut/.env

# Or update config directly
nano ~/.config/airut/airut.yaml

# Restart service to pick up changes
systemctl --user restart airut
```

### Prevention

- Keep the network allowlist conservative — don't remove `github.com` or
  `api.github.com`
- Test configuration changes locally before deploying
- Monitor the dashboard and service logs for early warning signs

## Storage Cleanup

Sessions and container images are garbage-collected automatically every 24 hours
(first pass runs 60 seconds after startup). Image pruning is controlled by
`execution.image_prune` (default `true`).

You can also clean up manually:

```bash
# View storage usage
du -sh ~/.local/state/airut/*/conversations/

# Prune old Podman images
podman image prune -a
```

## Upgrading

```bash
airut update
```

To switch channels, reinstall the tool with `--force`:

```bash
# Switch to release channel (PyPI)
uv tool install airut --force

# Switch to dev channel (main branch)
uv tool install airut --force --from git+https://github.com/airutorg/airut.git
```
