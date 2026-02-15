# Deployment

This guide covers deploying Airut on a fresh Linux VM. The service runs as a
regular user (not root) using systemd user services and rootless Podman.

## Prerequisites

- **Linux VM** (tested on Debian 13)
- **Rootless Podman** (for container execution)
- **Python 3.13+** (via uv)
- **uv** (Python package manager)
- **Git** and **GitHub CLI** (`gh`)
- **Dedicated email account** with IMAP/SMTP access — one per repository (see
  [Email Setup](#email-setup) for details)
- **Git credentials** for fetching configured repositories (see below)

## Installation Steps

### 1. Install System Dependencies

```bash
# Debian
sudo apt update
sudo apt install -y podman git curl

# Install GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
  https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list
sudo apt update && sudo apt install -y gh
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

This installs the latest release from PyPI to `~/.local/bin/airut`.

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

For GitHub repositories, authenticate with `gh`:

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

This creates a stub config at `~/.config/airut/airut.yaml`. You can also check
`config/airut.example.yaml` (in the repository) for a fully documented example.

Edit `~/.config/airut/airut.yaml` with your settings. Secrets can be specified
inline or loaded from environment variables. The inline approach keeps
everything in one file:

```yaml
repos:
  my-project:
    email:
      password: your-email-password  # Inline secret
    secrets:
      ANTHROPIC_API_KEY: sk-ant-...  # Inline secret
      GH_TOKEN: ghp_...
```

Alternatively, use `!env` tags to load secrets from environment variables:

```yaml
repos:
  my-project:
    email:
      password: !env EMAIL_PASSWORD  # From environment
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
```

Environment variables can be set in `~/.config/airut/.env` (next to
`airut.yaml`), which is automatically loaded by the service:

```bash
cat > ~/.config/airut/.env << 'EOF'
EMAIL_PASSWORD=your-email-password
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN=ghp_your-github-token
EOF
chmod 600 ~/.config/airut/.env
```

When running `uv run airut` or `scripts/airut.py` interactively, a `.env` file
in the current working directory is also loaded (after the XDG file). Variables
already set by the XDG `.env` are not overwritten.

See [Configuration](#configuration) for full details.

**Important:** The target repository must also be configured for Airut. See
[repo-onboarding.md](repo-onboarding.md) for setting up the `.airut/` directory,
container Dockerfile, network allowlist, and `CLAUDE.md` in the target repo.

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

This installs and starts `airut.service` — the email gateway service.

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

repos:
  my-project:
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

    git:
      repo_url: https://github.com/your-org/repo.git

    imap:
      poll_interval: 30
      use_idle: true
      idle_reconnect_interval: 1740

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
EMAIL_PASSWORD=your-password
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN=ghp_...
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
          - "api.github.com"
          - "*.githubusercontent.com"
```

Real credentials never enter the container — the proxy inserts them into
upstream requests only for scoped hosts. A compromised container can still act
within scope (make authenticated API calls), but cannot extract credentials for
use outside the container. See
[network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement) for an
overview and [spec/masked-secrets.md](../spec/masked-secrets.md) for the full
specification.

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

The repo config references these with standard `!secret` tags — it doesn't need
to know about signing credentials. See
[network-sandbox.md](network-sandbox.md#signing-credentials-aws-sigv4-re-signing)
for an overview and
[spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) for the full
specification.

## Email Setup

### Dedicated Inbox Requirement

> **⚠️ Warning:** Each repository requires its own dedicated email
> account/inbox. Airut treats the inbox as a work queue — it continuously polls
> for messages, processes every email it finds, and **permanently deletes
> messages** after processing.
>
> **Never point Airut to an inbox used for other purposes** (such as your
> personal email or a shared team inbox). Airut will attempt to process every
> message and delete it.

### DMARC Requirements

Airut authenticates senders using DMARC verification on incoming emails. This
requires:

1. **Your mail server must add `Authentication-Results` headers** — Most mail
   providers (Gmail, Microsoft 365, Fastmail, etc.) do this automatically.

2. **Configure `trusted_authserv_id`** — This must match the server identifier
   in your mail provider's `Authentication-Results` header. Check an email's raw
   headers to find this value.

3. **Sender domains must have DMARC configured** — Emails from domains without
   DMARC records will be rejected.

### Testing Setup

For local testing or development, you have several options:

**Option 1: Gmail with App Password (simplest)**

- Use a Gmail account for IMAP/SMTP
- Generate an App Password (requires 2FA enabled)
- Set `trusted_authserv_id: mx.google.com`
- Limitation: Only works if senders use domains with DMARC (most corporate
  domains and major providers have this)

**Option 2: Fastmail or similar**

- Fastmail, Proton, and similar providers include DMARC verification
- Check their documentation for the correct `trusted_authserv_id`

**Option 3: Self-hosted mail server**

- Requires configuring OpenDMARC or similar
- Most complex option, but gives full control

### Verifying DMARC

To check if a sender's domain has DMARC configured:

```bash
dig +short TXT _dmarc.example.com
```

A valid response indicates DMARC is configured. No response means emails from
that domain cannot be authenticated.

## Microsoft OAuth2 for M365 (IMAP/SMTP)

If your mailbox is hosted on Microsoft 365, you can use OAuth2 instead of
password authentication. See [m365-oauth2.md](m365-oauth2.md) for the complete
step-by-step setup guide (app registration, service principal, mailbox
permissions, Airut configuration, and troubleshooting).

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

Airut is installed via `uv tool install` and updated manually with
`uv tool upgrade`. There is no automatic updater — run the upgrade command when
you want to pull in new changes:

```bash
uv tool upgrade airut
```

The update channel is determined by how the tool was originally installed:

- **Release channel**: `uv tool install airut` — installs from PyPI (tagged
  releases only).
- **Dev channel**:
  `uv tool install airut --from git+https://github.com/airutorg/airut.git` —
  tracks the main branch.

After upgrading, restart the service to pick up the new version:

```bash
systemctl --user restart airut
```

## Dashboard

The dashboard provides task monitoring at `http://localhost:5200`.

### Exposing Externally

For external access, consider:

- **Cloudflare Tunnel** or **Tailscale Funnel** — Zero-config secure tunnels
  without exposing ports
- **Caddy** or **nginx** — Self-hosted reverse proxy with TLS termination

Whichever method you use, add authentication to protect the dashboard.

Set `dashboard.base_url` in config to enable task links in acknowledgment
emails.

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

### IMAP Connection Issues

```bash
# Test IMAP manually
openssl s_client -connect mail.example.com:993

# Check if IDLE is supported
# Look for "IDLE" in CAPABILITY response
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

If the agent gets into a broken state that prevents email-driven recovery (e.g.,
corrupted configuration, broken allowlist, expired tokens), you'll need to
intervene manually via SSH.

### Common Recovery Scenarios

**Network allowlist blocks recovery:**

If the agent accidentally committed a broken `.airut/network-allowlist.yaml`
that prevents GitHub access:

```bash
# SSH into the server
ssh your-server

# Navigate to the git mirror for the affected repo
cd ~/airut-storage/my-project/git-mirror

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
ls ~/airut-storage/my-project/conversations/

# Remove a specific corrupted session
rm -rf ~/airut-storage/my-project/conversations/<session-id>

# Or remove all conversations (forces fresh starts)
rm -rf ~/airut-storage/my-project/conversations/
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

Sessions are garbage-collected automatically, but you can clean up manually:

```bash
# View storage usage
du -sh ~/airut-storage/*/conversations/

# Prune old Podman images
podman image prune -a
```

## Upgrading

```bash
uv tool upgrade airut
systemctl --user restart airut
```

To switch channels, reinstall the tool with `--force`:

```bash
# Switch to release channel (PyPI)
uv tool install airut --force

# Switch to dev channel (main branch)
uv tool install airut --force --from git+https://github.com/airutorg/airut.git
```
