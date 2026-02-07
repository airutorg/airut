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

### 3. Clone Airut

```bash
cd ~
git clone https://github.com/airutorg/airut.git
cd airut
```

### 4. Configure Git Credentials

The Airut server fetches from configured repositories to maintain git mirrors.
The user running the service must have git credentials that allow fetching from
all configured repos.

**Important:** The `GH_TOKEN` and other secrets in `config/airut.yaml` are only
passed to containers — they don't affect the server's git operations.

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
all repos configured in `config/airut.yaml`.

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

Create configuration from the example:

```bash
cp config/airut.example.yaml config/airut.yaml
```

Edit `config/airut.yaml` with your settings. Secrets can be specified inline or
loaded from environment variables. The inline approach keeps everything in one
file:

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

Environment variables can be set in a `.env` file in the repository root, which
is automatically loaded by the service:

```bash
cat > .env << 'EOF'
EMAIL_PASSWORD=your-email-password
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN=ghp_your-github-token
EOF
chmod 600 .env
```

See [Configuration](#configuration) for full details.

**Important:** The target repository must also be configured for Airut. See
[repo-onboarding.md](repo-onboarding.md) for setting up the `.airut/` directory,
container Dockerfile, network allowlist, and `CLAUDE.md` in the target repo.

### 7. Install Services

```bash
uv run scripts/install_services.py
```

This installs and starts:

- `airut.service` — Email gateway service
- `airut-updater.timer` — Auto-updater that pulls from origin when changes are
  detected (see [Auto-Updater](#auto-updater))

Use `--skip-updater` to install without automatic updates:

```bash
uv run scripts/install_services.py --skip-updater
```

To control update frequency, you can clone Airut to a local git server or mirror
repository. The updater pulls from whichever origin the local clone is
configured to track.

### 8. Verify Installation

```bash
# Check service status
systemctl --user status airut

# View logs
journalctl --user -u airut -f
```

## Configuration

### Server Config (`config/airut.yaml`)

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

    storage_dir: ~/airut-storage/my-project

    imap:
      poll_interval: 30
      use_idle: true
      idle_reconnect_interval: 1740

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
```

### Secrets

Secrets can be specified inline in `config/airut.yaml` or loaded from
environment variables using `!env` tags. If using environment variables, they
can be set in a `.env` file in the repository root — automatically loaded by the
service.

Example `.env` file:

```bash
EMAIL_PASSWORD=your-password
ANTHROPIC_API_KEY=sk-ant-...
GH_TOKEN=ghp_...
```

Keep `.env` secure (`chmod 600`). The file is gitignored and should never be
committed.

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

This prevents credential exfiltration — even if the container is compromised,
the attacker only has surrogates that are useless outside scoped hosts. See
[network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement) for
full details.

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
uv run scripts/install_services.py --uninstall
```

### Auto-Updater

The updater timer checks for updates every 5 minutes:

```bash
# View updater logs
journalctl --user -u airut-updater -f

# Check timer status
systemctl --user list-timers
```

When updates are available:

1. Updater acquires lock (waits for busy service to become idle)
2. Pulls latest from `origin/main`
3. Reinstalls services with new code
4. Services restart automatically

### Update Coordination

The service and updater coordinate via `.update.lock`:

- Service holds lock while processing messages
- Updater skips update if lock is held
- Timer retries in 5 minutes

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
# - Missing .env file or secrets
# - Invalid YAML in config/airut.yaml
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
nano ~/airut/.env

# Or update config directly
nano ~/airut/config/airut.yaml

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

If the auto-updater is enabled (default), updates are applied automatically when
changes are detected on `origin/main`.

To trigger an update manually:

```bash
uv run scripts/install_services.py --update
```

This checks for updates and applies them if available. If the auto-updater was
not previously installed (e.g., `--skip-updater` was used), this command will
not install it — it only updates the main service.
