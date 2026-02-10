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
- `airut-updater.timer` — Auto-updater (default: checks for new tagged releases
  every 6 hours). Use `--channel dev` to track `origin/main` instead. See
  [Auto-Updater](#auto-updater) for details.

Use `--skip-updater` to install without automatic updates:

```bash
uv run scripts/install_services.py --skip-updater
```

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

## Microsoft OAuth2 for M365 (IMAP/SMTP)

If your mailbox is hosted on Microsoft 365 (Exchange Online), you can use OAuth2
instead of password authentication. This is required for organizations that have
disabled Basic Authentication, and Microsoft is enforcing this for SMTP AUTH
starting
[April 30, 2026](https://techcommunity.microsoft.com/blog/exchange/exchange-online-to-retire-basic-auth-for-client-submission-smtp-auth/4114750).

Airut uses the **OAuth2 Client Credentials flow** with the XOAUTH2 SASL
mechanism. This authenticates as a service principal (application identity)
rather than a user, which is the correct approach for headless/daemon services.

### Prerequisites

- **Global Admin** (or Application Administrator + Exchange Administrator)
  access to your Microsoft 365 tenant
- **PowerShell** with the
  [ExchangeOnlineManagement](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
  module for Exchange configuration
- A dedicated mailbox for Airut (see
  [Dedicated Inbox Requirement](#dedicated-inbox-requirement))

### Step 1: Register the Application in Entra ID (Azure AD)

1. Go to the [Microsoft Entra admin center](https://entra.microsoft.com/) >
   **App registrations** > **New registration**
2. Name it (e.g., `airut-email-service`), leave the redirect URI empty
3. Note the **Application (client) ID** and **Directory (tenant) ID** from the
   overview page

### Step 2: Create a Client Secret

1. In your app registration, go to **Certificates & secrets** > **New client
   secret**
2. Set a description and expiry (e.g., 24 months)
3. **Copy the secret `Value` immediately** — it is only shown once

### Step 3: Add API Permissions

1. Go to **API permissions** > **Add a permission**
2. Select the **APIs my organization uses** tab
3. Search for **Office 365 Exchange Online** (not Microsoft Graph)
4. Select **Application permissions**
5. Add both:
   - **`IMAP.AccessAsApp`** — for reading the inbox
   - **`SMTP.SendAsApp`** — for sending replies
6. Click **Grant admin consent for [Your Organization]**

### Step 4: Register the Service Principal in Exchange Online

This is the step most people miss. Azure AD permissions alone are not enough —
you must explicitly register the application as a service principal in Exchange
Online.

First, find the correct Object ID:

1. In the Entra admin center, go to **Enterprise applications** (not App
   registrations)
2. Find your application and note the **Object ID** from its overview page

> **Warning:** There are two different Object IDs — one under **App
> registrations** and one under **Enterprise applications**. You must use the
> one from **Enterprise applications**. Using the wrong one causes
> authentication failures that are difficult to diagnose.

Then run the PowerShell commands:

```powershell
# Install the Exchange Online module (one-time)
Install-Module -Name ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline

# Register the service principal
# -AppId: Application (client) ID from App registrations
# -ObjectId: Object ID from Enterprise applications (NOT App registrations)
New-ServicePrincipal -AppId <CLIENT_ID> -ObjectId <ENTERPRISE_APP_OBJECT_ID>
```

> **Note:** If your tenant doesn't recognize the `-ObjectId` parameter, use
> `-ServiceId` instead (older alias):
> `New-ServicePrincipal -AppId <CLIENT_ID> -ServiceId <ENTERPRISE_APP_OBJECT_ID>`

### Step 5: Grant Mailbox Permissions

Grant the service principal access to the Airut mailbox:

> **⚠️ Security Warning:** The Azure AD permissions (`IMAP.AccessAsApp`) enable
> the capability for this app to access mailboxes, but they do not grant access
> to any specific mailbox content by default.
>
> You must strictly limit the `Add-MailboxPermission` command to the dedicated
> Airut mailbox.
>
> **Do not** run this command against a user group, a list of users, or your
> entire tenant. If you inadvertently grant this permission to a sensitive user
> (e.g., a CEO), the application — and anyone with its client secret — will have
> full access to that person's email.

```powershell
# Get the service principal identity
Get-ServicePrincipal | fl

# Grant FullAccess to the mailbox (for IMAP reading and SMTP sending)
# -User: the Identity value from Get-ServicePrincipal output
Add-MailboxPermission -Identity "airut@company.com" -User <SERVICE_PRINCIPAL_ID> -AccessRights FullAccess
```

### Step 6: Enable SMTP AUTH

SMTP AUTH must be enabled for the mailbox, even with OAuth2. Without this, SMTP
sending silently fails.

```powershell
# Enable SMTP AUTH for the specific mailbox
Set-CASMailbox -Identity "airut@company.com" -SmtpClientAuthenticationDisabled $false

# Verify the setting
Get-CASMailbox -Identity "airut@company.com" | fl SmtpClientAuthenticationDisabled
```

If SMTP AUTH is disabled at the organization level, you may also need:

```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $false
```

### Step 7: Configure Airut

Add the OAuth2 credentials to `config/airut.yaml`:

```yaml
repos:
  my-project:
    email:
      imap_server: outlook.office365.com
      imap_port: 993
      smtp_server: smtp.office365.com
      smtp_port: 587
      username: airut@company.com
      from: "Airut <airut@company.com>"
      # password is not needed when using OAuth2

      microsoft_oauth2:
        tenant_id: !env AZURE_TENANT_ID
        client_id: !env AZURE_CLIENT_ID
        client_secret: !env AZURE_CLIENT_SECRET

    # Microsoft 365 omits authserv-id from Authentication-Results
    # headers — set to empty string to skip the authserv-id check
    trusted_authserv_id: ""

    # Accept X-MS-Exchange-Organization-AuthAs: Internal for intra-org
    # email where Microsoft 365 omits Authentication-Results entirely
    microsoft_internal_auth_fallback: true

    authorized_senders:
      - you@company.com
```

Add the corresponding values to your `.env` file:

```bash
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret-value
```

When `microsoft_oauth2` is configured, Airut uses XOAUTH2 for both IMAP and SMTP
instead of password authentication. The `password` field can be omitted.

> **Important: `trusted_authserv_id` must be empty string for Microsoft 365.**
> Microsoft's Exchange Online Protection (EOP) omits the RFC 8601 `authserv-id`
> from `Authentication-Results` headers. Setting `trusted_authserv_id: ""` tells
> Airut to skip the authserv-id check and rely solely on the first-header-only
> policy for DMARC verification. See
> [Anti-spam message headers (Microsoft Learn)](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo)
> for details on Microsoft's header format.

> **Internal (intra-org) email:** Microsoft 365 does not generate
> `Authentication-Results` headers at all for email sent within the same tenant.
> Instead, it stamps the message with
> `X-MS-Exchange-Organization-AuthAs: Internal`. Set
> `microsoft_internal_auth_fallback: true` to accept this header as
> authentication proof when no `Authentication-Results` header is present.
> Authorization (sender allowlist) still applies. See
> [Demystifying Hybrid Mail Flow (Microsoft Tech Community)](https://techcommunity.microsoft.com/blog/exchange/demystifying-and-troubleshooting-hybrid-mail-flow-when-is-a-message-internal/1420838)
> for background.

### Step 8: Verify

Restart the service and check the logs:

```bash
systemctl --user restart airut
journalctl --user -u airut -f
```

You should see successful IMAP connections and no authentication errors. If you
see `AUTHENTICATE failed`, check the troubleshooting section below.

### Troubleshooting OAuth2

**`AUTHENTICATE failed` despite valid token:**

- Verify you used the Object ID from **Enterprise applications**, not App
  registrations
- Confirm `New-ServicePrincipal` and `Add-MailboxPermission` were run
  successfully
- Wait 15–30 minutes — Exchange Online permission propagation can be slow

**SMTP sending fails silently:**

- Ensure SMTP AUTH is enabled on the mailbox (`Set-CASMailbox`)
- Verify `SMTP.SendAsApp` permission was granted and admin-consented

**`invalid_client` error in logs:**

- Double-check the tenant ID, client ID, and client secret values
- Verify the client secret hasn't expired

**Token scope errors:**

- Airut uses the scope `https://outlook.office365.com/.default`, which is the
  only valid scope for M365 IMAP/SMTP client credentials. This is hardcoded and
  cannot be changed.

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

The updater supports two channels, selected at install time:

| Channel         | Target          | Default Interval | Description          |
| --------------- | --------------- | ---------------- | -------------------- |
| `rel` (default) | Latest `v*` tag | 6 hours          | Stable releases only |
| `dev`           | `origin/main`   | 30 minutes       | Tracks main branch   |

```bash
# Install with default rel channel
uv run scripts/install_services.py

# Install with dev channel
uv run scripts/install_services.py --channel dev

# Custom polling interval (in minutes)
uv run scripts/install_services.py --channel dev --interval 15
```

The chosen channel and interval are persisted in the generated systemd unit
files and survive self-updates.

```bash
# View updater logs
journalctl --user -u airut-updater -f

# Check timer status
systemctl --user list-timers
```

When updates are available:

1. Updater acquires lock (skips if service is busy)
2. **rel channel**: Checks out latest `v*` tag (detached HEAD)
3. **dev channel**: Pulls latest from `origin/main`
4. Reinstalls services with new code
5. Services restart automatically

### Update Coordination

The service and updater coordinate via `.update.lock`:

- Service holds lock while processing messages
- Updater skips update if lock is held
- Timer retries on next interval

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

## Upgrading Manually

To trigger an update without waiting for the auto-updater:

```bash
uv run scripts/install_services.py --update
```

To switch update channels, reinstall services:

```bash
uv run scripts/install_services.py --channel dev
```
