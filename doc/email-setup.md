# Email Setup

This guide covers setting up email as a channel for Airut, enabling users to
interact with Claude Code by sending and receiving emails.

For Slack setup, see [slack-setup.md](slack-setup.md). Both channels can run
simultaneously for the same repository.

## Prerequisites

- Airut server deployed (see [deployment.md](deployment.md))
- **Dedicated email account** with IMAP and SMTP access — one per repository
- Email provider that adds `Authentication-Results` headers (most major
  providers do)

## How It Works

Airut's email integration uses standard IMAP/SMTP:

- **IMAP** (polling or IDLE) for receiving incoming messages. Airut treats the
  inbox as a work queue — it continuously polls for messages, processes every
  email it finds, and **permanently deletes messages** after processing.
- **SMTP** for sending replies with threading headers (`In-Reply-To`,
  `References`) so replies appear in the same thread in the sender's mail
  client.

Each email thread maps to one Airut conversation. The conversation ID is
embedded in the subject line as `[ID:hex8]` and in message headers. Replying to
a previous email resumes that conversation.

> **Warning:** Each repository requires its own dedicated email account/inbox.
> **Never point Airut to an inbox used for other purposes** (such as your
> personal email or a shared team inbox). Airut will attempt to process every
> message and delete it.

## Step 1: Choose an Email Provider

You need an email account that supports IMAP and SMTP with
`Authentication-Results` headers for DMARC verification.

**Option 1: Gmail with App Password (simplest for testing)**

- Use a Gmail account for IMAP/SMTP
- Generate an App Password (requires 2FA enabled)
- Set `trusted_authserv_id: mx.google.com`
- Limitation: Only works if senders use domains with DMARC (most corporate
  domains and major providers have this)

**Option 2: Fastmail or similar**

- Fastmail and similar providers include DMARC verification
- Check their documentation for the correct `trusted_authserv_id`

**Option 3: Microsoft 365**

- See [m365-oauth2.md](m365-oauth2.md) for OAuth2 setup (required when Basic
  Authentication is disabled)
- Password auth also works if your tenant allows it

**Option 4: Self-hosted mail server**

- Requires configuring OpenDMARC or similar
- Most complex option, but gives full control

## Step 2: Configure Airut

Add the email channel to your server config (`~/.config/airut/airut.yaml`):

```yaml
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
        # - *@your-company.com  # Wildcard for domain

      trusted_authserv_id: mail.example.com

      imap:
        use_idle: true  # Recommended for real-time delivery

    git:
      repo_url: https://github.com/your-org/your-repo.git

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "api.github.com"
          - "*.githubusercontent.com"
        headers:
          - "Authorization"
```

Add the password to `~/.config/airut/.env`:

```bash
EMAIL_PASSWORD=your-email-password
```

**Email and Slack can coexist.** To run both channels for the same repo, include
both `email:` and `slack:` blocks under the repo. Each channel operates
independently with its own listener and authentication.

Restart the service to pick up the new configuration:

```bash
systemctl --user restart airut
```

## Step 3: Test the Setup

Send a test email:

```
To: airut@example.com
Subject: Test task

Please verify you can access the repository by listing the files in the
root directory.
```

You should see:

- An acknowledgment email with a dashboard link (if configured)
- A reply with the file listing

Check the service logs if something goes wrong:

```bash
journalctl --user -u airut -f
```

## DMARC Requirements

Airut authenticates senders using DMARC verification on incoming emails. This
requires:

1. **Your mail server must add `Authentication-Results` headers** — Most mail
   providers (Gmail, Microsoft 365, Fastmail, etc.) do this automatically.

2. **Configure `trusted_authserv_id`** — This must match the server identifier
   in your mail provider's `Authentication-Results` header. Check an email's raw
   headers to find this value.

3. **Sender domains must have DMARC configured** — Emails from domains without
   DMARC records will be rejected.

### Verifying DMARC

To check if a sender's domain has DMARC configured:

```bash
dig +short TXT _dmarc.example.com
```

A valid response indicates DMARC is configured. No response means emails from
that domain cannot be authenticated.

## Authorization

The `authorized_senders` list controls which email addresses can interact with
Airut. Both DMARC verification and authorization must pass.

```yaml
authorized_senders:
  - alice@example.com        # Exact address
  - *@your-company.com       # All addresses from domain
```

Wildcards use `*@domain` syntax for domain-level matching.

See [spec/authentication.md](../spec/authentication.md) for the full
verification flow, From header parsing, and Microsoft 365 quirks.

## IMAP Configuration

```yaml
imap:
  # Seconds between IMAP polls (only used when use_idle is false)
  poll_interval: 30

  # Use IMAP IDLE for efficient push-based notifications (recommended)
  use_idle: true

  # Reconnect interval for IDLE mode in seconds (keep below 29 min)
  idle_reconnect_interval: 1740
```

IMAP IDLE is recommended — it provides near-instant message detection. If your
provider doesn't support IDLE, set `use_idle: false` and configure
`poll_interval`.

## Model Selection

Email supports model selection via subaddressing. To use a specific model,
address the email to `airut+opus@example.com` or `airut+sonnet@example.com`. The
part after `+` is used as a model hint. If no subaddress is provided, the repo's
`default_model` from `.airut/airut.yaml` is used.

## Troubleshooting

### IMAP Connection Issues

```bash
# Test IMAP manually
openssl s_client -connect mail.example.com:993

# Check if IDLE is supported
# Look for "IDLE" in CAPABILITY response
```

### DMARC Failures

```bash
# Symptom: Emails rejected with "DMARC verification failed"

# Check:
# 1. trusted_authserv_id matches your mail server's Authentication-Results header
# 2. Sender's domain has a DMARC record (dig +short TXT _dmarc.sender.com)
# 3. If using M365, set trusted_authserv_id to "" (empty string)
```

### Emails Not Being Processed

```bash
# Check service logs for IMAP errors
journalctl --user -u airut | grep -i "imap\|email"

# Common causes:
# - Wrong IMAP/SMTP credentials
# - Firewall blocking IMAP port (993) or SMTP port (587)
# - Account locked due to failed login attempts
```

### Model Hint Not Working

Model hints via subaddressing (`airut+opus@`) require that your email provider
delivers subaddressed mail to the base address. Most providers support this by
default (Gmail, Fastmail, M365). Some self-hosted servers need explicit
configuration.
