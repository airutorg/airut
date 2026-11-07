# Email Setup

This guide covers setting up email as a channel for Airut, enabling users to
interact with Claude Code by sending and receiving emails.

For Slack setup, see [slack-setup.md](slack-setup.md). Both channels can run
simultaneously for the same repository.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Prerequisites](#prerequisites)
- [How It Works](#how-it-works)
- [Step 1: Choose an Email Provider](#step-1-choose-an-email-provider)
- [Step 2: Configure Airut](#step-2-configure-airut)
- [Step 3: Test the Setup](#step-3-test-the-setup)
- [DMARC Requirements](#dmarc-requirements)
  - [Verifying DMARC](#verifying-dmarc)
- [DKIM Requirements](#dkim-requirements)
  - [Checking a Sender's Signature](#checking-a-senders-signature)
  - [DNS for DKIM Keys](#dns-for-dkim-keys)
- [Authorization](#authorization)
- [IMAP Configuration](#imap-configuration)
- [Attachment Size Limit](#attachment-size-limit)
- [Model Selection](#model-selection)
- [Troubleshooting](#troubleshooting)
  - [IMAP Connection Issues](#imap-connection-issues)
  - [DMARC Failures](#dmarc-failures)
  - [DKIM Failures](#dkim-failures)
  - [Emails Not Being Processed](#emails-not-being-processed)
  - [Model Hint Not Working](#model-hint-not-working)

<!-- mdformat-toc end -->

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
- Set `auth.trusted_authserv_id: mx.google.com`
- Limitation: Only works if senders use domains with DMARC (most corporate
  domains and major providers have this)

**Option 2: Fastmail or similar**

- Fastmail and similar providers include DMARC verification
- Check their documentation for the correct `auth.trusted_authserv_id`

**Option 3: Microsoft 365**

- See [m365-oauth2.md](m365-oauth2.md) for OAuth2 setup (required when Basic
  Authentication is disabled)
- Password auth also works if your tenant allows it
- Set `auth.dkim_verification: server`: Exchange changes messages after they are
  signed, so Airut's own DKIM check would reject them (see
  [DKIM Requirements](#dkim-requirements))

**Option 4: Self-hosted mail server**

- Requires configuring OpenDMARC or similar
- Most complex option, but gives full control

## Step 2: Configure Airut

You can configure the email channel using the config editor in the dashboard
(`http://localhost:5200` → **Configure**), or by editing
`~/.config/airut/airut.yaml` directly. The field paths below (e.g.,
`repos.<repo>.email.account.username`) match the labels shown in the config
editor.

Add the email channel to your server config:

```yaml
repos:
  my-project:
    email:
      account:
        username: airut
        password: !env EMAIL_PASSWORD
        from: "Airut <airut@example.com>"

      imap:
        server: mail.example.com
        port: 993
        use_idle: true  # Recommended for real-time delivery

      smtp:
        server: mail.example.com
        port: 587

      auth:
        authorized_senders:
          - you@example.com
          # - *@your-company.com  # Wildcard for domain
        trusted_authserv_id: mail.example.com

    repo_url: https://github.com/your-org/your-repo.git

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "github.com"
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

If using the config editor, changes are saved and reloaded automatically — no
restart needed. If editing the YAML file directly, changes are also picked up
via live config reload (the channel restarts once any in-flight task completes).

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

Airut authenticates senders using DMARC verification on incoming emails (and a
DKIM signature, see [DKIM Requirements](#dkim-requirements)). This requires:

1. **Your mail server must add `Authentication-Results` headers** — Most mail
   providers (Gmail, Microsoft 365, Fastmail, etc.) do this automatically.

2. **Configure `auth.trusted_authserv_id`** — This must match the server
   identifier in your mail provider's `Authentication-Results` header. Check an
   email's raw headers to find this value.

3. **Sender domains must have DMARC configured** — Emails from domains without
   DMARC records will be rejected.

4. **The header's DMARC result must name the From domain** — Airut requires a
   single `dmarc=pass` entry whose `header.from` is the sender's domain, as
   Gmail, Microsoft 365 and other common servers write it.

5. **Messages must come from a single, valid address** — A `From` header naming
   more than one address, a group, or one that is not valid RFC 5322 syntax
   (such as an unquoted comma or `[ ]` in the display name) is rejected. So is
   one longer than 998 characters, with a comment inside or after the address
   (`user(c)@example.com`, `user@example.com (Name)`), with `<` or `>` anywhere
   in the display name, or with `,`, `:`, `;` or `@` in it outside quotes and
   comments. Mail clients write `Name <user@example.com>`, which is accepted.

6. **The header section must be well-formed** — A message is rejected if a line
   of its header section is neither a header field (`Name: value`) nor a folded
   continuation of one, if it holds a carriage return without a line feed, or if
   a field allowed only once (such as `Subject`, `To` or `Content-Type`) appears
   more than once. Mail clients do not write these.

### Verifying DMARC

To check if a sender's domain has DMARC configured:

```bash
dig +short TXT _dmarc.example.com
```

A valid response indicates DMARC is configured. No response means emails from
that domain cannot be authenticated.

## DKIM Requirements

DMARC passes when either SPF or DKIM is aligned with the sender's domain. SPF
depends only on the connecting IP address, which whoever runs the network in
front of your mail server may be able to choose. So Airut also requires a valid
DKIM signature by the sender's own domain (the `d=` of the signature must equal
the From domain exactly). Only the domain's key holder can produce one.

`auth.dkim_verification` says who must find the signature valid:

| Value            | Requires                                                                                                               |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `both` (default) | The mail server records a `dkim=pass` for the domain in its `Authentication-Results` header, and Airut verifies it too |
| `server`         | Only the mail server's recorded result                                                                                 |
| `airut`          | Only Airut's own verification                                                                                          |
| `none`           | No DKIM signature (DMARC alone, which SPF can satisfy)                                                                 |

Airut verifies signatures over the message exactly as fetched, so a result the
mail server got wrong, or an `Authentication-Results` header written by an
account that submits its own mail over port 465/587, cannot stand in for a valid
signature. Only `rsa-sha256` signatures with RSA keys of at least 1024 bits are
accepted (not `rsa-sha1` or `ed25519-sha256`), and not with `l=` (covering only
part of the body). A domain that signs only with Ed25519 needs `server`.

Use `server` where messages are changed in transit after signing (for example by
Microsoft 365 Safe Links or disclaimers), and `none` only for senders whose
provider does not sign with their own domain.

### Checking a Sender's Signature

In Gmail, open a message from the sender and choose **Show original**. It should
show `DKIM: 'PASS' with domain <the sender's domain>`. A pass with another
domain (such as `gappssmtp.com` for a Google Workspace domain without its own
DKIM key) is not enough: set up DKIM for the domain with its mail provider.

### DNS for DKIM Keys

With `both` or `airut`, Airut looks up signers' public keys in DNS through the
host's resolver. Whoever can answer those lookups can make a forged signature
verify, so the resolver must be one an attacker cannot answer for. That depends
on the deployment: in particular, the lookups must not pass unprotected through
a network operated by someone you do not trust (such as the one in front of your
mail server).

A secure setup runs a local resolver that validates DNSSEC and forwards queries
over DNS-over-HTTPS (or DNS-over-TLS) to a trusted upstream resolver, and points
the host at it. Note:

- DNSSEC only protects domains whose zones are signed, and many senders' domains
  are not. For those, what protects the lookups is the encrypted link to an
  upstream resolver you trust.
- Airut uses whatever resolver the host is configured with (`/etc/resolv.conf`),
  read once when the service starts: restart Airut after changing it.
- `network.upstream_dns` (see [network-sandbox.md](network-sandbox.md)) is the
  resolver for sandboxed containers' traffic; it does not apply to these
  lookups.

## Authorization

The `auth.authorized_senders` list controls which email addresses can interact
with Airut. Authentication (DMARC and DKIM) and authorization must both pass.

```yaml
auth:
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
  server: mail.example.com
  port: 993

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

## Attachment Size Limit

Files the agent places in `/outbox` are sent as attachments. Mail servers refuse
messages over a size limit, so Airut keeps each reply under one:

```yaml
smtp:
  server: mail.example.com
  # Largest reply in MB, attachments included (default 25)
  max_message_size_mb: 25
```

If the SMTP server advertises a lower limit (the `SIZE` extension), that one is
used instead. Attachments that would push a reply over the limit are left out —
the largest first — and the reply names them, so the text and the remaining
files still arrive. If the server refuses a reply as too large anyway, it is
sent again without attachments, noting that the mail server rejected the email
as too large. Files left out are kept in the conversation's
`/storage/undelivered/`, and the agent is told about them with your next
message, so you can ask it to split, compress, or summarize them. The agent is
told how much fits (about 18 MB of files for the default, since attachments grow
by about 37% when encoded for email) so it can split or compress files ahead of
time.

Set `max_message_size_mb` to the smallest limit along the way: if your server
accepts 50 MB but your recipients' servers stop at 25 MB, a 40 MB reply leaves
your server and bounces back to the Airut mailbox, which the user never sees.
The limit counts the message as sent, with attachments encoded: Gmail's 25 MB
attachment limit, for example, corresponds to the roughly 34 MB its SMTP server
advertises, which Airut picks up on its own.

## Model Selection

Email supports model selection via subaddressing. To use a specific model,
address the email to `airut+opus@example.com` or `airut+sonnet@example.com`. The
part after `+` is used as a model hint. If no subaddress is provided, the repo's
`model` from the server config is used (defaults to `opus`).

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
# Symptom: Emails rejected ("sender authentication failed"), log says DMARC

# Check:
# 1. auth.trusted_authserv_id matches your mail server's Authentication-Results header
# 2. Sender's domain has a DMARC record (dig +short TXT _dmarc.example.com)
# 3. If using M365, set auth.trusted_authserv_id to "" (empty string)
# 4. The header parses as RFC 8601 defines it (log: "... is malformed")
# 5. The header's dmarc entry has header.from=<sender's domain>
# 6. The From header names a single address in valid RFC 5322 syntax
# 7. The header section is well-formed (log: "... header section holds ...")
# The log line explains which check failed.
```

### DKIM Failures

```bash
# Symptom: Emails rejected ("sender authentication failed"), log says DKIM

# Check:
# 1. The sender's mail carries a DKIM signature by their own domain (see
#    "Checking a Sender's Signature")
# 2. "the mail server recorded no passing signature": its
#    Authentication-Results header has no dkim=pass with header.d (or
#    header.i) of the sender's domain
# 3. "no signature by ... verified": Airut's own check failed — the message
#    may have been changed after signing (set dkim_verification: server), or
#    the key lookup failed (check the host's DNS)
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
