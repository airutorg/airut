# Email Authentication and Authorization

Two logically separate layers protect the email gateway from unauthorized use.
Both must pass before a message is processed.

## Authentication (`SenderAuthenticator`)

Verifies the email actually came from who it claims. Uses DMARC validation on
trusted `Authentication-Results` headers.

### Configuration

- `trusted_authserv_id` (required): Hostname of the mail server whose
  `Authentication-Results` headers are trusted (e.g., `mail.example.com`). Set
  to empty string (`""`) for Microsoft 365 / EOP, which omits the authserv-id
  from the header (see [Microsoft 365 Quirk](#microsoft-365-quirk) below).

### Verification Flow

1. **Reject ambiguous sender**: If the message has zero or multiple `From`
   headers, reject immediately (prevents attacker confusion attacks where DMARC
   validates one From but the application reads another).
2. **Parse From header** using strict extraction (not `email.utils.parseaddr`).
   Rejects malformed headers: multiple angle brackets, missing address, invalid
   format.
3. **Check the first Authentication-Results header only**: Take the **first**
   (topmost) `Authentication-Results` header. The receiving MTA prepends its
   header at the top (RFC 8601 §5), so this is always the authoritative one.
   Lower headers are **never** examined — they may be attacker-injected.
   - Extract the authserv-id (first token before `;`, per RFC 8601 §2.2).
   - If the authserv-id does not match `trusted_authserv_id` (case-insensitive),
     **reject immediately**.
4. **Require `dmarc=pass`**: The first header must contain `dmarc=pass` as a
   whole token (not a substring like `dmarc=passthrough`). Matched
   case-insensitively. If it does not contain `dmarc=pass`, authentication
   fails.
5. **Return authenticated sender address** (lowercase) on success, `None` on
   failure.

### Why Not SPF Alone

SPF validates the envelope sender (`Return-Path`), not the visible `From`
header. An attacker can send from `attacker@evil.com` (passing SPF for
`evil.com`) while setting `From: ceo@company.com`. DMARC enforces alignment
between SPF/DKIM identities and the `From` domain, closing this gap.

### Why Only the First Header

Email messages may contain multiple `Authentication-Results` headers from
intermediate relays or injected by attackers. An attacker can inject a header
with the trusted authserv-id and `dmarc=pass` into their outbound message. While
well-configured MTAs strip such forgeries (RFC 8601 §5), we do not rely on this.

Only the **first** (topmost) `Authentication-Results` header is examined,
regardless of its authserv-id. The receiving MTA always prepends its header
above any headers present in the incoming message, so the first header is always
from the MTA. If the first header is not from the trusted server, the message is
rejected — we never search lower headers for a matching authserv-id.

### Microsoft 365 Quirk

Microsoft 365 / Exchange Online Protection (EOP) omits the `authserv-id` from
the `Authentication-Results` header, violating RFC 8601. Instead of:

```
Authentication-Results: spf.protection.outlook.com; dmarc=pass ...
```

Microsoft writes:

```
Authentication-Results: spf=pass (sender IP is 10.0.0.1)
 smtp.mailfrom=example.com; dkim=pass header.d=example.com;
 dmarc=pass action=none header.from=example.com;compauth=pass reason=100
```

When `trusted_authserv_id` is set to empty string (`""`), the authserv-id check
is skipped entirely. Security relies on the first-header-only policy: the
receiving MTA always prepends its `Authentication-Results` header at the top
(RFC 8601 §5), so the first header is always from the MTA. This is the same
trust model as the standard configuration, minus the authserv-id verification.

### Microsoft 365 Internal Mail

For intra-org (internal) email within the same Microsoft 365 tenant, Exchange
Online Protection does not generate an `Authentication-Results` header at all.
Instead, it stamps the message with:

```
X-MS-Exchange-Organization-AuthAs: Internal
```

This indicates the message was sent within the organization and authenticated by
Exchange's internal transport pipeline.

When `microsoft_internal_auth_fallback` is set to `true` and the message has
**no** `Authentication-Results` header, the authenticator accepts the message if
`X-MS-Exchange-Organization-AuthAs` is `Internal`. If any
`Authentication-Results` header is present (even with a DMARC failure), the
fallback does not apply — DMARC remains the authoritative mechanism.

Authorization (sender allowlist) still applies after the internal auth fallback.

Reference:
[Demystifying Hybrid Mail Flow: When is a message Internal?](https://techcommunity.microsoft.com/blog/exchange/demystifying-and-troubleshooting-hybrid-mail-flow-when-is-a-message-internal/1420838)

## Authorization (`SenderAuthorizer`)

Checks whether an authenticated sender is permitted to use the gateway. Operates
on the email address string returned by the authenticator.

### Configuration

- `authorized_senders` (required): List of email patterns allowed to send
  commands. Supports:
  - Exact addresses: `user@example.com`
  - Domain wildcards: `*@example.com` (matches any user at that domain)

All comparisons are case-insensitive.

### Behavior

The authenticated sender is checked against each pattern in order. Authorization
succeeds if the sender matches any pattern:

- For exact patterns: sender must equal the pattern
- For domain wildcards (`*@domain.com`): sender must end with `@domain.com`

### Example Configuration

```yaml
authorized_senders:
  - admin@company.com        # Exact match
  - *@trusted-partner.com    # Any user from this domain
  - external.contractor@consultant.org
```

## From Header Parsing

The `_extract_email` helper provides strict parsing:

- Bare address (`user@example.com`): validated against RFC 5322 pattern
- Display name with angle brackets (`Name <user@example.com>`): extracts address
  from single `<>` pair
- **Rejected**: multiple `<` or `>` characters (injection technique), `>` before
  `<`, empty brackets, addresses not matching the email regex

This replaces `email.utils.parseaddr` which is permissive and can be confused by
malformed headers in security-sensitive contexts.

## Message Processing Flow

```
Incoming email
    |
    v
SenderAuthenticator.authenticate(message)
    |-- Parse From header (strict)
    |-- Find trusted Authentication-Results header
    |-- Verify dmarc=pass
    |-- If no Auth-Results and fallback enabled:
    |     check X-MS-Exchange-Organization-AuthAs: Internal
    |-- Return sender address or None
    |
    v (if authenticated)
SenderAuthorizer.is_authorized(sender)
    |-- Compare against authorized_senders patterns
    |-- Return True/False
    |
    v (if authorized)
Process message
```
