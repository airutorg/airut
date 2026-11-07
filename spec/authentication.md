# Authentication and Authorization

Each channel implements authentication and authorization appropriate to its
transport. This spec covers the email channel's DMARC-based model. For Slack's
authorization model (workspace membership, user groups, user IDs), see
[slack-channel.md](slack-channel.md#authorization-model).

## Email Channel

Two logically separate layers protect the email channel from unauthorized use.
Both must pass before a message is processed.

## Authentication (`SenderAuthenticator`)

Verifies the email actually came from who it claims. Uses DMARC validation on
trusted `Authentication-Results` headers.

### Configuration

- `auth.trusted_authserv_id` (required): Hostname of the mail server whose
  `Authentication-Results` headers are trusted (e.g., `mail.example.com`). Set
  to empty string (`""`) for Microsoft 365 / EOP, which omits the authserv-id
  from the header (see [Microsoft 365 Quirk](#microsoft-365-quirk) below).

### Verification Flow

1. **Reject ambiguous sender**: If the message has zero or multiple `From`
   headers, reject immediately (prevents attacker confusion attacks where DMARC
   validates one From but the application reads another).
2. **Parse From header** as an RFC 5322 address list (see
   [From Header Parsing](#from-header-parsing)). It must hold exactly one
   mailbox.
3. **Check the first Authentication-Results header only**: Take the **first**
   (topmost) `Authentication-Results` header. The receiving MTA prepends its
   header at the top (RFC 8601 §5), so this is always the authoritative one.
   Lower headers are **never** examined — they may be attacker-injected.
   - Parse it as RFC 8601 defines it (see
     [Parsing Authentication-Results](#parsing-authentication-results)). A
     header that does not parse is rejected.
   - If its authserv-id does not match `trusted_authserv_id` (case-insensitive),
     **reject immediately**.
4. **Require a DMARC pass for the From domain**: The header must hold exactly
   one `dmarc` entry, its result must be `pass`, and its `header.from` must
   equal the From address's domain (case-insensitive). Anything else fails
   authentication: no `dmarc` entry, two of them, another result (`fail`,
   `temperror`, ...), or a missing or different `header.from`.
5. **Return authenticated sender address** (lowercase) on success, `None` on
   failure. This address, not the raw From header, is the conversation's sender:
   replies go to it alone. The raw header is kept for display only.

### Parsing Authentication-Results

The receiving MTA writes the header, but many values in it come from the sender:
the identity in a DKIM signature (`header.i`), the envelope sender
(`smtp.mailfrom`), a From domain. The MTA quotes such values, and a quoted value
may hold any text — including `dmarc=pass`. So the header is parsed as RFC 8601
§2.2 defines it, never searched for a substring:

- Text inside a quoted string or a comment is never read as structure: it cannot
  separate entries or start a `method=result`.
- Only the first `key=value` pair of an entry is its method and result; a result
  is never a quoted string.
- Methods, results, and keys are case-insensitive.
- A header with no authserv-id (Microsoft 365) is read as starting with its
  first entry.
- A header that does not parse is unusable, and the message is rejected.

Requiring exactly one `dmarc` entry is a second line of defence: if an MTA ever
wrote a sender's value unquoted and it held `; dmarc=pass`, the injected entry
would sit beside the MTA's own and the message would be rejected.

These rules assume that the MTA writes its own `dmarc` entry into the first
header for every message, and quotes or escapes the values a sender controls.
Verifying DKIM in Airut itself would remove the dependence on the MTA's header
format.

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

When `auth.trusted_authserv_id` is set to empty string (`""`), the authserv-id
check is skipped entirely; the parser reads a header whose first segment is
itself an entry as having no authserv-id. The DMARC entry rules are the same.
Security relies on the first-header-only policy: the receiving MTA always
prepends its `Authentication-Results` header at the top (RFC 8601 §5), so the
first header is always from the MTA. This is the same trust model as the
standard configuration, minus the authserv-id verification.

### Microsoft 365 Internal Mail

For intra-org (internal) email within the same Microsoft 365 tenant, Exchange
Online Protection does not generate an `Authentication-Results` header at all.
Instead, it stamps the message with:

```
X-MS-Exchange-Organization-AuthAs: Internal
```

This indicates the message was sent within the organization and authenticated by
Exchange's internal transport pipeline.

When `auth.microsoft_internal_fallback` is set to `true` and the message has
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

- `auth.authorized_senders` (required): List of email patterns allowed to send
  commands. Supports:
  - Exact addresses: `user@example.com`
  - Domain wildcards: `*@example.com` (matches any user at that domain)

All comparisons are case-insensitive.

### Behavior

The authenticated sender is checked against each pattern in order. Authorization
succeeds if the sender matches any pattern:

- For exact patterns: sender must equal the pattern
- For domain wildcards (`*@domain.com`): the sender's domain must be exactly
  `domain.com` (subdomains do not match)

### Example Configuration

See [`config/airut.example.yaml`](../config/airut.example.yaml) for the full
`email.auth` configuration with authorized senders and DMARC settings.

## From Header Parsing

The From header is parsed as an RFC 5322 address list, strictly (not with the
permissive `email.utils.parseaddr`). It must hold **exactly one mailbox**,
outside any group:

- Accepted: a bare address (`user@example.com`), a display name with an angle
  address (`Name <user@example.com>`), RFC 2047-encoded display names, comments,
  and obsolete syntax such as an unquoted `.` in a display name.
- **Rejected**: several addresses (`<user@example.com>, other@example.org`) —
  the reply would reach the others too; a group (`team: user@example.com;`); an
  address without a domain; a local part that needs quoting; a domain literal;
  any parse error other than obsolete syntax.

The DMARC check compares the domain read here with the `header.from` the MTA
recorded, so a From header that the two read differently is rejected.

## Message Processing Flow

```
Incoming email
    |
    v
SenderAuthenticator.authenticate(message)
    |-- Parse From header (exactly one mailbox)
    |-- Parse first Authentication-Results header (RFC 8601)
    |-- Check its authserv-id
    |-- Require one dmarc entry: pass, header.from = From domain
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
