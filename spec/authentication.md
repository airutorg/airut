# Authentication and Authorization

Each channel implements authentication and authorization appropriate to its
transport. This spec covers the email channel's DMARC- and DKIM-based model. For
Slack's authorization model (workspace membership, user groups, user IDs), see
[slack-channel.md](slack-channel.md#authorization-model).

## Email Channel

Two logically separate layers protect the email channel from unauthorized use.
Both must pass before a message is processed.

## Authentication (`SenderAuthenticator`)

Verifies the email actually came from who it claims. Uses DMARC validation on
trusted `Authentication-Results` headers, and requires a valid DKIM signature by
the From domain.

### Configuration

- `auth.trusted_authserv_id` (required): Hostname of the mail server whose
  `Authentication-Results` headers are trusted (e.g., `mail.example.com`). Set
  to empty string (`""`) for Microsoft 365 / EOP, which omits the authserv-id
  from the header (see [Microsoft 365 Quirk](#microsoft-365-quirk) below).
- `auth.dkim_verification` (default `both`): who must find a DKIM signature by
  the From domain valid — `both` (the mail server and Airut), `server`, `airut`,
  or `none` (see [DKIM Requirement](#dkim-requirement)).

### Verification Flow

1. **Reject ambiguous header sections**: Every line of the header section must
   be the first line of a header field (a field name of printable ASCII other
   than `:`, then `:`) or, after the first line, a continuation line (starting
   with a space or tab), and no carriage return may stand without a line feed.
   Otherwise, reject: parsers treat other lines inconsistently (as the start of
   the body, as lines to skip, or as errors) and disagree on whether a bare
   carriage return ends a line, so they could read different header fields (a
   different `From`), or a different body from the one a signature covers. Nor
   may a field that RFC 5322 §3.6 allows at most once (`Date`, `From`, `Sender`,
   `Reply-To`, `To`, `Cc`, `Bcc`, `Message-ID`, `In-Reply-To`, `References`,
   `Subject`), or a MIME field saying how the body is read (`MIME-Version`,
   `Content-Type`, `Content-Transfer-Encoding`), appear more than once: parsers
   disagree on which copy counts (Python's email parser reads the first, while a
   DKIM signature covers the last). No normalization by the mail server is
   assumed.
2. **Parse From header** as an RFC 5322 address list (see
   [From Header Parsing](#from-header-parsing)). It must hold exactly one
   mailbox. A message without a `From` header is rejected.
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
5. **Require a DKIM signature by the From domain**, as `dkim_verification` says
   (see [DKIM Requirement](#dkim-requirement)). The server's recorded result is
   checked here; Airut's own verification runs only after
   [authorization](#authorization-senderauthorizer) has passed, so that messages
   from senders who are not allowed cause no DNS lookups.
6. **Return authenticated sender address** (lowercase) on success, `None` on
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
- A header that does not parse is unusable, and the message is rejected. So is
  one longer than 16 KiB: real headers are a few hundred characters, and the
  bound keeps parsing cheap whatever the input.

Requiring exactly one `dmarc` entry is a second line of defence: if an MTA ever
wrote a sender's value unquoted and it held `; dmarc=pass`, the injected entry
would sit beside the MTA's own and the message would be rejected.

These rules assume that the MTA writes its own `dmarc` entry into the first
header for every message, and quotes or escapes the values a sender controls.
With `dkim_verification` set to `both` or `airut`, a header that is not what it
seems still cannot stand in for a valid signature by the From domain.

### DKIM Requirement

DMARC passes when either SPF or DKIM is aligned with the From domain. SPF
depends only on the connecting IP address, which whoever runs the network in
front of the MTA may be able to choose; no DMARC policy can require DKIM. So
after DMARC, a DKIM signature whose signing domain is **exactly** the From
domain must be valid. Signatures by other domains do not count.

`dkim_verification` says who must find it valid:

- **`server`**: the trusted header holds a `dkim` entry (not `dkim-atps`) with
  result `pass` whose signing domain is the From domain. The signing domain is
  `header.d`, or — when the MTA writes only the identity, as Stalwart does for a
  signature with an `i=` tag — the domain after the last `@` of `header.i`. In
  that case a signature by a parent domain whose identity is in the From domain
  also counts (RFC 6376 has `i=` lie within `d=`).
- **`airut`**: Airut verifies a signature itself, over the message's bytes as
  fetched, looking up the key in DNS through the host's resolver. A signature
  counts only if the single `From` field it covers is the authenticated sender,
  read the same way. Only `rsa-sha256` signatures with RSA keys of at least 1024
  bits count; a signature with `l=` (covering only part of the body) or one that
  does not sign `From` does not. Work is bounded whatever the message: the
  number of signatures tried, the size of signatures and key records used, and
  the messages verified at all (by header count and whitespace) are limited (see
  the constants in `airut/gateway/email/dkim.py`). Any error while verifying
  means the signature does not verify. The DNS resolver must be one an attacker
  cannot answer for; this is the deployment's responsibility
  ([email-setup.md](../doc/email-setup.md#dns-for-dkim-keys)).
- **`both`** (default): both. The server's result is checked first, so DNS is
  only queried for messages it vouches for, from authorized senders.
- **`none`**: no DKIM requirement; DMARC alone.

Deployments whose mail server changes messages after they are signed — such as
Microsoft 365, with Safe Links or disclaimers — cannot pass Airut's own
verification and use `server`.

Airut's own verification means that a result the MTA got wrong, or a header
written by an account that submits mail without the MTA adding its own (finding
the topmost header to be the sender's), cannot stand in for a valid signature.

The [internal-auth fallback](#microsoft-365-internal-mail) involves no DKIM: it
trusts Exchange's own authentication of internal senders.

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

Authorization (sender allowlist) still applies after the internal auth fallback;
the DKIM requirement does not.

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
`email.auth` configuration with authorized senders, DMARC and DKIM settings.

## From Header Parsing

The From header is parsed as an RFC 5322 address list, strictly (not with the
permissive `email.utils.parseaddr`). It must hold **exactly one mailbox**,
outside any group:

- Accepted: a bare address (`user@example.com`) as the whole header, or a
  display name with an angle address (`Name <user@example.com>`). The display
  name may be RFC 2047-encoded, carry comments, or use obsolete syntax such as
  an unquoted `.`.
- **Rejected**: several addresses (`<user@example.com>, other@example.org`) —
  the reply would reach the others too; a group (`team: user@example.com;`); an
  address without a domain; a local part that needs quoting; a domain literal;
  any parse error other than obsolete syntax.
- **Rejected**: an address not written plainly. The header must be the bare
  address, or a display name followed by the only `<address>` in it. RFC 5322
  allows some of the forms below, but another parser — in a sending relay, the
  MTA, or a mail client — may read such a header as naming a different address.
  Rejected are:
  - a comment, whitespace or obsolete route inside the address
    (`user(c)@example.com`, `<@route:...>`), or anything after it
    (`user@example.com (Name)`);
  - any other `<` or `>` (as in `"<other@example.org>" <user@example.com>`);
  - specials in the display name outside quoted strings and comments, read raw
    (an encoded word may hide them from a parser that decodes it first);
  - a display name holding an encoded word that decodes, as lenient mail clients
    decode it, to text with `<`, `>` or `@`.
- **Rejected without parsing**: a header longer than 998 characters once
  unfolded (a bound taken from RFC 5322's line limit), or with more than three
  `(` open at once — counting every `(`, even quoted ones. Reading the From is
  bounded in time whatever the input, and any header that cannot be read within
  the bound is rejected rather than raising.

The DMARC check compares the domain read here with the `header.from` the MTA
recorded, so a From header that the two read differently is rejected.

## Message Processing Flow

```
Incoming email
    |
    v
SenderAuthenticator.authenticate(email)
    |-- Reject an ambiguous header section (a line that is not a
    |     field or a continuation, a bare CR, or a repeated field
    |     allowed once)
    |-- Parse From header (exactly one mailbox)
    |-- Parse first Authentication-Results header (RFC 8601)
    |-- Check its authserv-id
    |-- Require one dmarc entry: pass, header.from = From domain
    |-- Require the server's DKIM result for the From domain
    |     (dkim_verification: server or both)
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
SenderAuthenticator.verify_signature(email, sender)
    |-- Airut's own DKIM verification (dkim_verification: airut or both)
    |
    v (if verified)
Process message
```
