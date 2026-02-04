# Email Authentication and Authorization

Two logically separate layers protect the email gateway from unauthorized use.
Both must pass before a message is processed.

## Authentication (`SenderAuthenticator`)

Verifies the email actually came from who it claims. Uses DMARC validation on
trusted `Authentication-Results` headers.

### Configuration

- `trusted_authserv_id` (required): Hostname of the mail server whose
  `Authentication-Results` headers are trusted (e.g., `mail.example.com`).

### Verification Flow

1. **Reject ambiguous sender**: If the message has zero or multiple `From`
   headers, reject immediately (prevents attacker confusion attacks where DMARC
   validates one From but the application reads another).
2. **Parse From header** using strict extraction (not `email.utils.parseaddr`).
   Rejects malformed headers: multiple angle brackets, missing address, invalid
   format.
3. **Find trusted Authentication-Results header**: Iterate all
   `Authentication-Results` headers; only consider those whose authserv-id
   (first token before `;`, per RFC 8601 section 2.2) matches
   `trusted_authserv_id` (case-insensitive).
4. **Require `dmarc=pass`**: The trusted header must contain `dmarc=pass` as a
   whole token (not a substring like `dmarc=passthrough`). Matched
   case-insensitively.
5. **Return authenticated sender address** (lowercase) on success, `None` on
   failure.

### Why Not SPF Alone

SPF validates the envelope sender (`Return-Path`), not the visible `From`
header. An attacker can send from `attacker@evil.com` (passing SPF for
`evil.com`) while setting `From: ceo@company.com`. DMARC enforces alignment
between SPF/DKIM identities and the `From` domain, closing this gap.

### Why Filter by authserv-id

Email messages may contain multiple `Authentication-Results` headers from
intermediate relays or injected by attackers. Without filtering, an attacker
adds `Authentication-Results: fake.server.com; dmarc=pass` to their message.
Only trusting headers from the configured mail server prevents this.

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
