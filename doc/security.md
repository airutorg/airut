# Security Model

## Motivation

Airut enables headless Claude Code interaction over email, allowing users to
delegate software engineering tasks to an AI agent. This shifts human feedback
from reviewing individual agent actions (file edits, shell commands) to
higher-level artifacts like pull requests.

Running Claude Code with `--dangerously-skip-permissions` is necessary because
interactive approval isn't feasible over email. This creates two security
challenges:

1. **Request authorization** — How do we verify that incoming emails are from
   trusted senders, not spoofed messages that could trigger unauthorized code
   execution?

2. **Execution containment** — How do we limit the blast radius when an agent
   executes arbitrary code, preventing credential theft, data exfiltration, or
   host compromise?

The security model addresses these through email-native authentication (DMARC)
and multi-layer sandboxing (container isolation, network allowlist).

## Core Principles

The security architecture rests on three principles:

**Sandboxing** — Execution and network isolation contain agent actions. Each
conversation runs in a dedicated container with controlled mounts (no host
credentials). All network traffic routes through a proxy that enforces an
allowlist, preventing data exfiltration even if the agent is compromised via
prompt injection.

**Email-native authentication (DMARC)** — Rather than inventing a custom
authentication scheme, Airut leverages DMARC — the standard email authentication
protocol that major providers already implement. This provides cryptographic
verification of sender identity without requiring users to manage API keys or
tokens.

**Defense in depth** — Multiple independent security layers ensure that failure
of any single control doesn't compromise the system. Email authentication +
sender allowlist, container isolation + network sandbox, surrogate credentials +
environment-only injection — each layer catches threats the others might miss.

## Security Layers

The following diagram shows the security controls at each layer:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Email Layer                                 │
│  ┌─────────────────────┐  ┌─────────────────────────────────────┐   │
│  │ DMARC Authentication│  │ Sender Authorization (allowlist)    │   │
│  └─────────────────────┘  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                       Execution Layer                               │
│  ┌─────────────────────┐  ┌─────────────────────────────────────┐   │
│  │ Container Isolation │  │ Filesystem Mount Restrictions       │   │
│  └─────────────────────┘  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                        Network Layer                                │
│  ┌─────────────────────┐  ┌─────────────────────────────────────┐   │
│  │ Internal Network +  │  │ Proxy Allowlist Enforcement         │   │
│  │ DNS Control         │  │ (HTTP/HTTPS + DNS)                  │   │
│  └─────────────────────┘  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                       Credential Layer                              │
│  ┌─────────────────────┐  ┌─────────────────────────────────────┐   │
│  │ Environment-only    │  │ Surrogate Credentials               │   │
│  │ secrets             │  │ (Masked Secrets + Signing Creds)    │   │
│  └─────────────────────┘  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                       Dashboard Layer                               │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Localhost binding + reverse proxy authentication (external)  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Email Authentication

Airut verifies sender identity via DMARC before processing any message. This
prevents spoofed emails from triggering code execution.

The authentication flow validates the `From` header against
`Authentication-Results` headers from the configured `trusted_authserv_id` (your
mail server). Only the first (topmost) header is examined — lower headers may be
attacker-injected. After authentication, the sender is checked against the
per-repo allowlist.

Both layers must pass. A valid DMARC pass from an unauthorized sender is
rejected.

See [spec/authentication.md](../spec/authentication.md) for the full
verification flow, From header parsing, Microsoft 365 quirks, and authorization
details.

## Execution Isolation

See [execution-sandbox.md](execution-sandbox.md) for full details.

**Key properties:**

- Each conversation runs in a dedicated Podman container
- Controlled mount points (workspace, claude state, inbox, outbox)
- No host credentials mounted (SSH keys, git config, etc.)
- Session metadata stored outside container mounts
- Configurable timeout with hard kill

## Network Isolation

See [network-sandbox.md](network-sandbox.md) for full details.

**Key properties:**

- Containers on internal network (no direct internet)
- All HTTP(S) transparently routed through mitmproxy enforcing allowlist — no
  `HTTP_PROXY` env vars needed, works with all tools (Node.js, Go, curl, etc.)
- Custom DNS responder replaces Podman's default aardvark-dns — returns proxy IP
  for allowed domains, NXDOMAIN for blocked, and never forwards queries upstream
  (blocks DNS exfiltration)
- Allowlist read from default branch (agent can't modify active list)
- Per-conversation proxy container and network (isolated from other tasks)

## Credential Management

### Server Secrets

Server credentials are configured in `~/.config/airut/airut.yaml` using `!env`
tags:

```yaml
repos:
  my-project:
    email:
      password: !env EMAIL_PASSWORD
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
```

Actual values come from environment variables or `~/.config/airut/.env`.

### Container Secrets

Repo config (`.airut/airut.yaml`) references server secrets with `!secret`:

```yaml
container_env:
  GH_TOKEN: !secret GH_TOKEN              # Required
  API_KEY: !secret? API_KEY               # Optional (skip if missing)
```

**Security properties:**

- Repo config cannot use `!env` (prevents reading arbitrary server state)
- Secrets resolved at task start, not stored in repo
- All resolved values registered for log redaction
- Container sees environment variables, not files

### Git Authentication

Containers use `gh auth git-credential` helper with `GH_TOKEN`:

- No SSH keys mounted from host
- Token scoped to repository operations
- Credential helper configured in container image

### Masked Secrets (Token Replacement)

For credentials that should only be usable with specific services, use
`masked_secrets` in the server config. Containers receive surrogate tokens
instead of real credentials; the proxy swaps surrogates for real values only
when the request host matches configured scopes.

Real credentials never enter the container — they stay with the proxy and are
only inserted into upstream requests to scoped hosts. A compromised container
can still make authenticated requests to scoped hosts through the proxy, but
cannot extract the real credentials for use outside the container. The ability
to act is bound to the container's lifetime and the proxy's scope.

See [network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement)
for an overview and [spec/masked-secrets.md](../spec/masked-secrets.md) for the
full specification.

### Signing Credentials (AWS SigV4 Re-signing)

AWS credentials present a unique challenge: the secret key never appears in HTTP
headers. Instead, it is used to compute HMAC (SigV4) or ECDSA (SigV4A)
signatures over the request. Simple string replacement cannot work — the proxy
must **re-sign** outbound requests with the real credentials.

`signing_credentials` in the server config handle this transparently:

1. Container receives **surrogate** AWS credentials (format-preserving: same
   AKIA/ASIA prefix, same lengths)
2. AWS SDK in the container signs requests normally using the surrogates
3. Proxy intercepts requests to scoped hosts, verifies the surrogate signature,
   and re-signs with the real credentials
4. Re-signing covers Authorization headers, presigned URLs, and chunked transfer
   encoding (S3 `aws-chunked`)

**Repo config is transparent** — it uses `!secret AWS_ACCESS_KEY_ID` just like
any other secret. The server admin decides whether to use plain secrets or
signing credentials; the repo config is unchanged either way.

This works with any S3-compatible API (AWS, Cloudflare R2, MinIO, etc.), not
just `*.amazonaws.com`.

See
[network-sandbox.md](network-sandbox.md#signing-credentials-aws-sigv4-re-signing)
for an overview and
[spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) for the full
specification.

## Dashboard Security

The dashboard binds to localhost (`127.0.0.1:5200`) by default:

- **No built-in authentication**: Assumes reverse proxy handles auth
- **Localhost only**: Not exposed to network without explicit configuration
- **Minimal actions**: Only action is stopping running tasks

For production, deploy behind an authenticating reverse proxy (nginx, Caddy,
etc.) that handles user authentication before forwarding to the dashboard.

The dashboard exposes:

- Conversation IDs and email subjects
- Task timing and status
- Session metadata and actions
- Network activity logs

This is acceptable for a single-user system behind authentication.

## Attack Surface Analysis

| Risk                  | Mitigation                                      |
| --------------------- | ----------------------------------------------- |
| Email spoofing        | DMARC verification on trusted headers           |
| Unauthorized access   | Sender allowlist after authentication           |
| Code execution escape | Podman container isolation                      |
| Data exfiltration     | Network allowlist via proxy                     |
| Credential theft      | Environment-only secrets, no host mounts        |
| Cross-session attack  | Per-conversation isolation (workspace, network) |
| Resource exhaustion   | Timeout, conversation limit, garbage collection |
| Log leakage           | Automatic secret redaction                      |
| Dashboard access      | Localhost binding, reverse proxy auth           |

## Configuration Security

### Repo Config Protection

Repo configuration (`.airut/airut.yaml`) is read from the git mirror's default
branch, not the workspace. The agent cannot modify:

- Network sandbox settings
- Container environment variables
- Timeout limits

Changes require a merged PR, providing human review.

### Network Allowlist Protection

The network allowlist (`.airut/network-allowlist.yaml`) follows the same
pattern:

- Read from default branch
- Agent can propose changes via PR
- Changes don't take effect until merged
- Human review required

### Container Image Build Isolation

The repo-defined Dockerfile (`.airut/container/Dockerfile`) cannot access
arbitrary server files during build:

- Build context is an ephemeral temp directory, not the server filesystem
- Only files from `.airut/container/` are copied to the build context
- Files are read via git mirror (`git show`), preventing path traversal
- `COPY` instructions can only access files within the build context

A malicious Dockerfile cannot `COPY /etc/passwd` or use `../` traversal to
escape the build context. This mirrors the `!secret` vs `!env` restriction:
repos declare what they need, the server controls what's actually available.

## Fail-Secure Defaults

- Missing `trusted_authserv_id`: Authentication fails (reject all)
- Empty `authorized_senders`: Authorization fails (reject all)
- Proxy startup failure: Task aborts (no unproxied execution)
- Secret resolution failure: Task aborts (no missing credentials)
- DMARC check failure: Message rejected (no processing)

## Security Limitations

The security model provides strong containment but does not offer absolute
protection. This section documents known limitations and realistic expectations.

### Prompt Injection

The sandbox does not prevent prompt injection attacks from succeeding — it
limits their impact. If an agent reads content containing malicious instructions
(from a webpage, API response, repository file, or email attachment), the agent
may follow those instructions within the boundaries of its execution and network
sandbox.

**What the attacker can do** (within sandbox boundaries):

- Execute arbitrary code in the container
- Access any files in the workspace
- Use credentials passed via environment variables
- Make requests to allowlisted hosts
- Create commits or PRs with malicious content

**What the attacker cannot do** (blocked by sandbox):

- Access hosts not on the network allowlist
- Read host files outside mounted directories
- Access other conversations
- Persist beyond the container lifetime
- Modify the active allowlist or configuration

**Mitigations:**

1. **Keep repository content safe** — Review all material entering the
   repository (PRs, issues, imported files)
2. **Minimize network allowlist** — Only allow hosts the agent genuinely needs
3. **Scope credentials tightly** — Grant minimum permissions required (e.g.,
   repo-scoped tokens, not org-wide)
4. **Send trusted prompts** — Only send files and instructions from trusted
   sources

### Authorized Channel Exfiltration

If prompt injection succeeds, the agent can exfiltrate data through channels it
legitimately has access to. For example:

- Embedding secrets in a GitHub PR description or commit message
- Sending data to an allowlisted API that the attacker can query
- Encoding information in allowed HTTP request parameters

The network sandbox blocks unauthorized channels but cannot distinguish
legitimate from malicious use of authorized channels.

**Mitigations:**

1. **Use masked secrets and signing credentials** — Real credentials configured
   as `masked_secrets` or `signing_credentials` never enter the container. The
   proxy inserts them into upstream requests only for scoped hosts. A
   compromised container can still act within the boundaries of what the
   credentials and scopes allow (e.g., make API calls to scoped hosts), but
   cannot extract the real credentials. The ability to act is bound to the
   container's lifetime and the proxy's enforcement — once the container stops,
   or if the attacker tries to use the credentials from outside, they are
   useless. This is the strongest mitigation for credential exfiltration.
2. **Scope credentials to minimum** — A token that can only push to one repo
   limits exfiltration to that repo
3. **Review agent outputs** — PRs, commits, and email replies are human review
   points
4. **Audit network logs** — `network-sandbox.log` shows all requests for
   forensic analysis

### Realistic Security Expectations

In practice, trusting all content the agent processes is not possible.
Repository files may contain untrusted user input. Fetched web pages may have
adversarial content. Email attachments may be crafted by attackers who know the
system.

**Security is therefore statistical rather than absolute.** The goal is to:

1. Make attacks significantly harder than on an unsandboxed system
2. Limit blast radius when attacks succeed
3. Provide audit trails for detection and response
4. Enable configuration that tilts odds strongly toward security

Proper configuration — tight network allowlist, scoped credentials, reviewed
repository content — makes successful exploitation substantially less likely and
less damaging. But no configuration eliminates risk entirely when processing
untrusted content with an AI agent.
