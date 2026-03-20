# Security Model

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Motivation](#motivation)
- [Core Principles](#core-principles)
- [Security Layers](#security-layers)
- [Channel Authentication](#channel-authentication)
  - [Email: DMARC Verification](#email-dmarc-verification)
  - [Slack: Socket Mode + Authorization Rules](#slack-socket-mode--authorization-rules)
- [Execution Isolation](#execution-isolation)
- [Network Isolation](#network-isolation)
- [Credential Management](#credential-management)
  - [Server Secrets](#server-secrets)
  - [Container Secrets](#container-secrets)
  - [Git Authentication](#git-authentication)
  - [Masked Secrets (Token Replacement)](#masked-secrets-token-replacement)
  - [Signing Credentials (AWS SigV4 Re-signing)](#signing-credentials-aws-sigv4-re-signing)
  - [GitHub App Credentials (Token Rotation)](#github-app-credentials-token-rotation)
- [Dashboard Security](#dashboard-security)
- [Attack Surface Analysis](#attack-surface-analysis)
- [Configuration Security](#configuration-security)
  - [Repo Config Protection](#repo-config-protection)
  - [Network Allowlist Protection](#network-allowlist-protection)
  - [Container Image Build Isolation](#container-image-build-isolation)
- [Fail-Secure Defaults](#fail-secure-defaults)
- [Security Limitations](#security-limitations)
  - [Prompt Injection](#prompt-injection)
  - [Authorized Channel Exfiltration](#authorized-channel-exfiltration)
  - [GitHub Actions Workflow Escape](#github-actions-workflow-escape)
  - [Realistic Security Expectations](#realistic-security-expectations)

<!-- mdformat-toc end -->

## Motivation

Airut enables headless Claude Code interaction over messaging channels (email
and Slack), allowing users to delegate software engineering tasks to an AI
agent. This shifts human feedback from reviewing individual agent actions (file
edits, shell commands) to higher-level artifacts like pull requests.

Running Claude Code with `--dangerously-skip-permissions` is necessary because
interactive approval isn't feasible over asynchronous channels. This creates two
security challenges:

1. **Request authorization** — How do we verify that incoming messages are from
   trusted senders, not spoofed or unauthorized requests that could trigger code
   execution?

2. **Execution containment** — How do we limit the blast radius when an agent
   executes arbitrary code, preventing credential theft, data exfiltration, or
   host compromise?

The security model addresses these through per-channel authentication and
multi-layer sandboxing (container isolation, network allowlist).

## Core Principles

The security architecture rests on three principles:

**Sandboxing** — Execution and network isolation contain agent actions. Each
conversation runs in a dedicated container with controlled mounts (no host
credentials). All network traffic routes through a proxy that enforces an
allowlist, preventing data exfiltration even if the agent is compromised via
prompt injection.

**Channel-native authentication** — Each channel uses its own authentication
model. Email uses DMARC — the standard email authentication protocol that major
providers already implement, providing cryptographic verification of sender
identity. Slack uses Socket Mode — a pre-authenticated WebSocket where Slack
guarantees sender identity at the platform level. Both approaches leverage
existing infrastructure rather than inventing custom authentication.

**Defense in depth** — Multiple independent security layers ensure that failure
of any single control doesn't compromise the system. Channel authentication +
sender authorization, container isolation + network sandbox, surrogate
credentials + environment-only injection — each layer catches threats the others
might miss.

## Security Layers

The following diagram shows the security controls at each layer:

```
┌──────────────────────────────────────────────────────────────────┐
│                 Channel Authentication Layer                     │
│  ┌───────────────────┐  ┌──────────────────────────────────┐     │
│  │ Email: DMARC      │  │ Sender Authorization             │     │
│  │ Slack: Socket Mode│  │ (allowlist / rules)              │     │
│  └───────────────────┘  └──────────────────────────────────┘     │
├──────────────────────────────────────────────────────────────────┤
│                      Execution Layer                             │
│  ┌───────────────────┐  ┌──────────────────────────────────┐     │
│  │ Container         │  │ Filesystem Mount Restrictions    │     │
│  │ Isolation         │  │                                  │     │
│  └───────────────────┘  └──────────────────────────────────┘     │
├──────────────────────────────────────────────────────────────────┤
│                       Network Layer                              │
│  ┌───────────────────┐  ┌──────────────────────────────────┐     │
│  │ Internal Network +│  │ Proxy Allowlist Enforcement      │     │
│  │ DNS Control       │  │ (HTTP/HTTPS + DNS)               │     │
│  └───────────────────┘  └──────────────────────────────────┘     │
├──────────────────────────────────────────────────────────────────┤
│                     Credential Layer                             │
│  ┌───────────────────┐  ┌──────────────────────────────────┐     │
│  │ Environment-only  │  │ Surrogate Credentials            │     │
│  │ secrets           │  │ (Masked/Signing/GitHub App)      │     │
│  └───────────────────┘  └──────────────────────────────────┘     │
├──────────────────────────────────────────────────────────────────┤
│                     Dashboard Layer                              │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Localhost binding + reverse proxy authentication (ext.)   │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Channel Authentication

Each channel implements its own authentication model. The channel adapter is
responsible for verifying sender identity and checking authorization before the
core processes any message.

### Email: DMARC Verification

Airut verifies sender identity via DMARC before processing any email. This
prevents spoofed emails from triggering code execution.

The authentication flow validates the `From` header against
`Authentication-Results` headers from the configured `trusted_authserv_id` (your
mail server). Only the first (topmost) header is examined — lower headers may be
attacker-injected. After authentication, the sender is checked against the
per-repo `authorized_senders` allowlist.

Both layers must pass. A valid DMARC pass from an unauthorized sender is
rejected.

See [email-setup.md](email-setup.md#dmarc-requirements) for DMARC setup and
[spec/authentication.md](../spec/authentication.md) for the full verification
flow, From header parsing, Microsoft 365 quirks, and authorization details.

### Slack: Socket Mode + Authorization Rules

Slack authentication is structurally different from email. The service
establishes an outbound WebSocket connection using an app-level token
(`xapp-...`). The connection is secured at two levels:

**Transport security (MITM protection):** The Slack SDK connects to Slack's API
over HTTPS (`https://slack.com/api/`) to obtain a `wss://` WebSocket URL via
`apps.connections.open`. Both the HTTPS API call and the WebSocket connection
use TLS with server certificate validation enforced — the SDK uses Python's
`ssl.create_default_context()`, which enables certificate verification
(`CERT_REQUIRED`), hostname checking, and the system CA bundle. A MITM attacker
cannot intercept or tamper with the connection without a valid certificate for
Slack's domain.

**Application-level authentication:** The app-level token (`xapp-...`) is
verified during the Socket Mode handshake. Once connected, all events arrive
over this pre-authenticated channel with no per-event signature verification
needed. The `user` field in Socket Mode events is guaranteed by Slack to be the
actual sender — there is no equivalent of email spoofing. Identity is
platform-enforced.

After identity verification, the sender is checked against per-repo `authorized`
rules. Baseline checks always reject bots, deactivated users, and external users
(team_id mismatch). Then rules are evaluated in order (first match wins):
`workspace_members`, `user_group`, or `user_id`.

Both layers must pass. A valid Slack user who doesn't match any authorization
rule is rejected.

See [slack-setup.md](slack-setup.md#authorization-rules) for rule configuration
and [spec/slack-channel.md](../spec/slack-channel.md) for the full
specification.

## Execution Isolation

See [execution-sandbox.md](execution-sandbox.md) for full details.

**Key properties:**

- Each conversation runs in a dedicated Podman container
- All Linux capabilities dropped (`--cap-drop=ALL`)
- Privilege escalation blocked (`--security-opt=no-new-privileges:true`)
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
      password: !env EMAIL_PASSWORD     # Channel credentials
    slack:
      bot_token: !env SLACK_BOT_TOKEN
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
- Git sends credentials as Basic Auth (`x-access-token:<token>`); the proxy
  decodes and replaces the surrogate transparently

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
headers — it is used to compute HMAC (SigV4) or ECDSA (SigV4A) signatures over
the request. Simple string replacement cannot work.

`signing_credentials` solve this by injecting **surrogate** AWS credentials
(format-preserving: same AKIA/ASIA prefix, same lengths) into the container. The
AWS SDK signs requests normally using the surrogates, and the proxy **re-signs**
with the real credentials for scoped hosts. This works with any S3-compatible
API (AWS, Cloudflare R2, MinIO, etc.).

As with masked secrets, the repo config is transparent — it uses
`!secret AWS_ACCESS_KEY_ID` just like any other secret. The server admin decides
whether to use plain secrets or signing credentials.

See
[network-sandbox.md](network-sandbox.md#signing-credentials-aws-sigv4-re-signing)
for the full details and
[spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) for the
specification.

### GitHub App Credentials (Token Rotation)

Masked secrets protect credentials from exfiltration, but GitHub API responses
can echo the authentication token back in the response body (the "response echo"
problem). Since the proxy only scrubs outbound requests (not inbound responses),
a compromised container could extract a leaked PAT from a response. A classic
PAT is long-lived, so this provides persistent access beyond the sandbox
session.

`github_app_credentials` solve this by eliminating long-lived tokens entirely.
The container receives a stable `ghs_`-prefixed surrogate in `GH_TOKEN`. The
proxy holds the GitHub App private key and generates short-lived **installation
access tokens** (1-hour expiry) on demand. Token rotation is invisible to the
container -- the surrogate never changes.

**Security properties:**

- **Private key isolation**: The RSA private key only exists in the proxy
  container, never in the client container
- **Short-lived tokens**: Even if leaked via response echo, installation tokens
  expire in 1 hour
- **No token escalation**: A leaked installation token cannot generate
  additional tokens (that requires JWT authentication with the private key)
- **No repository creation**: GitHub Apps cannot create repositories unless
  explicitly granted `Administration: write`
- **Scope enforcement**: Same as masked secrets -- proxy only replaces for
  matching hosts, foreign credentials are stripped

See [github-app-setup.md](github-app-setup.md) for the setup guide and
[network-sandbox.md](network-sandbox.md#github-app-credentials-proxy-managed-token-rotation)
for the proxy implementation details.

## Dashboard Security

The dashboard binds to localhost (`127.0.0.1:5200`) by default:

- **No built-in authentication**: Assumes reverse proxy handles auth
- **Localhost only**: Not exposed to network without explicit configuration
- **Minimal actions**: Only action is stopping running tasks

For production, deploy behind an authenticating reverse proxy (nginx, Caddy,
etc.) that handles user authentication before forwarding to the dashboard.

The dashboard exposes:

- Conversation IDs and message subjects
- Task timing and status
- Session metadata and actions
- Network activity logs

This is acceptable for a single-user system behind authentication.

## Attack Surface Analysis

| Risk                  | Mitigation                                                                    |
| --------------------- | ----------------------------------------------------------------------------- |
| Email spoofing        | DMARC verification on trusted headers                                         |
| Slack identity misuse | Platform-enforced identity + authorization rules                              |
| Unauthorized access   | Sender allowlist (email) / authorized rules (Slack)                           |
| Bot-to-bot loops      | Slack adapter rejects bot users; email uses DMARC                             |
| Code execution escape | Podman container isolation, all capabilities dropped, no privilege escalation |
| Data exfiltration     | Network allowlist via proxy                                                   |
| Credential theft      | Environment-only secrets, no host mounts                                      |
| Cross-session attack  | Per-conversation isolation (workspace, network)                               |
| Resource exhaustion   | Timeout, conversation limit, garbage collection                               |
| Log leakage           | Automatic secret redaction (passwords and tokens)                             |
| Dashboard access      | Localhost binding, reverse proxy auth                                         |
| Workflow escape       | Sandbox CI, omit `workflow` scope / GitHub App without `Workflows` permission |

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

**Email:**

- Missing `trusted_authserv_id`: Authentication fails (reject all)
- Empty `authorized_senders`: Authorization fails (reject all)
- DMARC check failure: Message rejected (no processing)

**Slack:**

- TLS certificate validation failure: WebSocket connection refused (no events)
- Invalid app token: Socket Mode connection fails (no events received)
- Empty `authorized` rules: Config validation fails at startup
- User info API failure: Authorization fails (reject request)
- Unknown user group: Rule rejects all users (with warning in logs)

**Shared:**

- Proxy startup failure: Task aborts (no unproxied execution)
- Secret resolution failure: Task aborts (no missing credentials)

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

1. **Use surrogate credentials** — Real credentials configured as
   `github_app_credentials`, `masked_secrets`, or `signing_credentials` never
   enter the container. The proxy inserts them into upstream requests only for
   scoped hosts. A compromised container can still act within the boundaries of
   what the credentials and scopes allow (e.g., make API calls to scoped hosts),
   but cannot extract the real credentials. For GitHub access specifically,
   `github_app_credentials` are preferred — even if a token is leaked via
   response echo, it expires in 1 hour. The ability to act is bound to the
   container's lifetime and the proxy's enforcement — once the container stops,
   or if the attacker tries to use the credentials from outside, they are
   useless. This is the strongest mitigation for credential exfiltration.
2. **Scope credentials to minimum** — A token that can only push to one repo
   limits exfiltration to that repo
3. **Review agent outputs** — PRs, commits, and channel replies are human review
   points
4. **Audit network logs** — `network-sandbox.log` shows all requests for
   forensic analysis

### GitHub Actions Workflow Escape

GitHub Actions workflows execute code from PR branches on runners with outbound
internet access — completely outside the Airut network sandbox. The agent can
exploit this in two ways: by pushing a malicious workflow file, or by modifying
code that existing workflows execute (test suites, build scripts, linters). The
second path requires no special permissions beyond normal git push access,
making it the harder threat to close. See [ci-sandbox.md](ci-sandbox.md) for the
recommended mitigation (running CI inside the Airut sandbox).

**Threat model:** This threat vector is relevant when the
[lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
(coined by Simon Willison) is present — all three conditions simultaneously:

1. **Access to private data** — The repository contains private code, secrets
   accessible to Actions, or other sensitive material
2. **Exposure to untrusted content** — The agent processes content controlled by
   a potential attacker (repository files with user input, fetched web pages,
   email attachments, Slack file uploads)
3. **Ability to externally communicate** — The agent can exfiltrate data through
   some channel. In this case, GitHub Actions runners have outbound internet
   access — a workflow escape gives the attacker a runner that can communicate
   with arbitrary external hosts, completely outside the network sandbox

The workflow escape is the mechanism that provides capability (3): even though
the container's network sandbox restricts outbound access, code running on a
GitHub-hosted runner (whether from a pushed workflow file or from existing
workflows executing agent-modified code) operates completely outside the
sandbox.

**The escape has two paths**, both of which must be closed:

- **Modify workflow files directly** — Push a new or altered workflow that runs
  attacker-controlled code. Requires the `GH_TOKEN` to have the `workflow` scope
  (classic PAT), `Workflows: Read and write` permission (fine-grained PAT), or
  the `Workflows` permission (GitHub App).
- **Modify code that workflows execute** — Most CI workflows run repository code
  (e.g., `uv run pytest`, `npm test`, build scripts). The agent can alter that
  code to perform arbitrary actions when the workflow executes it, without
  touching the workflow file at all. This only requires
  `Contents: Read and write` (which the agent needs for normal git operations)
  plus a workflow trigger the agent can activate (`on: pull_request` or
  `on: push`).

If the lethal trifecta is not present, the escape is not a meaningful threat.
For example:

- **Public repositories with no Actions secrets** — There is no private data to
  exfiltrate (condition 1 absent). Workflow escape gives the attacker a runner
  with outbound access but nothing sensitive to steal. (Note: if the repo's
  Actions configuration grants access to organization secrets, this does not
  apply.)
- **Network sandbox blocks untrusted content** — If the agent only processes
  trusted prompts and the network allowlist prevents fetching adversarial
  content, prompt injection cannot be triggered in the first place (condition 2
  absent).

**Mitigations:**

1. **Run CI inside the Airut sandbox (recommended)** — Use the
   [`airutorg/sandbox-action`](ci-sandbox.md) GitHub Action to run CI commands
   inside the same container isolation, network allowlisting, and credential
   masking that the Airut gateway uses. The workflow auto-triggers on PRs, but
   agent-steerable code runs inside a sandboxed container — not directly on the
   runner. Even if the agent injects malicious code into test suites or build
   scripts, the sandbox prevents exfiltration. This closes path 2 while
   preserving auto-triggered CI. **This is the recommended approach** and must
   be combined with mitigation 2 (protecting workflow files) to close both
   paths. See [ci-sandbox.md](ci-sandbox.md) for the full setup guide.
2. **Prevent the agent from modifying workflow files** — The agent must not be
   able to push changes to `.github/workflows/`. Three mechanisms are available:
   using a GitHub App without `Workflows` permission (recommended — GitHub
   enforces at push time), omitting the `workflow` scope from a classic PAT, or
   using a push ruleset to block workflow file changes (Teams/Enterprise plans).
   These can be combined for defense in depth. See
   [ci-sandbox.md](ci-sandbox.md#1-protecting-workflow-files) for setup
   instructions.
   - **Limitation**: This alone is not sufficient — the agent cannot modify
     workflow files, but can still modify code that workflows execute (path 2).
     Mitigation 1 (sandboxed CI) or mitigation 3 (manual triggers) is needed to
     close path 2.
3. **Use `workflow_dispatch` instead of `pull_request` triggers (fallback)** —
   Workflows that use `on: workflow_dispatch` can only be triggered manually
   from the GitHub UI or API by an authorized user. Even if the agent pushes
   malicious code, the workflow will not run until a human explicitly triggers
   it. This closes path 2 but **sacrifices auto-triggered CI**. Combined with
   mitigation 2, this closes both paths. Use this approach when sandboxed CI
   (mitigation 1) is not feasible — for example, workflows that require
   capabilities the sandbox cannot provide (GPU access, specific hardware,
   non-containerizable tools).

**When is this relevant?** Evaluate whether the lethal trifecta is present:

- If your repository is **public with no Actions secrets**: Low risk. No private
  data to steal (condition 1 absent).
- If your repository is **private or has Actions secrets**: Apply mitigations 1
  and 2 (sandboxed CI + workflow file protection). Use mitigation 3 as a
  fallback for workflows that cannot run in the sandbox.
- If the agent processes **untrusted content** (user-submitted issues, external
  web pages, email attachments from untrusted senders): Apply mitigations 1 and
  2\.
- If the agent only processes **trusted prompts from authorized senders** and
  the network sandbox prevents fetching adversarial content: Lower risk
  (condition 2 absent), but mitigation 2 is still recommended as defense in
  depth.

### Realistic Security Expectations

In practice, trusting all content the agent processes is not possible.
Repository files may contain untrusted user input. Fetched web pages may have
adversarial content. Email attachments or Slack file uploads may be crafted by
attackers who know the system.

**Security is therefore statistical rather than absolute.** The goal is to:

1. Make attacks significantly harder than on an unsandboxed system
2. Limit blast radius when attacks succeed
3. Provide audit trails for detection and response
4. Enable configuration that tilts odds strongly toward security

Proper configuration — tight network allowlist, scoped credentials, reviewed
repository content — makes successful exploitation substantially less likely and
less damaging. But no configuration eliminates risk entirely when processing
untrusted content with an AI agent.
