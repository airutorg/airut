# Repo Configuration

All per-repo configuration lives in the **server config**
(`~/.config/airut/airut.yaml`). There is no repo-side `airut.yaml` for the
gateway. The server config is the single source of truth for model, effort,
resource limits, network sandbox toggle, and credential pools.

Repository-side files that remain in `.airut/`:

- `.airut/network-allowlist.yaml` — network sandbox allowlist (read from git
  mirror's default branch at task start)
- `.airut/container/Dockerfile` — repo-defined container base image
- `.airut/sandbox.yaml` — sandbox CLI config (used by `airut-sandbox` /
  `sandbox-action` only, not the gateway)

## Per-Repo Schema in Server Config

Each repo is defined under `repos.<repo_id>` in the server config. The complete
field reference — types, defaults, descriptions, and commented examples — is in
[`config/airut.example.yaml`](../config/airut.example.yaml). For the config
infrastructure (field metadata, migrations, diffing, variables), see
[declarative-config.md](declarative-config.md).

## Credential Auto-Injection

All credential pool entries auto-inject into the container as environment
variables by their key name. Declaring a secret in any credential pool
automatically makes it available as an env var.

**Priority ordering** for duplicate env var names (first match wins):

1. `signing_credentials` (by field `.name` values)
2. `github_app_credentials` (by key)
3. `masked_secrets` (by key)
4. `secrets` (by key)

When the same env var name appears in multiple pools, the highest-priority pool
wins. This allows upgrading a credential from plain `secrets` to
`masked_secrets` without removing the old entry (though removing it is cleaner).

All resolved values are registered for log redaction.

## Model and Effort

The `model` field defaults to `"opus"`. For new conversations, the priority is:

| Priority | Model                             | Effort                       |
| -------- | --------------------------------- | ---------------------------- |
| 1        | channel `model_hint` (e.g. email) | `repos.<id>.effort` (server) |
| 2        | `repos.<id>.model` (server)       | *(none -- Claude default)*   |

Resumed conversations always use the model and effort stored at conversation
creation time, regardless of current server config.

## Resource Limits via Variables

Shared resource limit defaults are defined as variables in the `vars:` section
and referenced with `!var` in each repo. This replaces the former top-level
`resource_limits` block (migrated automatically in config version 3). All fields
are optional. Omitted fields mean no limit for that dimension. Repos can
override any field to a literal value or reference a different variable. See
[`config/airut.example.yaml`](../config/airut.example.yaml) for the full `vars:`
and `resource_limits:` examples, and
[declarative-config.md](declarative-config.md#config-variables) for `!var`
syntax and resolution.

## What Stays in the Repository

### Network Allowlist

`.airut/network-allowlist.yaml` remains in the repository. It is read from the
git mirror's default branch at task start. The agent can propose changes via PR,
but a human must review and merge before the change takes effect.

### Container Dockerfile

The container Dockerfile remains in the repository. By default it is read from
`.airut/container/Dockerfile`, but the directory can be overridden per-repo via
`container.path` in the server config (e.g., `.devcontainer` to reuse an
existing devcontainer Dockerfile). The container image is rebuilt from the
repository's default branch at every task start.

### Sandbox CLI Config

`.airut/sandbox.yaml` is used by `airut-sandbox run` (the standalone CLI for CI
pipelines). It is not used by the Airut gateway service.

## Server Config Reference

The complete field reference with types, defaults, and descriptions is in
[`config/airut.example.yaml`](../config/airut.example.yaml). Per-repo config is
nested under `repos.<repo_id>`; global settings (`execution`, `dashboard`,
`network`, `vars`) live at the top level.

**Important:** All channel-specific fields must be nested under their channel
block (`email:` or `slack:`). A repo must have at least one channel block
configured. Multiple channels can coexist under the same repo — each runs its
own listener and feeds messages through the shared processing pipeline.

## Loading Flow

1. Service starts, loads server config (`ServerConfig.from_yaml()`)
2. Per-repo settings (model, effort, resource limits, network, all credential
   pools) are parsed from the server config
3. Mirror is updated (`mirror.update_mirror()`)
4. Network allowlist and container Dockerfile are read from the mirror's default
   branch
5. Credential pool entries are resolved and prepared (surrogates generated for
   masked/signing/GitHub App credentials)
6. All resolved env var values are registered with `SecretFilter`
7. Fields are validated (timeout >= 10, etc.)

## Multi-Repo Support

The server supports multiple repositories. Each repo is defined under `repos:`
in the server config with its own channel blocks (e.g. `email:` for IMAP/SMTP),
storage directory, and credential pools. A repo can have multiple channel blocks
configured simultaneously. See `multi-repo.md` for the full design.

## Proxy Manager Lifecycle

Since `network.sandbox_enabled` is per-repo, the `ProxyManager` is always
created and its gateway infrastructure (egress network, proxy image, CA cert) is
set up at startup. Per-conversation proxy containers are only started when the
repo has `network.sandbox_enabled: true`.
