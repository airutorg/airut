# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Secret masking and surrogate generation for the sandbox.

The sandbox owns surrogate generation for masked secrets and signing
credentials. Callers provide real secret values with scope metadata;
the sandbox generates surrogates, returns them so the caller can inject
them into ContainerEnv, and configures the proxy replacement map
internally.
"""

from __future__ import annotations

import secrets as secrets_module
from dataclasses import dataclass, field

from airut._json_types import JsonDict


# Known token prefixes to preserve during surrogate generation.
_TOKEN_PREFIXES = (
    "github_pat_",  # GitHub fine-grained PAT
    "ghp_",  # GitHub personal access token
    "gho_",  # GitHub OAuth token
    "ghs_",  # GitHub server-to-server token
    "ghr_",  # GitHub refresh token
    "sk-ant-",  # Anthropic API key
    "sk-",  # OpenAI API key
    "xoxb-",  # Slack bot token
    "xoxp-",  # Slack user token
    "AKIA",  # AWS long-term access key ID
    "ASIA",  # AWS temporary access key ID (STS)
)

# Fixed length for STS session token surrogates.
_SESSION_TOKEN_SURROGATE_LENGTH = 512


@dataclass(frozen=True)
class MaskedSecret:
    """A secret that should be masked with a surrogate in the container.

    The sandbox generates a surrogate token, the caller injects the
    surrogate into ContainerEnv, and the proxy swaps it for the real
    value when the request host matches a scope pattern.

    Attributes:
        env_var: Environment variable name for the container.
        real_value: The actual secret value.
        scopes: Fnmatch patterns for hosts where replacement is allowed.
        headers: Fnmatch patterns for headers to scan.
        allow_foreign_credentials: If False (default), headers matching
            scope+header patterns that do NOT contain the surrogate are
            stripped. Prevents attacker-supplied credentials on scoped hosts.
    """

    env_var: str
    real_value: str
    scopes: tuple[str, ...]
    headers: tuple[str, ...]
    allow_foreign_credentials: bool = False


@dataclass(frozen=True)
class SigningCredential:
    """AWS SigV4 signing credential for proxy re-signing.

    Unlike masked secrets (simple token replacement), signing credentials
    require the proxy to re-sign requests. The sandbox generates surrogates
    for the access key ID (and session token if present) and returns them
    so the caller can inject them into ContainerEnv.

    Attributes:
        access_key_id_env_var: Env var name for the access key ID.
        access_key_id: Real access key ID value.
        secret_access_key_env_var: Env var name for the secret access key.
        secret_access_key: Real secret access key value.
        session_token_env_var: Optional env var name for session token.
        session_token: Optional real session token value.
        scopes: Fnmatch patterns for allowed hosts.
    """

    access_key_id_env_var: str
    access_key_id: str
    secret_access_key_env_var: str
    secret_access_key: str
    session_token_env_var: str | None
    session_token: str | None
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class _ReplacementEntry:
    """Internal entry for proxy token replacement."""

    real_value: str
    scopes: tuple[str, ...]
    headers: tuple[str, ...]
    allow_foreign_credentials: bool = False

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export."""
        d: JsonDict = {
            "value": self.real_value,
            "scopes": list(self.scopes),
            "headers": list(self.headers),
        }
        if self.allow_foreign_credentials:
            d["allow_foreign_credentials"] = True
        return d


@dataclass(frozen=True)
class _SigningCredentialEntry:
    """Internal entry for AWS signing credential replacement."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None
    surrogate_session_token: str | None
    scopes: tuple[str, ...]

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export."""
        return {
            "type": "aws-sigv4",
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key,
            "session_token": self.session_token,
            "surrogate_session_token": self.surrogate_session_token,
            "scopes": list(self.scopes),
        }


@dataclass(frozen=True)
class GitHubAppCredential:
    """GitHub App credential for proxy-managed token rotation.

    The sandbox generates a ``ghs_``-prefixed surrogate and includes the
    App credential metadata in the replacement map so the proxy can
    manage token lifecycle transparently.

    Attributes:
        env_var: Environment variable name for the container.
        app_id: GitHub App Client ID or numeric App ID.
        private_key: PEM-encoded RSA private key.
        installation_id: Installation ID for the target org/user.
        scopes: Fnmatch patterns for allowed hosts.
        allow_foreign_credentials: Whether to allow non-surrogate credentials.
        base_url: GitHub API base URL.
        permissions: Optional token permission restrictions.
        repositories: Optional token repository restrictions.
    """

    env_var: str
    app_id: str
    private_key: str
    installation_id: str
    scopes: tuple[str, ...]
    allow_foreign_credentials: bool = False
    base_url: str = "https://api.github.com"
    permissions: dict[str, str] | None = None
    repositories: tuple[str, ...] | None = None


@dataclass(frozen=True)
class _GitHubAppEntry:
    """Internal entry for GitHub App credential replacement."""

    app_id: str
    private_key: str
    installation_id: str
    base_url: str
    scopes: tuple[str, ...]
    allow_foreign_credentials: bool = False
    permissions: dict[str, str] | None = None
    repositories: tuple[str, ...] | None = None

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export."""
        d: JsonDict = {
            "type": "github-app",
            "app_id": self.app_id,
            "private_key": self.private_key,
            "installation_id": self.installation_id,
            "base_url": self.base_url,
            "scopes": list(self.scopes),
        }
        if self.allow_foreign_credentials:
            d["allow_foreign_credentials"] = True
        if self.permissions is not None:
            d["permissions"] = dict(self.permissions)
        if self.repositories is not None:
            d["repositories"] = list(self.repositories)
        return d


@dataclass(frozen=True)
class SecretReplacements:
    """Opaque container for proxy replacement configuration.

    Created by prepare_secrets(). Passed to NetworkSandboxConfig.
    The caller does not inspect or modify this -- the sandbox uses it
    internally to configure the proxy.
    """

    _map: dict[
        str,
        _ReplacementEntry | _SigningCredentialEntry | _GitHubAppEntry,
    ] = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export (internal use)."""
        return {
            surrogate: entry.to_dict() for surrogate, entry in self._map.items()
        }


@dataclass(frozen=True)
class PreparedSecrets:
    """Result of surrogate generation.

    Contains the environment variables to inject into the container
    (with surrogates instead of real values) and the replacement
    configuration for the proxy.

    Attributes:
        env_vars: Mapping of env var names to surrogate values.
        replacements: Opaque replacement config for NetworkSandboxConfig.
    """

    env_vars: dict[str, str]
    replacements: SecretReplacements


def generate_surrogate(original: str) -> str:
    """Generate a surrogate token that mimics the original's format.

    Preserves:
    - Exact length
    - Character set (uppercase, lowercase, digits, common special chars)
    - Known prefixes (ghp_, sk-ant-, etc.)

    Args:
        original: The original secret value.

    Returns:
        A random surrogate with matching format.
    """
    # Detect and preserve known prefix
    prefix = ""
    suffix_source = original
    for known in _TOKEN_PREFIXES:
        if original.startswith(known):
            prefix = known
            suffix_source = original[len(known) :]
            break

    # Analyze character set of the suffix
    has_upper = any(c.isupper() for c in suffix_source)
    has_lower = any(c.islower() for c in suffix_source)
    has_digit = any(c.isdigit() for c in suffix_source)
    has_special = any(not c.isalnum() for c in suffix_source)

    # Build charset for surrogate generation
    charset = ""
    if has_upper:
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if has_lower:
        charset += "abcdefghijklmnopqrstuvwxyz"
    if has_digit:
        charset += "0123456789"
    if has_special:
        charset += "-_"

    # Fallback if charset detection failed (e.g., empty suffix)
    if not charset:
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"

    # Generate random suffix of matching length
    suffix_len = len(suffix_source)
    random_suffix = "".join(
        secrets_module.choice(charset) for _ in range(suffix_len)
    )

    return prefix + random_suffix


def generate_session_token_surrogate() -> str:
    """Generate a fixed-length surrogate for AWS STS session tokens.

    STS tokens vary in length (400-1200+ chars). The surrogate uses a
    fixed length to avoid leaking information about the real token.

    Returns:
        A random 512-character alphanumeric string.
    """
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(
        secrets_module.choice(charset)
        for _ in range(_SESSION_TOKEN_SURROGATE_LENGTH)
    )


# Template for GitHub App surrogates: ghs_ prefix + 36 mixed-case
# alphanumeric chars = 40 chars total (matches real ghs_ token format).
_GITHUB_APP_SURROGATE_TEMPLATE = "ghs_" + "aA0" * 12


def prepare_secrets(
    masked_secrets: list[MaskedSecret],
    signing_credentials: list[SigningCredential],
    github_app_credentials: list[GitHubAppCredential] | None = None,
) -> PreparedSecrets:
    """Generate surrogates for secrets and signing credentials.

    For each masked secret, generates a surrogate that preserves the
    original token's format (length, charset, known prefix). For signing
    credentials, generates surrogates for access_key_id and session_token.
    For GitHub App credentials, generates ``ghs_``-prefixed surrogates.

    Args:
        masked_secrets: List of secrets to mask with surrogates.
        signing_credentials: List of AWS signing credentials.
        github_app_credentials: List of GitHub App credentials.

    Returns:
        PreparedSecrets containing env_vars (surrogates) and
        replacements (opaque config for the proxy).
    """
    env_vars: dict[str, str] = {}
    replacement_map: dict[
        str,
        _ReplacementEntry | _SigningCredentialEntry | _GitHubAppEntry,
    ] = {}

    # Process masked secrets
    for secret in masked_secrets:
        if not secret.real_value:
            # Empty string is a valid configured value
            env_vars[secret.env_var] = ""
            continue

        surrogate = generate_surrogate(secret.real_value)
        env_vars[secret.env_var] = surrogate
        replacement_map[surrogate] = _ReplacementEntry(
            real_value=secret.real_value,
            scopes=secret.scopes,
            headers=secret.headers,
            allow_foreign_credentials=secret.allow_foreign_credentials,
        )

    # Process signing credentials
    for cred in signing_credentials:
        surrogate_key_id = generate_surrogate(cred.access_key_id)
        env_vars[cred.access_key_id_env_var] = surrogate_key_id
        env_vars[cred.secret_access_key_env_var] = cred.secret_access_key

        surrogate_session_token: str | None = None
        if cred.session_token_env_var and cred.session_token:
            surrogate_session_token = generate_session_token_surrogate()
            env_vars[cred.session_token_env_var] = surrogate_session_token

        replacement_map[surrogate_key_id] = _SigningCredentialEntry(
            access_key_id=cred.access_key_id,
            secret_access_key=cred.secret_access_key,
            session_token=cred.session_token,
            surrogate_session_token=surrogate_session_token,
            scopes=cred.scopes,
        )

    # Process GitHub App credentials
    for gh_cred in github_app_credentials or []:
        surrogate = generate_surrogate(_GITHUB_APP_SURROGATE_TEMPLATE)
        env_vars[gh_cred.env_var] = surrogate
        replacement_map[surrogate] = _GitHubAppEntry(
            app_id=gh_cred.app_id,
            private_key=gh_cred.private_key,
            installation_id=gh_cred.installation_id,
            base_url=gh_cred.base_url,
            scopes=gh_cred.scopes,
            allow_foreign_credentials=gh_cred.allow_foreign_credentials,
            permissions=gh_cred.permissions,
            repositories=gh_cred.repositories,
        )

    return PreparedSecrets(
        env_vars=env_vars,
        replacements=SecretReplacements(_map=replacement_map),
    )
