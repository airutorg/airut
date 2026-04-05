# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for secret masking and surrogate generation."""

from typing import cast

from airut._json_types import JsonDict
from airut.sandbox.secrets import (
    _SESSION_TOKEN_SURROGATE_LENGTH,
    _TOKEN_PREFIXES,
    GitHubAppCredential,
    MaskedSecret,
    PreparedSecrets,
    SecretReplacements,
    SigningCredential,
    _GitHubAppEntry,
    _ReplacementEntry,
    _SigningCredentialEntry,
    generate_session_token_surrogate,
    generate_surrogate,
    prepare_secrets,
)


class TestGenerateSurrogate:
    """Tests for generate_surrogate function."""

    def test_preserves_length(self) -> None:
        """Surrogate has same length as original."""
        original = "abcdef12345678"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)

    def test_different_from_original(self) -> None:
        """Surrogate is different from original (overwhelmingly likely)."""
        original = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        surrogate = generate_surrogate(original)
        assert surrogate != original

    def test_preserves_github_pat_prefix(self) -> None:
        """Preserves github_pat_ prefix."""
        original = "github_pat_abc123def456ghi789"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("github_pat_")
        assert len(surrogate) == len(original)

    def test_preserves_ghp_prefix(self) -> None:
        """Preserves ghp_ prefix."""
        original = "ghp_abcdefghijklmnopqrstuvwxyz12345"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("ghp_")
        assert len(surrogate) == len(original)

    def test_preserves_sk_ant_prefix(self) -> None:
        """Preserves sk-ant- prefix."""
        original = "sk-ant-abcdefghij1234567890"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("sk-ant-")
        assert len(surrogate) == len(original)

    def test_preserves_sk_prefix(self) -> None:
        """Preserves sk- prefix."""
        original = "sk-abc123def456"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("sk-")
        assert len(surrogate) == len(original)

    def test_preserves_akia_prefix(self) -> None:
        """Preserves AKIA prefix for AWS long-term access key."""
        original = "AKIAIOSFODNN7EXAMPLE"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("AKIA")
        assert len(surrogate) == len(original)

    def test_preserves_asia_prefix(self) -> None:
        """Preserves ASIA prefix for AWS temporary access key."""
        original = "ASIATEMPORARY12345678"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("ASIA")
        assert len(surrogate) == len(original)

    def test_preserves_xoxb_prefix(self) -> None:
        """Preserves xoxb- prefix for Slack bot token."""
        original = "xoxb-TESTTOKEN"
        surrogate = generate_surrogate(original)
        assert surrogate.startswith("xoxb-")
        assert len(surrogate) == len(original)

    def test_preserves_uppercase_charset(self) -> None:
        """Surrogate uses uppercase when original is uppercase."""
        original = "ABCDEFGHIJK"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)
        assert surrogate.isupper() or all(
            c.isupper() or c.isdigit() for c in surrogate
        )

    def test_preserves_lowercase_charset(self) -> None:
        """Surrogate uses lowercase when original is lowercase."""
        original = "abcdefghijk"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)
        assert all(c.islower() for c in surrogate)

    def test_preserves_mixed_charset(self) -> None:
        """Surrogate uses mixed case when original has mixed case."""
        original = "AbCdEf123"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)

    def test_preserves_special_chars(self) -> None:
        """Surrogate includes special chars when original has them."""
        original = "abc-def_ghi"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)

    def test_empty_suffix_fallback(self) -> None:
        """Uses fallback charset when no prefix match and empty string."""
        # If we pass a prefix that exactly matches, suffix is empty
        # The prefix is returned directly
        original = "ghp_"
        surrogate = generate_surrogate(original)
        assert surrogate == "ghp_"

    def test_no_prefix_match(self) -> None:
        """Works with token that has no matching prefix."""
        original = "random-token-value-12345"
        surrogate = generate_surrogate(original)
        assert len(surrogate) == len(original)
        assert surrogate != original

    def test_all_known_prefixes_recognized(self) -> None:
        """All _TOKEN_PREFIXES are recognized and preserved."""
        for prefix in _TOKEN_PREFIXES:
            original = prefix + "abcdef12345"
            surrogate = generate_surrogate(original)
            assert surrogate.startswith(prefix), (
                f"Prefix {prefix} not preserved"
            )


class TestGenerateSessionTokenSurrogate:
    """Tests for generate_session_token_surrogate function."""

    def test_fixed_length(self) -> None:
        """Surrogate is exactly 512 characters."""
        surrogate = generate_session_token_surrogate()
        assert len(surrogate) == _SESSION_TOKEN_SURROGATE_LENGTH

    def test_alphanumeric(self) -> None:
        """Surrogate is alphanumeric only."""
        surrogate = generate_session_token_surrogate()
        assert surrogate.isalnum()

    def test_different_each_time(self) -> None:
        """Each call produces a different surrogate."""
        s1 = generate_session_token_surrogate()
        s2 = generate_session_token_surrogate()
        assert s1 != s2


class TestPrepareSecrets:
    """Tests for prepare_secrets function."""

    def test_masked_secrets(self) -> None:
        """Generates surrogates for masked secrets."""
        secrets = [
            MaskedSecret(
                env_var="GH_TOKEN",
                real_value="ghp_realtoken12345678901234567890",
                scopes=("api.github.com",),
                headers=("Authorization",),
            ),
        ]

        result = prepare_secrets(secrets, [])

        assert isinstance(result, PreparedSecrets)
        assert "GH_TOKEN" in result.env_vars
        surrogate = result.env_vars["GH_TOKEN"]
        assert surrogate.startswith("ghp_")
        assert surrogate != "ghp_realtoken12345678901234567890"
        assert len(surrogate) == len("ghp_realtoken12345678901234567890")

        # Verify replacement map
        replacements_dict = result.replacements.to_dict()
        assert surrogate in replacements_dict
        entry = cast(JsonDict, replacements_dict[surrogate])
        assert entry["value"] == "ghp_realtoken12345678901234567890"
        assert entry["scopes"] == ["api.github.com"]
        assert entry["headers"] == ["Authorization"]

    def test_empty_secret_value(self) -> None:
        """Empty secret value is passed through without surrogate."""
        secrets = [
            MaskedSecret(
                env_var="OPTIONAL_KEY",
                real_value="",
                scopes=("api.example.com",),
                headers=("Authorization",),
            ),
        ]

        result = prepare_secrets(secrets, [])

        assert result.env_vars["OPTIONAL_KEY"] == ""
        # No replacement entry for empty values
        assert len(result.replacements.to_dict()) == 0

    def test_multiple_masked_secrets(self) -> None:
        """Handles multiple masked secrets."""
        secrets = [
            MaskedSecret(
                env_var="TOKEN_A",
                real_value="sk-ant-realvalueA123456789",
                scopes=("api.anthropic.com",),
                headers=("x-api-key",),
            ),
            MaskedSecret(
                env_var="TOKEN_B",
                real_value="ghp_realvalueB1234567890123456",
                scopes=("api.github.com",),
                headers=("Authorization",),
            ),
        ]

        result = prepare_secrets(secrets, [])

        assert len(result.env_vars) == 2
        assert result.env_vars["TOKEN_A"].startswith("sk-ant-")
        assert result.env_vars["TOKEN_B"].startswith("ghp_")
        assert len(result.replacements.to_dict()) == 2

    def test_signing_credentials(self) -> None:
        """Generates surrogates for AWS signing credentials."""
        credentials = [
            SigningCredential(
                access_key_id_env_var="AWS_ACCESS_KEY_ID",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                session_token_env_var=None,
                session_token=None,
                scopes=("s3.us-east-1.amazonaws.com",),
            ),
        ]

        result = prepare_secrets([], credentials)

        assert "AWS_ACCESS_KEY_ID" in result.env_vars
        surrogate_key = result.env_vars["AWS_ACCESS_KEY_ID"]
        assert surrogate_key.startswith("AKIA")
        assert surrogate_key != "AKIAIOSFODNN7EXAMPLE"

        # Secret access key is passed through as-is
        assert (
            result.env_vars["AWS_SECRET_ACCESS_KEY"]
            == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        # Verify replacement map has signing credential entry
        replacements_dict = result.replacements.to_dict()
        assert surrogate_key in replacements_dict
        entry = cast(JsonDict, replacements_dict[surrogate_key])
        assert entry["type"] == "aws-sigv4"
        assert entry["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert (
            entry["secret_access_key"]
            == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        assert entry["session_token"] is None
        assert entry["surrogate_session_token"] is None

    def test_signing_credentials_with_session_token(self) -> None:
        """Generates surrogates for signing credentials with session token."""
        credentials = [
            SigningCredential(
                access_key_id_env_var="AWS_ACCESS_KEY_ID",
                access_key_id="ASIATEMPORARY12345678",
                secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
                secret_access_key="tempSecretKey",
                session_token_env_var="AWS_SESSION_TOKEN",
                session_token="FwoGZXIvY...long_session_token",
                scopes=("bedrock.us-east-1.amazonaws.com",),
            ),
        ]

        result = prepare_secrets([], credentials)

        assert "AWS_ACCESS_KEY_ID" in result.env_vars
        assert "AWS_SECRET_ACCESS_KEY" in result.env_vars
        assert "AWS_SESSION_TOKEN" in result.env_vars

        surrogate_key = result.env_vars["AWS_ACCESS_KEY_ID"]
        assert surrogate_key.startswith("ASIA")

        # Session token surrogate has fixed length
        session_surrogate = result.env_vars["AWS_SESSION_TOKEN"]
        assert len(session_surrogate) == _SESSION_TOKEN_SURROGATE_LENGTH

        # Replacement entry includes session token info
        replacements_dict = result.replacements.to_dict()
        entry = cast(JsonDict, replacements_dict[surrogate_key])
        assert entry["session_token"] == "FwoGZXIvY...long_session_token"
        assert entry["surrogate_session_token"] == session_surrogate

    def test_mixed_secrets_and_credentials(self) -> None:
        """Handles both masked secrets and signing credentials."""
        secrets = [
            MaskedSecret(
                env_var="GH_TOKEN",
                real_value="ghp_mixedtest123456789012345678",
                scopes=("api.github.com",),
                headers=("Authorization",),
            ),
        ]
        credentials = [
            SigningCredential(
                access_key_id_env_var="AWS_ACCESS_KEY_ID",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
                secret_access_key="secretkey",
                session_token_env_var=None,
                session_token=None,
                scopes=("s3.amazonaws.com",),
            ),
        ]

        result = prepare_secrets(secrets, credentials)

        assert len(result.env_vars) == 3  # GH_TOKEN + AWS key pair
        assert len(result.replacements.to_dict()) == 2

    def test_empty_inputs(self) -> None:
        """Returns empty results for empty inputs."""
        result = prepare_secrets([], [])

        assert result.env_vars == {}
        assert result.replacements.to_dict() == {}

    def test_allow_foreign_credentials_threaded(self) -> None:
        """allow_foreign_credentials is threaded to replacement map."""
        secrets = [
            MaskedSecret(
                env_var="TOKEN",
                real_value="ghp_realtoken12345678901234567890",
                scopes=("api.github.com",),
                headers=("Authorization",),
                allow_foreign_credentials=True,
            ),
        ]
        result = prepare_secrets(secrets, [])

        surrogate = result.env_vars["TOKEN"]
        replacements_dict = result.replacements.to_dict()
        entry = cast(JsonDict, replacements_dict[surrogate])
        assert entry["allow_foreign_credentials"] is True

    def test_allow_foreign_credentials_default_omitted(self) -> None:
        """Default allow_foreign_credentials=False is omitted from JSON."""
        secrets = [
            MaskedSecret(
                env_var="TOKEN",
                real_value="ghp_realtoken12345678901234567890",
                scopes=("api.github.com",),
                headers=("Authorization",),
            ),
        ]
        result = prepare_secrets(secrets, [])

        surrogate = result.env_vars["TOKEN"]
        replacements_dict = result.replacements.to_dict()
        entry = cast(JsonDict, replacements_dict[surrogate])
        assert "allow_foreign_credentials" not in entry


class TestSecretReplacements:
    """Tests for SecretReplacements dataclass."""

    def test_empty_replacements(self) -> None:
        """Empty replacements serializes to empty dict."""
        r = SecretReplacements()
        assert r.to_dict() == {}

    def test_to_dict_with_replacement_entry(self) -> None:
        """Serializes replacement entries correctly."""
        entry = _ReplacementEntry(
            real_value="real",
            scopes=("scope1",),
            headers=("header1",),
        )
        r = SecretReplacements(_map={"surrogate": entry})
        d = r.to_dict()
        assert "surrogate" in d
        entry = cast(JsonDict, d["surrogate"])
        assert entry["value"] == "real"
        assert entry["scopes"] == ["scope1"]
        assert entry["headers"] == ["header1"]
        assert "allow_foreign_credentials" not in entry

    def test_to_dict_with_allow_foreign_credentials(self) -> None:
        """Serializes allow_foreign_credentials when True."""
        entry = _ReplacementEntry(
            real_value="real",
            scopes=("scope1",),
            headers=("header1",),
            allow_foreign_credentials=True,
        )
        r = SecretReplacements(_map={"surrogate": entry})
        d = r.to_dict()
        d_entry = cast(JsonDict, d["surrogate"])
        assert d_entry["allow_foreign_credentials"] is True

    def test_to_dict_with_signing_credential_entry(self) -> None:
        """Serializes signing credential entries correctly."""
        entry = _SigningCredentialEntry(
            access_key_id="AKIA_REAL",
            secret_access_key="secret",
            session_token=None,
            surrogate_session_token=None,
            scopes=("s3.amazonaws.com",),
        )
        r = SecretReplacements(_map={"surrogate_key": entry})
        d = r.to_dict()
        assert "surrogate_key" in d
        d_entry = cast(JsonDict, d["surrogate_key"])
        assert d_entry["type"] == "aws-sigv4"
        assert d_entry["access_key_id"] == "AKIA_REAL"


class TestMaskedSecret:
    """Tests for MaskedSecret dataclass."""

    def test_create(self) -> None:
        """Creates MaskedSecret with all fields."""
        secret = MaskedSecret(
            env_var="MY_TOKEN",
            real_value="secret_value",
            scopes=("api.example.com", "*.example.com"),
            headers=("Authorization", "X-Custom-Header"),
        )
        assert secret.env_var == "MY_TOKEN"
        assert secret.real_value == "secret_value"
        assert secret.scopes == ("api.example.com", "*.example.com")
        assert secret.headers == ("Authorization", "X-Custom-Header")
        assert secret.allow_foreign_credentials is False

    def test_create_with_allow_foreign_credentials(self) -> None:
        """Creates MaskedSecret with allow_foreign_credentials=True."""
        secret = MaskedSecret(
            env_var="MY_TOKEN",
            real_value="secret_value",
            scopes=("api.example.com",),
            headers=("Authorization",),
            allow_foreign_credentials=True,
        )
        assert secret.allow_foreign_credentials is True

    def test_frozen(self) -> None:
        """MaskedSecret is immutable."""
        secret = MaskedSecret(
            env_var="MY_TOKEN",
            real_value="value",
            scopes=("example.com",),
            headers=("Authorization",),
        )
        with __import__("pytest").raises(AttributeError):
            secret.env_var = "OTHER"  # type: ignore[misc]  # ty:ignore[invalid-assignment]


class TestSigningCredential:
    """Tests for SigningCredential dataclass."""

    def test_create_without_session_token(self) -> None:
        """Creates SigningCredential without session token."""
        cred = SigningCredential(
            access_key_id_env_var="AWS_ACCESS_KEY_ID",
            access_key_id="AKIAEXAMPLE",
            secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
            secret_access_key="secretkey",
            session_token_env_var=None,
            session_token=None,
            scopes=("s3.amazonaws.com",),
        )
        assert cred.session_token is None
        assert cred.session_token_env_var is None

    def test_create_with_session_token(self) -> None:
        """Creates SigningCredential with session token."""
        cred = SigningCredential(
            access_key_id_env_var="AWS_ACCESS_KEY_ID",
            access_key_id="ASIAEXAMPLE",
            secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
            secret_access_key="secretkey",
            session_token_env_var="AWS_SESSION_TOKEN",
            session_token="token_value",
            scopes=("bedrock.amazonaws.com",),
        )
        assert cred.session_token == "token_value"
        assert cred.session_token_env_var == "AWS_SESSION_TOKEN"

    def test_frozen(self) -> None:
        """SigningCredential is immutable."""
        cred = SigningCredential(
            access_key_id_env_var="A",
            access_key_id="B",
            secret_access_key_env_var="C",
            secret_access_key="D",
            session_token_env_var=None,
            session_token=None,
            scopes=(),
        )
        with __import__("pytest").raises(AttributeError):
            cred.access_key_id = "X"  # type: ignore[misc]  # ty:ignore[invalid-assignment]


class TestPreparedSecrets:
    """Tests for PreparedSecrets dataclass."""

    def test_create(self) -> None:
        """Creates PreparedSecrets with env_vars and replacements."""
        result = PreparedSecrets(
            env_vars={"KEY": "surrogate"},
            replacements=SecretReplacements(),
        )
        assert result.env_vars == {"KEY": "surrogate"}
        assert result.replacements.to_dict() == {}


class TestGitHubAppCredential:
    """Tests for GitHubAppCredential dataclass."""

    def test_create_minimal(self) -> None:
        """Creates GitHubAppCredential with required fields."""
        cred = GitHubAppCredential(
            env_var="GH_TOKEN",
            app_id="Iv23liXyz",
            private_key="key-data",
            installation_id=12345,
            scopes=("api.github.com",),
        )
        assert cred.env_var == "GH_TOKEN"
        assert cred.app_id == "Iv23liXyz"
        assert cred.base_url == "https://api.github.com"
        assert cred.allow_foreign_credentials is False
        assert cred.permissions is None
        assert cred.repositories is None

    def test_create_with_all_fields(self) -> None:
        """Creates GitHubAppCredential with optional fields."""
        cred = GitHubAppCredential(
            env_var="GH_TOKEN",
            app_id="Iv23liXyz",
            private_key="key",
            installation_id=12345,
            scopes=("api.github.com",),
            allow_foreign_credentials=True,
            base_url="https://ghes.example.com/api/v3",
            permissions={"contents": "write"},
            repositories=("my-repo",),
        )
        assert cred.allow_foreign_credentials is True
        assert cred.base_url == "https://ghes.example.com/api/v3"
        assert cred.permissions == {"contents": "write"}
        assert cred.repositories == ("my-repo",)

    def test_frozen(self) -> None:
        """GitHubAppCredential is immutable."""
        cred = GitHubAppCredential(
            env_var="GH_TOKEN",
            app_id="app",
            private_key="key",
            installation_id=123,
            scopes=("api.github.com",),
        )
        with __import__("pytest").raises(AttributeError):
            cred.app_id = "other"  # type: ignore[misc]  # ty:ignore[invalid-assignment]


class TestGitHubAppEntry:
    """Tests for _GitHubAppEntry dataclass."""

    def test_to_dict_minimal(self) -> None:
        """Serializes minimal entry correctly."""
        entry = _GitHubAppEntry(
            app_id="Iv23li",
            private_key="key",
            installation_id=12345,
            base_url="https://api.github.com",
            scopes=("api.github.com",),
        )
        d = entry.to_dict()
        assert d["type"] == "github-app"
        assert d["app_id"] == "Iv23li"
        assert d["private_key"] == "key"
        assert d["installation_id"] == 12345
        assert d["base_url"] == "https://api.github.com"
        assert d["scopes"] == ["api.github.com"]
        assert "permissions" not in d
        assert "repositories" not in d

    def test_to_dict_with_optional_fields(self) -> None:
        """Serializes optional permissions and repositories."""
        entry = _GitHubAppEntry(
            app_id="Iv23li",
            private_key="key",
            installation_id=12345,
            base_url="https://api.github.com",
            scopes=("api.github.com",),
            allow_foreign_credentials=True,
            permissions={"contents": "write"},
            repositories=("my-repo",),
        )
        d = entry.to_dict()
        assert d["allow_foreign_credentials"] is True
        assert d["permissions"] == {"contents": "write"}
        assert d["repositories"] == ["my-repo"]


class TestPrepareSecretsGitHubApp:
    """Tests for GitHub App credential handling in prepare_secrets."""

    def test_github_app_generates_ghs_surrogate(self) -> None:
        """Generates ghs_ prefixed surrogate for GitHub App credential."""
        gh_creds = [
            GitHubAppCredential(
                env_var="GH_TOKEN",
                app_id="Iv23liXyz",
                private_key="key",
                installation_id=12345,
                scopes=("api.github.com",),
            ),
        ]
        result = prepare_secrets([], [], gh_creds)

        assert "GH_TOKEN" in result.env_vars
        surrogate = result.env_vars["GH_TOKEN"]
        assert surrogate.startswith("ghs_")
        assert len(surrogate) == 40

    def test_github_app_replacement_map(self) -> None:
        """Replacement map includes github-app entry."""
        gh_creds = [
            GitHubAppCredential(
                env_var="GH_TOKEN",
                app_id="Iv23liXyz",
                private_key="key-data",
                installation_id=12345,
                scopes=("api.github.com",),
            ),
        ]
        result = prepare_secrets([], [], gh_creds)

        surrogate = result.env_vars["GH_TOKEN"]
        replacements_dict = result.replacements.to_dict()
        assert surrogate in replacements_dict
        entry = cast(JsonDict, replacements_dict[surrogate])
        assert entry["type"] == "github-app"
        assert entry["app_id"] == "Iv23liXyz"
        assert entry["private_key"] == "key-data"
        assert entry["installation_id"] == 12345

    def test_mixed_all_credential_types(self) -> None:
        """Handles masked secrets, signing creds, and GitHub App creds."""
        secrets = [
            MaskedSecret(
                env_var="API_KEY",
                real_value="sk-ant-realvalueA123456789",
                scopes=("api.anthropic.com",),
                headers=("x-api-key",),
            ),
        ]
        signing = [
            SigningCredential(
                access_key_id_env_var="AWS_ACCESS_KEY_ID",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
                secret_access_key="secret",
                session_token_env_var=None,
                session_token=None,
                scopes=("s3.amazonaws.com",),
            ),
        ]
        gh_creds = [
            GitHubAppCredential(
                env_var="GH_TOKEN",
                app_id="Iv23li",
                private_key="key",
                installation_id=123,
                scopes=("api.github.com",),
            ),
        ]

        result = prepare_secrets(secrets, signing, gh_creds)

        assert len(result.env_vars) == 4  # API_KEY + 2 AWS + GH_TOKEN
        assert result.env_vars["GH_TOKEN"].startswith("ghs_")
        assert result.env_vars["API_KEY"].startswith("sk-ant-")
        assert result.env_vars["AWS_ACCESS_KEY_ID"].startswith("AKIA")
        assert len(result.replacements.to_dict()) == 3

    def test_backwards_compatible_without_github_app(self) -> None:
        """prepare_secrets works without github_app_credentials arg."""
        result = prepare_secrets([], [])
        assert result.env_vars == {}
        assert result.replacements.to_dict() == {}
