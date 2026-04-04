# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut.config.generate."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

import pytest

from airut.config import generate
from airut.config.generate import (
    _SKIP_FIELDS,
    EXAMPLE_CONFIG_PATH,
    _comment_lines,
    _field_value,
    _format_scalar,
    _format_yaml,
    _get_example_instances,
    _group_fields_by_section,
    _is_nested_dataclass,
    _render_class,
    _render_field,
    _render_instance,
    _render_instance_body,
    _render_section,
    _yaml_key,
    _yaml_section,
    check_field_coverage,
    generate_example_config,
    generate_stub_config,
    main,
    validate_tables,
)
from airut.config.schema import Scope, get_field_meta, meta
from airut.config.source import (
    YAML_EMAIL_STRUCTURE,
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
)
from airut.yaml_env import EnvVar, VarRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestFormatYaml:
    """Tests for _format_yaml."""

    def test_bool_true(self) -> None:
        assert _format_yaml(True) == "true"

    def test_bool_false(self) -> None:
        assert _format_yaml(False) == "false"

    def test_int(self) -> None:
        assert _format_yaml(42) == "42"

    def test_float(self) -> None:
        assert _format_yaml(1.5) == "1.5"

    def test_str(self) -> None:
        assert _format_yaml("hello") == "hello"

    def test_bool_before_int(self) -> None:
        """Bool is a subclass of int; bool must be checked first."""
        assert _format_yaml(True) == "true"
        assert _format_yaml(False) == "false"

    def test_env_var(self) -> None:
        assert _format_yaml(EnvVar("MY_VAR")) == "!env MY_VAR"

    def test_var_ref(self) -> None:
        assert _format_yaml(VarRef("my_var")) == "!var my_var"


class TestFormatScalar:
    """Tests for _format_scalar."""

    def test_plain_string(self) -> None:
        assert _format_scalar("hello") == "hello"

    def test_quotes_wildcards(self) -> None:
        assert _format_scalar("*.example.com") == '"*.example.com"'

    def test_quotes_dots_in_sequence(self) -> None:
        assert (
            _format_scalar("api.github.com", in_sequence=True)
            == '"api.github.com"'
        )

    def test_no_quotes_dots_outside_sequence(self) -> None:
        assert _format_scalar("api.github.com") == "api.github.com"

    def test_env_var(self) -> None:
        assert _format_scalar(EnvVar("FOO")) == "!env FOO"

    def test_var_ref(self) -> None:
        assert _format_scalar(VarRef("bar")) == "!var bar"

    def test_bool(self) -> None:
        assert _format_scalar(True) == "true"
        assert _format_scalar(False) == "false"

    def test_int(self) -> None:
        assert _format_scalar(42) == "42"


class TestYamlKey:
    """Tests for _yaml_key."""

    def test_with_structure(self) -> None:
        assert (
            _yaml_key("max_concurrent_executions", YAML_GLOBAL_STRUCTURE)
            == "max_concurrent"
        )

    def test_without_structure(self) -> None:
        assert (
            _yaml_key("container_command", YAML_GLOBAL_STRUCTURE)
            == "container_command"
        )

    def test_none_structure(self) -> None:
        assert _yaml_key("some_field", None) == "some_field"


class TestYamlSection:
    """Tests for _yaml_section."""

    def test_nested_field(self) -> None:
        assert (
            _yaml_section("max_concurrent_executions", YAML_GLOBAL_STRUCTURE)
            == "execution"
        )

    def test_top_level_field(self) -> None:
        assert _yaml_section("container_command", YAML_GLOBAL_STRUCTURE) is None

    def test_empty_structure_returns_none(self) -> None:
        """Empty YAML_EMAIL_STRUCTURE means all fields are top-level."""
        assert _yaml_section("imap", YAML_EMAIL_STRUCTURE) is None

    def test_none_structure(self) -> None:
        assert _yaml_section("anything", None) is None


class TestCommentLines:
    """Tests for _comment_lines."""

    def test_basic(self) -> None:
        result = _comment_lines(["hello", "world"])
        assert result == ["# hello", "# world"]

    def test_empty_lines(self) -> None:
        result = _comment_lines(["hello", "", "world"])
        assert result == ["# hello", "#", "# world"]

    def test_with_prefix(self) -> None:
        result = _comment_lines(["hello"], "    ")
        assert result == ["    # hello"]


class TestFieldValue:
    """Tests for _field_value."""

    def test_with_example_override(self) -> None:
        from airut.gateway.config import GlobalConfig

        f = next(
            f
            for f in dataclasses.fields(GlobalConfig)
            if f.name == "dashboard_base_url"
        )
        value, has_default = _field_value(GlobalConfig, f)
        assert value == "dashboard.example.com"
        assert has_default is True  # defaults to None

    def test_with_real_default(self) -> None:
        from airut.gateway.config import GlobalConfig

        f = next(
            f
            for f in dataclasses.fields(GlobalConfig)
            if f.name == "container_command"
        )
        value, has_default = _field_value(GlobalConfig, f)
        assert value == "podman"
        assert has_default is True

    def test_none_default_no_override(self) -> None:
        from airut.gateway.config import EmailChannelConfig

        f = next(
            f
            for f in dataclasses.fields(EmailChannelConfig)
            if f.name == "microsoft_oauth2"
        )
        value, has_default = _field_value(EmailChannelConfig, f)
        assert value is None
        assert has_default is True

    def test_required_with_override(self) -> None:
        from airut.gateway.config import ImapConfig

        f = next(
            f for f in dataclasses.fields(ImapConfig) if f.name == "server"
        )
        value, has_default = _field_value(ImapConfig, f)
        assert value == "mail.example.com"
        assert has_default is False  # field has no default

    def test_default_factory(self) -> None:
        from airut.gateway.config import RepoServerConfig

        f = next(
            f
            for f in dataclasses.fields(RepoServerConfig)
            if f.name == "secrets"
        )
        value, has_default = _field_value(RepoServerConfig, f)
        assert value is None  # dict factory → None value
        assert has_default is True

    def test_bool_default(self) -> None:
        from airut.gateway.config import SmtpConfig

        f = next(
            f
            for f in dataclasses.fields(SmtpConfig)
            if f.name == "require_auth"
        )
        value, has_default = _field_value(SmtpConfig, f)
        assert value == "true"
        assert has_default is True


class TestIsNestedDataclass:
    """Tests for _is_nested_dataclass."""

    def test_resource_limits_field(self) -> None:
        from airut.gateway.config import RepoServerConfig
        from airut.sandbox.types import ResourceLimits

        f = next(
            f
            for f in dataclasses.fields(RepoServerConfig)
            if f.name == "resource_limits"
        )
        assert _is_nested_dataclass(RepoServerConfig, f) is ResourceLimits

    def test_non_nested_field(self) -> None:
        from airut.gateway.config import GlobalConfig

        f = next(
            f
            for f in dataclasses.fields(GlobalConfig)
            if f.name == "container_command"
        )
        assert _is_nested_dataclass(GlobalConfig, f) is None


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestValidateTables:
    """Tests for validate_tables."""

    def test_valid_tables(self) -> None:
        errors = validate_tables()
        assert errors == []

    def test_detects_bad_class_name(self) -> None:
        with mock.patch.dict(
            generate._EXAMPLE_VALUES, {"FakeClass.field": "v"}
        ):
            errors = validate_tables()
            assert any("FakeClass" in e for e in errors)

    def test_detects_bad_field_name(self) -> None:
        with mock.patch.dict(
            generate._EXAMPLE_VALUES,
            {"GlobalConfig.fake_field": "v"},
        ):
            errors = validate_tables()
            assert any("fake_field" in e for e in errors)

    def test_detects_bad_key_format(self) -> None:
        with mock.patch.dict(generate._EXAMPLE_VALUES, {"noperiod": "v"}):
            errors = validate_tables()
            assert any("invalid key format" in e for e in errors)

    def test_validates_complex_snippets(self) -> None:
        with mock.patch.dict(
            generate._COMPLEX_SNIPPETS,
            {"GlobalConfig.nonexistent": [("line", False)]},
        ):
            errors = validate_tables()
            assert any("nonexistent" in e for e in errors)

    def test_validates_example_instances(self) -> None:
        instances = _get_example_instances()
        with mock.patch.object(
            generate,
            "_get_example_instances",
            return_value={**instances, "GlobalConfig.fake": "x"},
        ):
            errors = validate_tables()
            assert any("fake" in e for e in errors)


# ---------------------------------------------------------------------------
# Instance rendering
# ---------------------------------------------------------------------------


class TestRenderInstanceBody:
    """Tests for _render_instance_body."""

    def test_simple_dict(self) -> None:
        body = _render_instance_body("secrets", {"KEY": EnvVar("KEY")})
        assert body == ["secrets:", "  KEY: !env KEY"]

    def test_list_value(self) -> None:
        body = _render_instance_body("authorized_senders", ["a@b.com"])
        assert body == ["authorized_senders:", '  - "a@b.com"']

    def test_scalar_dict_value(self) -> None:
        body = _render_instance_body("items", {"key": "val"})
        assert body == ["items:", "  key: val"]

    def test_schedule_comments(self) -> None:
        from airut.gateway.config import ScheduleConfig, ScheduleDelivery

        sched = {
            "test-job": ScheduleConfig(
                cron="0 0 * * *",
                deliver=ScheduleDelivery(to="x@y.com"),
                prompt="Do stuff.",
            ),
        }
        comments = {"test-job": ["  # My comment"]}
        body = _render_instance_body("schedules", sched, comments)
        assert "  # My comment" in body
        assert any("test-job:" in line for line in body)


class TestExampleInstances:
    """Tests for _build_example_instances / _get_example_instances."""

    def test_all_keys_valid(self) -> None:
        """All instance keys reference real schema fields."""
        errors = validate_tables()
        assert errors == []

    def test_instances_are_cached(self) -> None:
        a = _get_example_instances()
        b = _get_example_instances()
        assert a is b

    def test_masked_secret_is_real_dataclass(self) -> None:
        from airut.gateway.config import MaskedSecret

        instances = _get_example_instances()
        ms = instances["RepoServerConfig.masked_secrets"]["GH_TOKEN"]
        assert isinstance(ms, MaskedSecret)

    def test_schedule_configs_are_real(self) -> None:
        from airut.gateway.config import ScheduleConfig

        instances = _get_example_instances()
        schedules = instances["RepoServerConfig.schedules"]
        assert isinstance(schedules["daily-report"], ScheduleConfig)
        assert isinstance(schedules["nightly-check"], ScheduleConfig)


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


class TestGroupFieldsBySection:
    """Tests for _group_fields_by_section."""

    def test_global_sections(self) -> None:
        from airut.gateway.config import GlobalConfig

        groups = _group_fields_by_section(GlobalConfig, YAML_GLOBAL_STRUCTURE)
        section_names = [name for name, _ in groups]
        assert "execution" in section_names
        assert "dashboard" in section_names
        assert "network" in section_names

    def test_email_sections(self) -> None:
        from airut.gateway.config import EmailChannelConfig

        groups = _group_fields_by_section(
            EmailChannelConfig, YAML_EMAIL_STRUCTURE
        )
        # With empty YAML_EMAIL_STRUCTURE, all fields are top-level (None)
        section_names = [name for name, _ in groups]
        assert None in section_names
        # All sub-dataclass fields are grouped under the None section
        all_fields = [f.name for _, fields in groups for f in fields]
        assert "account" in all_fields
        assert "imap" in all_fields
        assert "smtp" in all_fields
        assert "auth" in all_fields
        assert "microsoft_oauth2" in all_fields

    def test_skipped_fields(self) -> None:
        from airut.gateway.config import RepoServerConfig

        groups = _group_fields_by_section(RepoServerConfig, YAML_REPO_STRUCTURE)
        all_fields = [f.name for _, fields in groups for f in fields]
        assert "repo_id" not in all_fields
        assert "channels" not in all_fields

    def test_preserves_declaration_order(self) -> None:
        from airut.gateway.config import GlobalConfig

        groups = _group_fields_by_section(GlobalConfig, YAML_GLOBAL_STRUCTURE)
        section_names = [name for name, _ in groups]
        # execution comes before dashboard in GlobalConfig field order
        assert section_names.index("execution") < section_names.index(
            "dashboard"
        )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class TestRenderField:
    """Tests for _render_field."""

    def test_required_field_uncommented(self) -> None:
        from airut.gateway.config import ImapConfig

        f = next(
            f for f in dataclasses.fields(ImapConfig) if f.name == "server"
        )
        lines = _render_field(ImapConfig, f, None, "  ")
        assert any("server: mail.example.com" in x for x in lines)
        # Should NOT be commented
        value_line = [x for x in lines if "server:" in x][0]
        assert not value_line.strip().startswith("# server:")

    def test_optional_field_commented(self) -> None:
        from airut.gateway.config import GlobalConfig

        f = next(
            f
            for f in dataclasses.fields(GlobalConfig)
            if f.name == "container_command"
        )
        lines = _render_field(GlobalConfig, f, YAML_GLOBAL_STRUCTURE, "")
        value_line = [x for x in lines if "container_command:" in x][0]
        assert value_line.startswith("# container_command: podman")

    def test_force_comment(self) -> None:
        from airut.gateway.config import ImapConfig

        f = next(
            f for f in dataclasses.fields(ImapConfig) if f.name == "server"
        )
        lines = _render_field(
            ImapConfig,
            f,
            None,
            "",
            force_comment=True,
        )
        value_line = [x for x in lines if "server:" in x][0]
        assert value_line.startswith("# server:")

    def test_plain_mode(self) -> None:
        from airut.gateway.config import GlobalConfig

        f = next(
            f
            for f in dataclasses.fields(GlobalConfig)
            if f.name == "container_command"
        )
        lines = _render_field(
            GlobalConfig,
            f,
            YAML_GLOBAL_STRUCTURE,
            "",
            plain=True,
        )
        value_line = [x for x in lines if "container_command:" in x][0]
        # In plain mode, default values are NOT commented
        assert value_line == "container_command: podman"

    def test_plain_mode_none_default(self) -> None:
        """Plain mode renders a None-default scalar field without commenting."""

        @dataclass(frozen=True)
        class _PlainNone:
            opt_field: str | None = field(
                default=None,
                metadata=meta("Optional field for testing", Scope.SERVER),
            )

        f = dataclasses.fields(_PlainNone)[0]
        lines = _render_field(
            _PlainNone,
            f,
            None,
            "",
            plain=True,
        )
        value_line = [
            x for x in lines if "opt_field:" in x and "Optional" not in x
        ][0]
        assert value_line == "opt_field:"

    def test_instance_field(self) -> None:
        """Instance-based complex fields render with doc and content."""
        from airut.gateway.config import RepoServerConfig

        f = next(
            f
            for f in dataclasses.fields(RepoServerConfig)
            if f.name == "secrets"
        )
        lines = _render_field(RepoServerConfig, f, YAML_REPO_STRUCTURE, "    ")
        # Instance fields with default_factory=dict are commented out
        assert any("# secrets:" in x for x in lines)
        assert any("ANTHROPIC_API_KEY" in x for x in lines)

    def test_nested_dataclass(self) -> None:
        from airut.config.source import YAML_REPO_STRUCTURE
        from airut.gateway.config import RepoServerConfig

        f = next(
            f
            for f in dataclasses.fields(RepoServerConfig)
            if f.name == "resource_limits"
        )
        lines = _render_field(RepoServerConfig, f, YAML_REPO_STRUCTURE, "    ")
        assert any("resource_limits:" in x for x in lines)
        assert any("!var default_resource_timeout" in x for x in lines)
        assert any("memory:" in x for x in lines)

    def test_doc_always_present(self) -> None:
        from airut.gateway.config import GlobalConfig

        for f in dataclasses.fields(GlobalConfig):
            fm = get_field_meta(f)
            if fm is None:
                continue
            lines = _render_field(GlobalConfig, f, YAML_GLOBAL_STRUCTURE, "")
            assert any(fm.doc in x for x in lines)


class TestRenderClass:
    """Tests for _render_class."""

    def test_global_config(self) -> None:
        from airut.gateway.config import GlobalConfig

        lines = _render_class(GlobalConfig, YAML_GLOBAL_STRUCTURE)
        text = "\n".join(lines)
        assert "execution:" in text
        assert "dashboard:" in text
        assert "container_command" not in text  # hidden field
        assert "network:" in text

    def test_email_config(self) -> None:
        from airut.gateway.config import EmailChannelConfig

        lines = _render_class(
            EmailChannelConfig, YAML_EMAIL_STRUCTURE, indent="      "
        )
        text = "\n".join(lines)
        assert "server: mail.example.com" in text
        assert "imap:" in text
        assert "smtp:" in text
        assert "account:" in text
        assert "auth:" in text
        assert "microsoft_oauth2:" in text

    def test_force_comment(self) -> None:
        from airut.gateway.slack.config import SlackChannelConfig

        lines = _render_class(
            SlackChannelConfig,
            None,
            indent="    ",
            force_comment=True,
        )
        # All lines should start with spaces + #
        for line in lines:
            stripped = line.strip()
            if stripped:
                assert stripped.startswith("#")


# ---------------------------------------------------------------------------
# Example config
# ---------------------------------------------------------------------------


class TestGenerateExampleConfig:
    """Tests for generate_example_config."""

    def test_generates_valid_content(self) -> None:
        content = generate_example_config()
        assert content.startswith("# Airut Server Configuration")
        assert content.endswith("\n")

    def test_contains_header(self) -> None:
        content = generate_example_config()
        assert "Never commit real credentials." in content
        assert "!env" in content
        assert "!var" in content
        assert "vars:" in content

    def test_contains_all_global_sections(self) -> None:
        content = generate_example_config()
        assert "execution:" in content
        assert "dashboard:" in content
        assert "container_command" not in content  # hidden field
        assert "network:" in content

    def test_contains_repo_section(self) -> None:
        content = generate_example_config()
        assert "repos:" in content
        assert "my-project:" in content

    def test_contains_email_channel(self) -> None:
        content = generate_example_config()
        assert "email:" in content
        assert "server: mail.example.com" in content

    def test_contains_repo_url(self) -> None:
        content = generate_example_config()
        assert "repo_url:" in content

    def test_contains_credentials(self) -> None:
        content = generate_example_config()
        assert "secrets:" in content
        assert "masked_secrets:" in content
        assert "signing_credentials:" in content
        assert "github_app_credentials:" in content

    def test_contains_slack_channel(self) -> None:
        content = generate_example_config()
        assert "bot_token:" in content
        assert "app_token:" in content
        assert "authorized:" in content

    def test_global_defaults_commented(self) -> None:
        content = generate_example_config()
        assert "# execution:" in content
        assert "# dashboard:" in content

    def test_required_fields_uncommented(self) -> None:
        content = generate_example_config()
        lines = content.split("\n")
        # imap/smtp "server: mail.example.com" lines under repos should be
        # uncommented.  Exclude the vars header comment which also contains
        # "mail_server: mail.example.com".
        server_lines = [
            line
            for line in lines
            if "server: mail.example.com" in line and "mail_server" not in line
        ]
        assert len(server_lines) >= 1
        # Should be uncommented (just indented, no #)
        for line in server_lines:
            stripped = line.lstrip()
            assert not stripped.startswith("#")

    def test_schema_derived_doc_strings(self) -> None:
        """Verify doc strings from FieldMeta appear in output."""
        from airut.gateway.config import GlobalConfig

        content = generate_example_config()
        for f in dataclasses.fields(GlobalConfig):
            fm = get_field_meta(f)
            if fm is not None and not fm.hidden:
                assert fm.doc in content, (
                    f"GlobalConfig.{f.name} doc missing from output"
                )

    def test_schema_derived_defaults(self) -> None:
        """Verify actual defaults from dataclasses appear in output."""
        content = generate_example_config()
        assert "max_concurrent: 3" in content
        assert "shutdown_timeout: 60" in content
        assert "enabled: true" in content
        assert "host: 127.0.0.1" in content
        assert "port: 5200" in content

    def test_example_overrides_present(self) -> None:
        content = generate_example_config()
        assert "timeout: !var default_resource_timeout" in content
        assert "memory: !var default_resource_memory" in content
        assert "cpus: !var default_resource_cpus" in content
        assert "effort: max" in content

    def test_instance_based_credentials(self) -> None:
        """Instance-generated credential blocks appear correctly."""
        content = generate_example_config()
        # Masked secrets
        assert "GH_TOKEN:" in content
        assert "!env GH_TOKEN" in content
        # Signing credentials
        assert "type: aws-sigv4" in content
        assert "AWS_ACCESS_KEY_ID" in content
        # GitHub App credentials
        assert "!env GH_APP_ID" in content
        assert "!env GH_APP_PRIVATE_KEY" in content

    def test_instance_based_schedules(self) -> None:
        """Instance-generated schedule blocks appear correctly."""
        content = generate_example_config()
        assert "daily-report:" in content
        assert "nightly-check:" in content
        assert "Prompt mode" in content
        assert "Script mode" in content
        assert "trigger_command:" in content

    def test_idempotent(self) -> None:
        c1 = generate_example_config()
        c2 = generate_example_config()
        assert c1 == c2

    def test_validates_tables_on_generation(self) -> None:
        """Drift detection: invalid table entries cause ValueError."""
        with mock.patch.dict(
            generate._EXAMPLE_VALUES,
            {"GlobalConfig.fake_field": "x"},
        ):
            with pytest.raises(ValueError, match="Schema drift"):
                generate_example_config()

    def test_no_double_commenting(self) -> None:
        """Sections should not have '# # key: value' patterns."""
        content = generate_example_config()
        for line in content.split("\n"):
            stripped = line.lstrip()
            # After removing all leading "# " pairs, should not start with "# "
            # followed immediately by a yaml key: value
            if stripped.startswith("# # "):
                inner = stripped[4:]
                # OK if inner is also a comment (doc string)
                # Not OK if inner looks like "key: value"
                if (
                    ":" in inner
                    and not inner.startswith("#")
                    and not inner.startswith("- ")
                ):
                    # Allow doc comments that happen to contain colons
                    # (e.g. "# Max container execution time in seconds")
                    # by checking if there's a space before the colon
                    parts = inner.split(":", 1)
                    if " " not in parts[0]:
                        pytest.fail(f"Double-commented value found: {line!r}")


# ---------------------------------------------------------------------------
# Stub config
# ---------------------------------------------------------------------------


class TestGenerateStubConfig:
    """Tests for generate_stub_config."""

    def test_generates_valid_content(self) -> None:
        content = generate_stub_config()
        assert content.startswith("# Airut Server Configuration")
        assert content.endswith("\n")

    def test_contains_reference_link(self) -> None:
        content = generate_stub_config()
        assert "config/airut.example.yaml" in content

    def test_contains_repo_section(self) -> None:
        content = generate_stub_config()
        assert "repos:" in content
        assert "my-project:" in content

    def test_contains_required_email_fields(self) -> None:
        content = generate_stub_config()
        assert "server:" in content  # imap/smtp server
        assert "username:" in content
        assert "from:" in content
        assert "trusted_authserv_id:" in content

    def test_contains_repo_url(self) -> None:
        content = generate_stub_config()
        assert "repo_url:" in content

    def test_contains_secrets(self) -> None:
        content = generate_stub_config()
        assert "ANTHROPIC_API_KEY" in content

    def test_excludes_optional_email_fields(self) -> None:
        content = generate_stub_config()
        lines = content.split("\n")
        # Optional email fields should not appear as uncommented in stub
        uncommented = [
            line for line in lines if not line.strip().startswith("#")
        ]
        uncommented_text = "\n".join(uncommented)
        assert "poll_interval" not in uncommented_text
        assert "use_idle" not in uncommented_text
        assert "microsoft_oauth2" not in uncommented_text

    def test_idempotent(self) -> None:
        c1 = generate_stub_config()
        c2 = generate_stub_config()
        assert c1 == c2

    def test_includes_global_config_commented(self) -> None:
        content = generate_stub_config()
        assert "# execution:" in content
        assert "# container_command:" not in content  # hidden field


# ---------------------------------------------------------------------------
# Field coverage
# ---------------------------------------------------------------------------


class TestFieldCoverage:
    """Tests for check_field_coverage."""

    def test_all_fields_covered(self) -> None:
        errors = check_field_coverage()
        assert errors == [], f"Missing fields: {errors}"

    def test_detects_missing_field(self) -> None:
        """If a field's doc doesn't appear, coverage check fails."""
        with mock.patch.object(
            generate,
            "generate_example_config",
            return_value="empty config",
        ):
            errors = check_field_coverage()
            assert len(errors) > 0

    def test_skipped_fields_excluded(self) -> None:
        """_SKIP_FIELDS are not checked for coverage."""
        errors = check_field_coverage()
        for cls_name, field_name in _SKIP_FIELDS:
            assert not any(field_name in e for e in errors)


# ---------------------------------------------------------------------------
# CLI (main)
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for main CLI entry point."""

    def test_write_mode(self, tmp_path: Path) -> None:
        out_path = tmp_path / "config" / "airut.example.yaml"
        with mock.patch.object(generate, "EXAMPLE_CONFIG_PATH", out_path):
            result = main()
        assert result == 0
        assert out_path.exists()
        assert out_path.read_text().startswith("# Airut Server Configuration")

    def test_check_mode_pass(self, tmp_path: Path) -> None:
        out_path = tmp_path / "config" / "airut.example.yaml"
        out_path.parent.mkdir(parents=True)
        out_path.write_text(generate_example_config())
        with (
            mock.patch.object(generate, "EXAMPLE_CONFIG_PATH", out_path),
            mock.patch("sys.argv", ["generate", "--check"]),
        ):
            result = main()
        assert result == 0

    def test_check_mode_fail(self, tmp_path: Path) -> None:
        out_path = tmp_path / "config" / "airut.example.yaml"
        out_path.parent.mkdir(parents=True)
        out_path.write_text("stale content\n")
        with (
            mock.patch.object(generate, "EXAMPLE_CONFIG_PATH", out_path),
            mock.patch("sys.argv", ["generate", "--check"]),
        ):
            result = main()
        assert result == 1

    def test_check_mode_missing(self, tmp_path: Path) -> None:
        out_path = tmp_path / "nonexistent" / "airut.example.yaml"
        with (
            mock.patch.object(generate, "EXAMPLE_CONFIG_PATH", out_path),
            mock.patch("sys.argv", ["generate", "--check"]),
        ):
            result = main()
        assert result == 1

    def test_module_invocation(self) -> None:
        """Verify ``python -m airut.config.generate --check`` works."""
        result = subprocess.run(
            [sys.executable, "-m", "airut.config.generate", "--check"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Integration: drift detection
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases and defensive code paths."""

    def test_group_skips_fields_without_meta(self) -> None:
        """Fields without FieldMeta are silently skipped."""

        @dataclass(frozen=True)
        class _MixedConfig:
            annotated: str = field(
                default="x",
                metadata=meta("Has meta", Scope.SERVER),
            )
            plain: str = "no meta"

        groups = _group_fields_by_section(_MixedConfig, None)
        all_names = [f.name for _, fields in groups for f in fields]
        assert "annotated" in all_names
        assert "plain" not in all_names

    def test_render_field_none_default_not_plain(self) -> None:
        """Non-plain rendering of a field with None default and no override."""

        @dataclass(frozen=True)
        class _NoneField:
            opt: str | None = field(
                default=None,
                metadata=meta("Optional field", Scope.SERVER),
            )

        f = dataclasses.fields(_NoneField)[0]
        lines = _render_field(_NoneField, f, None, "")
        # Should render as commented key
        assert any(line == "# opt:" for line in lines)

    def test_mixed_section_rendering(self) -> None:
        """Section with mix of required and optional fields."""

        @dataclass(frozen=True)
        class _MixedSection:
            required: str = field(
                metadata=meta("Required field", Scope.SERVER),
            )
            optional: str = field(
                default="x",
                metadata=meta("Optional field", Scope.SERVER),
            )

        structure: dict[str, tuple[str, ...]] = {
            "required": ("mysect", "required"),
            "optional": ("mysect", "optional"),
        }
        groups = _group_fields_by_section(_MixedSection, structure)
        lines = _render_section(
            _MixedSection, "mysect", groups[0][1], structure, ""
        )
        text = "\n".join(lines)
        # Section header should be uncommented (mixed section)
        assert "mysect:" in text
        assert not text.startswith("#")

    def test_nested_field_with_non_none_default(self) -> None:
        """Nested dataclass fields with non-None defaults use _format_yaml."""

        @dataclass(frozen=True)
        class _Nested:
            val: int = field(
                default=42,
                metadata=meta("A value with default", Scope.TASK),
            )

        @dataclass(frozen=True)
        class _Outer:
            resource_limits: _Nested | None = field(
                default=None,
                metadata=meta("Nested config", Scope.SERVER),
            )

        # Temporarily make _is_nested_dataclass return our test class
        with mock.patch(
            "airut.config.generate._is_nested_dataclass",
            return_value=_Nested,
        ):
            f = dataclasses.fields(_Outer)[0]
            lines = _render_field(_Outer, f, None, "")
        text = "\n".join(lines)
        # Should render the nested field's default value via _format_yaml
        assert "val: 42" in text
        assert "A value with default" in text

    def test_nested_field_skips_unannotated(self) -> None:
        """Nested dataclass rendering skips fields without FieldMeta."""

        @dataclass(frozen=True)
        class _Nested:
            annotated: int = field(
                default=1,
                metadata=meta("Has meta", Scope.TASK),
            )
            plain: str = "no meta"

        @dataclass(frozen=True)
        class _Outer:
            resource_limits: _Nested | None = field(
                default=None,
                metadata=meta("Nested config", Scope.SERVER),
            )

        with mock.patch(
            "airut.config.generate._is_nested_dataclass",
            return_value=_Nested,
        ):
            f = dataclasses.fields(_Outer)[0]
            lines = _render_field(_Outer, f, None, "")
        text = "\n".join(lines)
        assert "annotated: 1" in text
        assert "plain" not in text

    def test_check_coverage_skips_unannotated(self) -> None:
        """check_field_coverage skips fields without FieldMeta."""
        # This is implicitly tested, but let's verify the path
        # by ensuring no errors for current schema
        errors = check_field_coverage()
        assert errors == []

    def test_stub_handles_field_without_meta(self) -> None:
        """Stub generation skips fields without FieldMeta."""
        from airut.gateway.config import EmailChannelConfig

        original_fields = dataclasses.fields(EmailChannelConfig)

        # Create a mock field without FieldMeta metadata
        mock_field = mock.MagicMock(spec=dataclasses.Field)
        mock_field.name = "no_meta_field"
        mock_field.metadata = {}  # No FieldMeta

        with mock.patch(
            "airut.config.generate.dc_fields",
            side_effect=lambda cls: (
                (*original_fields, mock_field)
                if cls is EmailChannelConfig
                else dataclasses.fields(cls)
            ),
        ):
            content = generate_stub_config()
        assert "server:" in content  # imap/smtp server
        assert "no_meta_field" not in content

    def test_stub_skips_required_field_without_example(self) -> None:
        """Stub generation skips required fields not in _EXAMPLE_VALUES."""
        # Temporarily remove an example value to trigger the skip path
        saved = generate._EXAMPLE_VALUES.pop("ImapConfig.server")
        try:
            content = generate_stub_config()
            lines = content.split("\n")
            # Count uncommented "server: mail.example.com" lines.
            # Without the override, IMAP section should not have it.
            # SMTP still has its own SmtpConfig.server override.
            server_lines = [
                line
                for line in lines
                if not line.strip().startswith("#")
                and "server: mail.example.com" in line
            ]
            # Only the SMTP server line should remain (1 instead of 2)
            assert len(server_lines) == 1
        finally:
            generate._EXAMPLE_VALUES["ImapConfig.server"] = saved

    def test_check_coverage_skips_unannotated_fields(self) -> None:
        """check_field_coverage skips fields without FieldMeta."""
        from airut.gateway.config import GlobalConfig

        original_fields = dataclasses.fields(GlobalConfig)

        # Add a mock field without FieldMeta
        mock_field = mock.MagicMock(spec=dataclasses.Field)
        mock_field.name = "no_meta"
        mock_field.metadata = {}

        with mock.patch(
            "airut.config.generate.dc_fields",
            side_effect=lambda cls: (
                (*original_fields, mock_field)
                if cls is GlobalConfig
                else dataclasses.fields(cls)
            ),
        ):
            errors = check_field_coverage()
        assert not any("no_meta" in e for e in errors)

    def test_snippet_uncommented_top_level(self) -> None:
        """Top-level snippet renders uncommented when field has no default."""

        @dataclass(frozen=True)
        class _Cls:
            items: tuple[dict[str, str | bool], ...] = field(
                metadata=meta("Items list", Scope.SERVER),
            )

        snippet = [("items:", False), ("  - one", False)]
        with mock.patch.dict(
            generate._COMPLEX_SNIPPETS, {"_Cls.items": snippet}
        ):
            f = dataclasses.fields(_Cls)[0]
            lines = _render_field(_Cls, f, None, "")
        assert "items:" in lines
        assert "  - one" in lines

    def test_instance_uncommented_required(self) -> None:
        """Instance field renders uncommented when field has no default."""
        instances = _get_example_instances()
        with mock.patch.object(
            generate,
            "_get_example_instances",
            return_value={
                **instances,
                "_Test.items": ["a"],
            },
        ):
            lines = _render_instance(
                "_Test.items",
                "items",
                "Test items",
                "  ",
                commented=False,
            )
        assert any(
            "items:" in x and not x.strip().startswith("#") for x in lines
        )

    def test_append_field_empty_list(self) -> None:
        """_append_field_value skips empty lists."""
        from airut.config.generate import _append_field_value

        out: list[str] = []
        _append_field_value(out, "items", [], "")
        assert out == []

    def test_append_field_empty_dict(self) -> None:
        """_append_field_value skips empty dicts."""
        from airut.config.generate import _append_field_value

        out: list[str] = []
        _append_field_value(out, "perms", {}, "")
        assert out == []

    def test_append_field_dict(self) -> None:
        """_append_field_value renders dicts."""
        from airut.config.generate import _append_field_value

        out: list[str] = []
        _append_field_value(out, "perms", {"read": "true"}, "  ")
        assert out == ["  perms:", "    read: true"]

    def test_render_dataclass_fields_skips_default_factory(self) -> None:
        """Fields with default_factory whose value matches are skipped."""
        from airut.config.generate import _render_dataclass_fields

        @dataclass
        class _D:
            tags: list[str] = field(default_factory=list)
            name: str = "x"

        inst = _D()  # tags=[], name="x" — both are defaults
        lines = _render_dataclass_fields(inst, "")
        assert lines == []

    def test_nested_instance_sub_field_commented(self) -> None:
        """Nested dataclass with instance sub-field rendered commented."""

        @dataclass(frozen=True)
        class _Inner:
            items: list[str] = field(
                default_factory=list,
                metadata=meta("Item list", Scope.SERVER),
            )

        @dataclass(frozen=True)
        class _Outer:
            inner: _Inner = field(
                default_factory=_Inner,
                metadata=meta("Inner config", Scope.SERVER),
            )

        instances = _get_example_instances()
        with (
            mock.patch.object(
                generate,
                "_get_example_instances",
                return_value={
                    **instances,
                    "_Inner.items": ["a", "b"],
                },
            ),
            mock.patch(
                "airut.config.generate._is_nested_dataclass",
                return_value=_Inner,
            ),
        ):
            f = dataclasses.fields(_Outer)[0]
            lines = _render_field(_Outer, f, None, "")
        text = "\n".join(lines)
        # The whole block is commented (outer has default_factory)
        assert "# items:" in text

    def test_nested_snippet_sub_field_uncommented(self) -> None:
        """Snippet sub-field without default is uncommented."""

        @dataclass(frozen=True)
        class _Inner:
            rules: tuple[dict[str, str], ...] = field(
                metadata=meta("Auth rules", Scope.SERVER),
            )

        @dataclass(frozen=True)
        class _Outer:
            inner: _Inner = field(
                metadata=meta("Inner config", Scope.SERVER),
            )

        snippet = [("rules:", False), ("  - key: val", False)]
        with (
            mock.patch.dict(
                generate._COMPLEX_SNIPPETS,
                {"_Inner.rules": snippet},
            ),
            mock.patch(
                "airut.config.generate._is_nested_dataclass",
                return_value=_Inner,
            ),
        ):
            f = dataclasses.fields(_Outer)[0]
            lines = _render_field(_Outer, f, None, "")
        text = "\n".join(lines)
        assert "rules:" in text
        assert "key: val" in text

    def test_nested_snippet_sub_field_commented(self) -> None:
        """Nested dataclass: snippet sub-field with default is commented."""

        @dataclass(frozen=True)
        class _Inner:
            rules: tuple[dict[str, str], ...] = field(
                default_factory=tuple,
                metadata=meta("Auth rules", Scope.SERVER),
            )

        @dataclass(frozen=True)
        class _Outer:
            inner: _Inner = field(
                metadata=meta("Inner config", Scope.SERVER),
            )

        snippet = [
            ("rules:", False),
            ("  - key: val", False),
            ("# inline comment", True),
        ]
        with (
            mock.patch.dict(
                generate._COMPLEX_SNIPPETS,
                {"_Inner.rules": snippet},
            ),
            mock.patch(
                "airut.config.generate._is_nested_dataclass",
                return_value=_Inner,
            ),
        ):
            f = dataclasses.fields(_Outer)[0]
            lines = _render_field(_Outer, f, None, "")
        text = "\n".join(lines)
        assert "# rules:" in text
        # is_comment=True lines are not double-commented
        assert "# # inline comment" not in text
        assert "# inline comment" in text


class TestDriftDetection:
    """Tests for schema drift detection."""

    def test_example_values_all_valid(self) -> None:
        """Every key in _EXAMPLE_VALUES references a real schema field."""
        errors = validate_tables()
        assert errors == []

    def test_example_instances_all_valid(self) -> None:
        """Every key in _EXAMPLE_INSTANCES references a real schema field."""
        errors = validate_tables()
        assert errors == []

    def test_complex_snippets_all_valid(self) -> None:
        """Every key in _COMPLEX_SNIPPETS references a real schema field."""
        errors = validate_tables()
        assert errors == []

    def test_example_config_matches_file(self) -> None:
        """Generated config matches the checked-in file."""
        content = generate_example_config()
        if EXAMPLE_CONFIG_PATH.exists():
            assert content == EXAMPLE_CONFIG_PATH.read_text()

    def test_adding_fake_override_detected(self) -> None:
        """Adding a non-existent field to _EXAMPLE_VALUES is detected."""
        with mock.patch.dict(
            generate._EXAMPLE_VALUES,
            {"ResourceLimits.nonexistent_field": "42"},
        ):
            errors = validate_tables()
            assert any("nonexistent_field" in e for e in errors)

    def test_adding_fake_snippet_detected(self) -> None:
        """Adding a non-existent field to _COMPLEX_SNIPPETS is detected."""
        with mock.patch.dict(
            generate._COMPLEX_SNIPPETS,
            {"EmailChannelConfig.fake": [("line", False)]},
        ):
            errors = validate_tables()
            assert any("fake" in e for e in errors)
