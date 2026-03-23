# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for full_schema_for_api() in airut/config/schema.py."""

from airut.config.schema import full_schema_for_api


class TestFullSchemaForApi:
    def test_returns_all_sections(self) -> None:
        schema = full_schema_for_api()
        assert "global" in schema
        assert "email_channel" in schema
        assert "slack_channel" in schema
        assert "repo" in schema
        assert "resource_limits" in schema

    def test_global_has_fields(self) -> None:
        schema = full_schema_for_api()
        names = [f["name"] for f in schema["global"]]
        assert "max_concurrent_executions" in names
        assert "dashboard_host" in names
        assert "dashboard_port" in names

    def test_fields_have_yaml_path(self) -> None:
        schema = full_schema_for_api()
        for field in schema["global"]:
            assert "yaml_path" in field
            assert isinstance(field["yaml_path"], list)
            assert len(field["yaml_path"]) >= 1

    def test_yaml_path_uses_structure_mapping(self) -> None:
        schema = full_schema_for_api()
        global_fields = {f["name"]: f for f in schema["global"]}
        # max_concurrent_executions maps to ("execution", "max_concurrent")
        mc = global_fields["max_concurrent_executions"]
        assert mc["yaml_path"] == ["execution", "max_concurrent"]

    def test_unmapped_fields_use_field_name(self) -> None:
        schema = full_schema_for_api()
        slack_fields = {f["name"]: f for f in schema["slack_channel"]}
        # Slack fields have no mapping, use (field_name,)
        assert "bot_token" in slack_fields
        assert slack_fields["bot_token"]["yaml_path"] == ["bot_token"]

    def test_field_properties(self) -> None:
        schema = full_schema_for_api()
        for section_name, fields in schema.items():
            for f in fields:
                assert "name" in f
                assert "type_name" in f
                assert "doc" in f
                assert "scope" in f
                assert "secret" in f
                assert "required" in f
                assert isinstance(f["name"], str)
                assert isinstance(f["doc"], str)
                assert f["scope"] in ("server", "repo", "task")
                assert isinstance(f["secret"], bool)

    def test_defaults_are_json_safe(self) -> None:
        """Ensure MISSING sentinels are replaced with None."""
        schema = full_schema_for_api()
        import dataclasses

        for section_name, fields in schema.items():
            for f in fields:
                assert f["default"] is not dataclasses.MISSING

    def test_repo_section_has_model(self) -> None:
        schema = full_schema_for_api()
        repo_names = [f["name"] for f in schema["repo"]]
        assert "model" in repo_names
        assert "git_repo_url" in repo_names

    def test_resource_limits_section(self) -> None:
        schema = full_schema_for_api()
        rl_names = [f["name"] for f in schema["resource_limits"]]
        assert "timeout" in rl_names
        assert "memory" in rl_names
        assert "cpus" in rl_names
        assert "pids_limit" in rl_names

    def test_email_channel_fields(self) -> None:
        schema = full_schema_for_api()
        email_names = [f["name"] for f in schema["email_channel"]]
        assert "imap_server" in email_names
        assert "smtp_server" in email_names
        assert "password" in email_names

    def test_email_yaml_path_mapping(self) -> None:
        schema = full_schema_for_api()
        email_fields = {f["name"]: f for f in schema["email_channel"]}
        assert email_fields["poll_interval_seconds"]["yaml_path"] == [
            "imap",
            "poll_interval",
        ]

    def test_secret_fields_marked(self) -> None:
        schema = full_schema_for_api()
        email_fields = {f["name"]: f for f in schema["email_channel"]}
        assert email_fields["password"]["secret"] is True
        slack_fields = {f["name"]: f for f in schema["slack_channel"]}
        assert slack_fields["bot_token"]["secret"] is True
