# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config diffing utilities."""

from dataclasses import dataclass, field

from airut.config.diff import diff_by_scope, diff_configs
from airut.config.schema import Scope, meta
from airut.config.snapshot import ConfigSnapshot


@dataclass(frozen=True)
class SampleConfig:
    server_field: str = field(
        default="original",
        metadata=meta("A server field", Scope.SERVER),
    )
    repo_field: str = field(
        default="original",
        metadata=meta("A repo field", Scope.REPO),
    )
    task_field: int = field(
        default=0,
        metadata=meta("A task field", Scope.TASK),
    )
    secret_field: str = field(
        default="",
        metadata=meta("A secret", Scope.REPO, secret=True),
    )


class TestDiffConfigs:
    def test_no_changes(self) -> None:
        config = SampleConfig()
        a = ConfigSnapshot(config, frozenset({"server_field"}))
        b = ConfigSnapshot(config, frozenset({"server_field"}))
        assert diff_configs(a, b) == {}

    def test_changed_field(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(server_field="old"),
            frozenset({"server_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(server_field="new"),
            frozenset({"server_field"}),
        )
        changes = diff_configs(a, b)
        assert changes == {"server_field": ("old", "new")}

    def test_multiple_changes(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(server_field="old", task_field=1),
            frozenset({"server_field", "task_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(server_field="new", task_field=2),
            frozenset({"server_field", "task_field"}),
        )
        changes = diff_configs(a, b)
        assert len(changes) == 2
        assert changes["server_field"] == ("old", "new")
        assert changes["task_field"] == (1, 2)

    def test_only_compares_provided_fields(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(server_field="a"),
            frozenset({"server_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(server_field="b", repo_field="changed"),
            frozenset({"server_field", "repo_field"}),
        )
        changes = diff_configs(a, b)
        # repo_field is provided in b but not a — still compared
        # because it's in the union of provided_keys
        assert "server_field" in changes
        assert "repo_field" in changes

    def test_unchanged_field_excluded(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(server_field="same", repo_field="same"),
            frozenset({"server_field", "repo_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(server_field="same", repo_field="same"),
            frozenset({"server_field", "repo_field"}),
        )
        assert diff_configs(a, b) == {}


class TestDiffByScope:
    def test_groups_by_scope(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(server_field="old", repo_field="old", task_field=1),
            frozenset({"server_field", "repo_field", "task_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(server_field="new", repo_field="new", task_field=2),
            frozenset({"server_field", "repo_field", "task_field"}),
        )
        grouped = diff_by_scope(a, b)

        assert "server_field" in grouped[Scope.SERVER]
        assert "repo_field" in grouped[Scope.REPO]
        assert "task_field" in grouped[Scope.TASK]

    def test_empty_scopes_included(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(server_field="old"),
            frozenset({"server_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(server_field="new"),
            frozenset({"server_field"}),
        )
        grouped = diff_by_scope(a, b)

        assert Scope.SERVER in grouped
        assert Scope.REPO in grouped
        assert Scope.TASK in grouped
        assert grouped[Scope.REPO] == {}
        assert grouped[Scope.TASK] == {}

    def test_no_changes(self) -> None:
        config = SampleConfig()
        snap = ConfigSnapshot(config, frozenset({"server_field"}))
        grouped = diff_by_scope(snap, snap)

        for scope_changes in grouped.values():
            assert scope_changes == {}

    def test_secret_field_included(self) -> None:
        a = ConfigSnapshot(
            SampleConfig(secret_field="old_secret"),
            frozenset({"secret_field"}),
        )
        b = ConfigSnapshot(
            SampleConfig(secret_field="new_secret"),
            frozenset({"secret_field"}),
        )
        grouped = diff_by_scope(a, b)
        assert "secret_field" in grouped[Scope.REPO]
        old, new = grouped[Scope.REPO]["secret_field"]
        # Values are actual (not masked) - consumers must check FieldMeta.secret
        assert old == "old_secret"
        assert new == "new_secret"


@dataclass(frozen=True)
class MixedConfig:
    """Config with both annotated and unannotated fields."""

    annotated: str = field(
        default="a",
        metadata=meta("Annotated", Scope.REPO),
    )
    unannotated: str = "b"


class TestDiffConfigsWithSnapshots:
    """Cover ConfigSnapshot unwrapping in diff_configs."""

    def test_unwraps_config_snapshots(self) -> None:
        @dataclass(frozen=True)
        class Inner:
            x: int = 0

        @dataclass(frozen=True)
        class Outer:
            child: Inner = field(
                default_factory=Inner,
                metadata=meta("Child", Scope.REPO),
            )

        inner_a = Inner(x=1)
        inner_b = Inner(x=2)
        snap_a = ConfigSnapshot(inner_a, frozenset({"x"}))
        snap_b = ConfigSnapshot(inner_b, frozenset({"x"}))
        outer_a = Outer(child=snap_a)  # type: ignore[arg-type]
        outer_b = Outer(child=snap_b)  # type: ignore[arg-type]

        a = ConfigSnapshot(outer_a, frozenset({"child"}))
        b = ConfigSnapshot(outer_b, frozenset({"child"}))
        changes = diff_configs(a, b)
        assert "child" in changes

    def test_bogus_provided_key_skipped(self) -> None:
        a = ConfigSnapshot(SampleConfig(), frozenset({"nonexistent"}))
        b = ConfigSnapshot(SampleConfig(), frozenset({"nonexistent"}))
        changes = diff_configs(a, b)
        assert changes == {}


class TestDiffByScopeUnannotated:
    def test_unannotated_defaults_to_server(self) -> None:
        a = ConfigSnapshot(
            MixedConfig(unannotated="old"),
            frozenset({"unannotated"}),
        )
        b = ConfigSnapshot(
            MixedConfig(unannotated="new"),
            frozenset({"unannotated"}),
        )
        grouped = diff_by_scope(a, b)
        assert "unannotated" in grouped[Scope.SERVER]


class TestDiffWithRealConfigs:
    """Verify diffing works with actual config classes."""

    def test_global_config_diff(self) -> None:
        from airut.gateway.config import GlobalConfig

        a = ConfigSnapshot(
            GlobalConfig(max_concurrent_executions=3),
            frozenset({"max_concurrent_executions"}),
        )
        b = ConfigSnapshot(
            GlobalConfig(max_concurrent_executions=5),
            frozenset({"max_concurrent_executions"}),
        )
        changes = diff_configs(a, b)
        assert changes == {"max_concurrent_executions": (3, 5)}

    def test_global_config_diff_by_scope(self) -> None:
        from airut.gateway.config import GlobalConfig

        a = ConfigSnapshot(
            GlobalConfig(max_concurrent_executions=3),
            frozenset({"max_concurrent_executions"}),
        )
        b = ConfigSnapshot(
            GlobalConfig(max_concurrent_executions=5),
            frozenset({"max_concurrent_executions"}),
        )
        grouped = diff_by_scope(a, b)
        assert "max_concurrent_executions" in grouped[Scope.SERVER]
