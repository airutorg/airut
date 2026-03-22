# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for ConfigSnapshot user-set value tracking."""

from dataclasses import dataclass, field

from airut.config.snapshot import ConfigSnapshot


@dataclass(frozen=True)
class SampleConfig:
    host: str = "localhost"
    port: int = 8080
    debug: bool = False


@dataclass(frozen=True)
class NestedConfig:
    name: str = "default"


@dataclass(frozen=True)
class ParentConfig:
    child: NestedConfig = field(default_factory=NestedConfig)
    value: int = 0


class TestConfigSnapshot:
    def test_value_property(self) -> None:
        config = SampleConfig(host="example.com", port=9090)
        snap = ConfigSnapshot(config, frozenset({"host", "port"}))
        assert snap.value is config

    def test_provided_keys(self) -> None:
        config = SampleConfig()
        snap = ConfigSnapshot(config, frozenset({"host"}))
        assert snap.provided_keys == frozenset({"host"})

    def test_to_dict_only_provided(self) -> None:
        config = SampleConfig(host="example.com", port=9090, debug=True)
        snap = ConfigSnapshot(config, frozenset({"host", "port"}))

        result = snap.to_dict()
        assert result == {"host": "example.com", "port": 9090}
        assert "debug" not in result

    def test_to_dict_include_defaults(self) -> None:
        config = SampleConfig(host="example.com")
        snap = ConfigSnapshot(config, frozenset({"host"}))

        result = snap.to_dict(include_defaults=True)
        assert result == {
            "host": "example.com",
            "port": 8080,
            "debug": False,
        }

    def test_to_dict_empty_provided(self) -> None:
        config = SampleConfig()
        snap = ConfigSnapshot(config, frozenset())

        result = snap.to_dict()
        assert result == {}

    def test_to_dict_all_provided(self) -> None:
        config = SampleConfig(host="a", port=1, debug=True)
        snap = ConfigSnapshot(config, frozenset({"host", "port", "debug"}))

        result = snap.to_dict()
        assert result == {"host": "a", "port": 1, "debug": True}


class TestConfigSnapshotNested:
    def test_nested_config_snapshot(self) -> None:
        child = NestedConfig(name="custom")
        child_snap = ConfigSnapshot(child, frozenset({"name"}))
        parent = ParentConfig(child=child_snap, value=42)  # type: ignore[arg-type]
        parent_snap = ConfigSnapshot(parent, frozenset({"child", "value"}))

        result = parent_snap.to_dict()
        assert result == {"child": {"name": "custom"}, "value": 42}

    def test_nested_config_snapshot_defaults_excluded(self) -> None:
        child = NestedConfig(name="custom")
        child_snap = ConfigSnapshot(child, frozenset({"name"}))
        parent = ParentConfig(child=child_snap, value=42)  # type: ignore[arg-type]
        # Only "child" is provided, not "value"
        parent_snap = ConfigSnapshot(parent, frozenset({"child"}))

        result = parent_snap.to_dict()
        assert result == {"child": {"name": "custom"}}
        assert "value" not in result


class TestConfigSnapshotDict:
    def test_dict_field(self) -> None:
        @dataclass(frozen=True)
        class Config:
            env: dict[str, str] = field(default_factory=dict)

        config = Config(env={"KEY": "VALUE"})
        snap = ConfigSnapshot(config, frozenset({"env"}))
        result = snap.to_dict()
        assert result == {"env": {"KEY": "VALUE"}}


class TestConfigSnapshotListAndDataclass:
    def test_list_field(self) -> None:
        @dataclass(frozen=True)
        class Config:
            items: list[str] = field(default_factory=list)

        config = Config(items=["a", "b"])
        snap = ConfigSnapshot(config, frozenset({"items"}))
        result = snap.to_dict()
        assert result == {"items": ["a", "b"]}

    def test_tuple_field(self) -> None:
        @dataclass(frozen=True)
        class Config:
            tags: tuple[str, ...] = ()

        config = Config(tags=("x", "y"))
        snap = ConfigSnapshot(config, frozenset({"tags"}))
        result = snap.to_dict()
        assert result == {"tags": ["x", "y"]}

    def test_nested_dataclass_field(self) -> None:
        @dataclass(frozen=True)
        class Inner:
            x: int = 0
            y: int = 0

        @dataclass(frozen=True)
        class Config:
            inner: Inner = field(default_factory=Inner)

        config = Config(inner=Inner(x=1, y=2))
        snap = ConfigSnapshot(config, frozenset({"inner"}))
        result = snap.to_dict()
        assert result == {"inner": {"x": 1, "y": 2}}


class TestConfigSnapshotEquality:
    def test_equal(self) -> None:
        config = SampleConfig()
        a = ConfigSnapshot(config, frozenset({"host"}))
        b = ConfigSnapshot(config, frozenset({"host"}))
        assert a == b

    def test_different_provided(self) -> None:
        config = SampleConfig()
        a = ConfigSnapshot(config, frozenset({"host"}))
        b = ConfigSnapshot(config, frozenset({"port"}))
        assert a != b

    def test_different_instance(self) -> None:
        a = ConfigSnapshot(SampleConfig(host="a"), frozenset({"host"}))
        b = ConfigSnapshot(SampleConfig(host="b"), frozenset({"host"}))
        assert a != b

    def test_not_equal_to_non_snapshot(self) -> None:
        snap = ConfigSnapshot(SampleConfig(), frozenset())
        assert snap != "not a snapshot"


class TestConfigSnapshotRepr:
    def test_repr(self) -> None:
        config = SampleConfig()
        snap = ConfigSnapshot(config, frozenset({"host"}))
        r = repr(snap)
        assert "SampleConfig" in r
        assert "1/3" in r


class TestConfigSnapshotWithRealConfigs:
    """Verify ConfigSnapshot works with actual config classes."""

    def test_global_config(self) -> None:
        from airut.gateway.config import GlobalConfig

        config = GlobalConfig(max_concurrent_executions=5)
        snap = ConfigSnapshot(config, frozenset({"max_concurrent_executions"}))

        result = snap.to_dict()
        assert result == {"max_concurrent_executions": 5}
        assert "dashboard_enabled" not in result

    def test_global_config_round_trip(self) -> None:
        from airut.gateway.config import GlobalConfig

        config = GlobalConfig(
            max_concurrent_executions=5,
            dashboard_port=8080,
        )
        snap = ConfigSnapshot(
            config,
            frozenset({"max_concurrent_executions", "dashboard_port"}),
        )

        result = snap.to_dict()
        assert result == {
            "max_concurrent_executions": 5,
            "dashboard_port": 8080,
        }
