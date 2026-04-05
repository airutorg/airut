# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_image_cache.py -- unified image cache."""

import subprocess
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from airut.sandbox._image_cache import (
    ImageBuildError,
    ImageBuildSpec,
    ImageCache,
    _format_age,
    _parse_timestamp,
    content_hash,
)


class TestContentHash:
    """Tests for content_hash function."""

    def test_consistent_hash(self) -> None:
        """Returns consistent hex digest for same spec."""
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        h1 = content_hash(spec)
        h2 = content_hash(spec)
        assert h1 == h2

    def test_different_dockerfile_different_hash(self) -> None:
        """Returns different hex digest for different Dockerfile."""
        s1 = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        s2 = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:22.04\n")
        assert content_hash(s1) != content_hash(s2)

    def test_returns_64_char_hex(self) -> None:
        """Returns 64-character SHA-256 hex digest."""
        spec = ImageBuildSpec(kind="repo", dockerfile=b"test")
        h = content_hash(spec)
        assert len(h) == 64

    def test_context_files_affect_hash(self) -> None:
        """Context files are included in the hash."""
        s1 = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"a.txt": b"content1"},
        )
        s2 = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"a.txt": b"content2"},
        )
        assert content_hash(s1) != content_hash(s2)

    def test_context_file_names_affect_hash(self) -> None:
        """Context file names are included in the hash."""
        s1 = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"a.txt": b"content"},
        )
        s2 = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"b.txt": b"content"},
        )
        assert content_hash(s1) != content_hash(s2)

    def test_context_files_sorted_order(self) -> None:
        """Hash is deterministic regardless of context file insertion order."""
        s1 = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"b.txt": b"2", "a.txt": b"1"},
        )
        s2 = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"a.txt": b"1", "b.txt": b"2"},
        )
        assert content_hash(s1) == content_hash(s2)


class TestImageBuildSpec:
    """Tests for ImageBuildSpec dataclass."""

    def test_create(self) -> None:
        """Creates ImageBuildSpec with required fields."""
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu\n")
        assert spec.kind == "repo"
        assert spec.dockerfile == b"FROM ubuntu\n"
        assert spec.context_files == {}

    def test_create_with_context(self) -> None:
        """Creates ImageBuildSpec with context files."""
        spec = ImageBuildSpec(
            kind="proxy",
            dockerfile=b"FROM python:3.13\n",
            context_files={"script.py": b"print('hello')"},
        )
        assert spec.context_files == {"script.py": b"print('hello')"}

    def test_frozen(self) -> None:
        """ImageBuildSpec is immutable."""
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu\n")
        with pytest.raises(AttributeError):
            spec.kind = "overlay"  # ty:ignore[invalid-assignment]


class TestImageCacheTagFor:
    """Tests for ImageCache.tag_for()."""

    def test_tag_format(self) -> None:
        """Tag follows {prefix}-{kind}:{hash} format."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu\n")
        tag = cache.tag_for(spec)
        assert tag.startswith("airut-repo:")
        assert len(tag.split(":")[1]) == 64

    def test_custom_prefix(self) -> None:
        """Tag uses the configured resource prefix."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut-cli",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="proxy", dockerfile=b"FROM python\n")
        tag = cache.tag_for(spec)
        assert tag.startswith("airut-cli-proxy:")

    def test_deterministic(self) -> None:
        """Same spec always produces the same tag."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu\n")
        assert cache.tag_for(spec) == cache.tag_for(spec)


class TestImageCacheEnsure:
    """Tests for ImageCache.ensure()."""

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_first_build_no_cache_false(self, mock_run: MagicMock) -> None:
        """First build (image does not exist) uses no_cache=False."""
        # First call: image inspect returns non-zero (not found)
        # Second call: podman build succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect: not found
            MagicMock(returncode=0),  # build: success
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        tag = cache.ensure(spec)

        assert tag.startswith("airut-repo:")
        # Build command should NOT have --no-cache
        build_call = mock_run.call_args_list[1]
        build_cmd = build_call[0][0]
        assert "--no-cache" not in build_cmd

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_fresh_image_reused(self, mock_run: MagicMock) -> None:
        """Fresh existing image is reused without rebuild."""
        now = datetime.now(UTC)
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=now.isoformat(),
        )
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        tag = cache.ensure(spec)

        assert tag.startswith("airut-repo:")
        # Only inspect was called, no build
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "image"
        assert cmd[2] == "inspect"

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_stale_image_rebuilt_with_no_cache(
        self, mock_run: MagicMock
    ) -> None:
        """Stale image is rebuilt with --no-cache."""
        old_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=old_time),  # inspect: stale
            MagicMock(returncode=0),  # build: success
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        cache.ensure(spec)

        # Build should have --no-cache
        build_call = mock_run.call_args_list[1]
        build_cmd = build_call[0][0]
        assert "--no-cache" in build_cmd

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_force_rebuilds_with_no_cache(self, mock_run: MagicMock) -> None:
        """force=True rebuilds with --no-cache even when fresh."""
        now = datetime.now(UTC)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=now.isoformat()),  # inspect: fresh
            MagicMock(returncode=0),  # build: success
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        cache.ensure(spec, force=True)

        build_call = mock_run.call_args_list[1]
        build_cmd = build_call[0][0]
        assert "--no-cache" in build_cmd

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_max_age_zero_always_rebuilds(self, mock_run: MagicMock) -> None:
        """max_age_hours=0 rebuilds with --no-cache."""
        now = datetime.now(UTC)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=now.isoformat()),  # inspect: exists
            MagicMock(returncode=0),  # build: success
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=0,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        cache.ensure(spec)

        build_call = mock_run.call_args_list[1]
        build_cmd = build_call[0][0]
        assert "--no-cache" in build_cmd

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_build_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Raises ImageBuildError when build fails."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect: not found
            subprocess.CalledProcessError(
                1, ["podman", "build"], stderr="build error"
            ),
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")

        with pytest.raises(ImageBuildError, match="Image build failed"):
            cache.ensure(spec)

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_custom_container_command(self, mock_run: MagicMock) -> None:
        """Uses specified container command."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect: not found
            MagicMock(returncode=0),  # build: success
        ]
        cache = ImageCache(
            container_command="docker",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(kind="repo", dockerfile=b"FROM ubuntu:24.04\n")
        cache.ensure(spec)

        # Both inspect and build use docker
        inspect_cmd = mock_run.call_args_list[0][0][0]
        build_cmd = mock_run.call_args_list[1][0][0]
        assert inspect_cmd[0] == "docker"
        assert build_cmd[0] == "docker"

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_context_files_written_to_build_dir(
        self, mock_run: MagicMock
    ) -> None:
        """Context files are written into the build context directory."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect: not found
            MagicMock(returncode=0),  # build: success
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\nCOPY gitconfig /root/.gitconfig\n",
            context_files={"gitconfig": b"[user]\n\tname = Test\n"},
        )
        tag = cache.ensure(spec)

        assert tag.startswith("airut-repo:")
        build_cmd = mock_run.call_args_list[1][0][0]
        assert build_cmd[0] == "podman"
        assert build_cmd[1] == "build"

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_rejects_path_traversal_in_context_files(
        self, mock_run: MagicMock
    ) -> None:
        """Context file names with path separators are rejected."""
        mock_run.side_effect = [
            MagicMock(returncode=1),  # inspect: not found
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        spec = ImageBuildSpec(
            kind="repo",
            dockerfile=b"FROM ubuntu:24.04\n",
            context_files={"../escape.txt": b"malicious"},
        )

        with pytest.raises(ValueError, match="Invalid context file name"):
            cache.ensure(spec)


class TestFormatAge:
    """Tests for _format_age()."""

    def test_hours_and_minutes(self) -> None:
        """Ages >= 1h show hours and minutes."""
        assert _format_age(timedelta(hours=25, minutes=30)) == "25h30m"

    def test_minutes_and_seconds(self) -> None:
        """Ages >= 1m but < 1h show minutes and seconds."""
        assert _format_age(timedelta(minutes=5, seconds=42)) == "5m42s"

    def test_seconds_only(self) -> None:
        """Ages < 1m show seconds only."""
        assert _format_age(timedelta(seconds=7)) == "7s"

    def test_zero(self) -> None:
        """Zero age shows 0s."""
        assert _format_age(timedelta()) == "0s"


class TestParseTimestamp:
    """Tests for _parse_timestamp()."""

    def test_go_time_format_with_nanoseconds(self) -> None:
        """Parses Go time.Time.String() format from podman."""
        raw = "2026-03-15 16:19:16.937789677 +0000 UTC"
        dt = _parse_timestamp(raw)
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 3
        assert dt.day == 15
        assert dt.hour == 16
        assert dt.minute == 19
        assert dt.second == 16
        assert dt.microsecond == 937789
        assert dt.tzinfo is not None

    def test_go_time_format_variable_fraction(self) -> None:
        """Parses Go format with fewer fractional digits."""
        raw = "2026-03-14 10:46:10.84137945 +0000 UTC"
        dt = _parse_timestamp(raw)
        assert dt is not None
        assert dt.hour == 10
        assert dt.minute == 46
        assert dt.second == 10
        assert dt.microsecond == 841379

    def test_go_time_format_no_fraction(self) -> None:
        """Parses Go format without fractional seconds."""
        raw = "2026-01-01 00:00:00 +0000 UTC"
        dt = _parse_timestamp(raw)
        assert dt is not None
        assert dt.microsecond == 0

    def test_go_time_format_negative_offset(self) -> None:
        """Parses Go format with negative timezone offset."""
        raw = "2026-06-15 08:30:00.123456789 -0500 CDT"
        dt = _parse_timestamp(raw)
        assert dt is not None
        assert dt.hour == 8
        from datetime import timedelta, timezone

        assert dt.tzinfo == timezone(timedelta(hours=-5))

    def test_iso_format(self) -> None:
        """Parses ISO 8601 format (docker)."""
        dt = _parse_timestamp("2026-01-15T10:30:00+00:00")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 1
        assert dt.day == 15

    def test_naive_iso_gets_utc(self) -> None:
        """Naive ISO datetime gets UTC timezone attached."""
        dt = _parse_timestamp("2026-01-15T10:30:00")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_returns_none_for_garbage(self) -> None:
        """Returns None for unparseable input."""
        assert _parse_timestamp("not-a-timestamp") is None


class TestImageCacheGetImageCreated:
    """Tests for ImageCache.get_image_created()."""

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_returns_datetime_for_existing_image(
        self, mock_run: MagicMock
    ) -> None:
        """Returns timezone-aware datetime for existing image."""
        ts = "2026-01-15 10:30:00.123456789 +0000 UTC"
        mock_run.return_value = MagicMock(returncode=0, stdout=ts)
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        result = cache.get_image_created("airut-repo:abc123")
        assert result is not None
        assert result.year == 2026
        assert result.month == 1
        assert result.day == 15

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_returns_none_for_missing_image(self, mock_run: MagicMock) -> None:
        """Returns None when image does not exist."""
        mock_run.return_value = MagicMock(returncode=1)
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.get_image_created("airut-repo:nonexistent") is None

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_returns_none_for_unparseable_timestamp(
        self, mock_run: MagicMock
    ) -> None:
        """Returns None and logs warning for unparseable timestamp."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="not-a-timestamp"
        )
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.get_image_created("airut-repo:abc123") is None


class TestImageCachePruneImages:
    """Tests for ImageCache.prune_images()."""

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_dangling_and_old_images(self, mock_run: MagicMock) -> None:
        """Prunes dangling images and removes old prefixed images."""
        old_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        mock_run.side_effect = [
            # 1. image prune -f
            MagicMock(returncode=0, stdout=""),
            # 2. images --filter reference=airut-*
            MagicMock(
                returncode=0,
                stdout="airut-repo:abc123\nairut-proxy:def456\n",
            ),
            # 3. inspect airut-repo:abc123 (stale)
            MagicMock(returncode=0, stdout=old_time),
            # 4. rmi airut-repo:abc123
            MagicMock(returncode=0),
            # 5. inspect airut-proxy:def456 (fresh)
            MagicMock(returncode=0, stdout=datetime.now(UTC).isoformat()),
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        removed = cache.prune_images()

        assert removed == 1
        # Verify prune call
        prune_cmd = mock_run.call_args_list[0][0][0]
        assert prune_cmd == ["podman", "image", "prune", "-f"]
        # Verify rmi called for stale image only
        rmi_cmd = mock_run.call_args_list[3][0][0]
        assert rmi_cmd == ["podman", "rmi", "airut-repo:abc123"]

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_handles_prune_failure(self, mock_run: MagicMock) -> None:
        """Continues with old-image removal even if prune -f fails."""
        mock_run.side_effect = [
            # 1. image prune -f fails
            MagicMock(returncode=1, stderr="permission denied"),
            # 2. images --filter (empty)
            MagicMock(returncode=0, stdout=""),
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        removed = cache.prune_images()
        assert removed == 0

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_handles_image_list_failure(
        self, mock_run: MagicMock
    ) -> None:
        """Returns 0 when image listing fails."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # prune ok
            MagicMock(returncode=1, stderr="error"),  # list fails
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.prune_images() == 0

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_handles_rmi_failure(self, mock_run: MagicMock) -> None:
        """Counts only successfully removed images."""
        old_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # prune
            MagicMock(returncode=0, stdout="airut-repo:abc\n"),  # list
            MagicMock(returncode=0, stdout=old_time),  # inspect
            MagicMock(returncode=1, stderr="in use"),  # rmi fails
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.prune_images() == 0

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_skips_none_tag(self, mock_run: MagicMock) -> None:
        """Skips <none>:<none> entries from image listing."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # prune
            MagicMock(returncode=0, stdout="<none>:<none>\n"),  # list
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.prune_images() == 0

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_no_old_images(self, mock_run: MagicMock) -> None:
        """Returns 0 when no images are stale."""
        fresh_time = datetime.now(UTC).isoformat()
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # prune
            MagicMock(returncode=0, stdout="airut-repo:abc\n"),  # list
            MagicMock(returncode=0, stdout=fresh_time),  # inspect
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.prune_images() == 0

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_uses_correct_prefix_filter(
        self, mock_run: MagicMock
    ) -> None:
        """Uses correct resource prefix in filter."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),
            MagicMock(returncode=0, stdout=""),
        ]
        cache = ImageCache(
            container_command="docker",
            resource_prefix="airut-cli",
            max_age_hours=24,
        )
        cache.prune_images()

        list_cmd = mock_run.call_args_list[1][0][0]
        assert "--filter" in list_cmd
        idx = list_cmd.index("--filter")
        assert list_cmd[idx + 1] == "reference=airut-cli-*"

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_logs_dangling_output(self, mock_run: MagicMock) -> None:
        """Logs non-empty dangling prune output."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="Deleted: sha256:abc123\n"),
            MagicMock(returncode=0, stdout=""),
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        cache.prune_images()

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_skips_unparseable_timestamp(
        self, mock_run: MagicMock
    ) -> None:
        """Skips images whose timestamp cannot be parsed."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # prune
            MagicMock(returncode=0, stdout="airut-repo:abc\n"),  # list
            MagicMock(returncode=0, stdout="not-a-timestamp"),  # inspect
        ]
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        assert cache.prune_images() == 0

    @patch("airut.sandbox._image_cache.subprocess.run")
    def test_prune_skips_when_max_age_zero(self, mock_run: MagicMock) -> None:
        """Returns 0 immediately when max_age_hours=0 (always-rebuild mode)."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=0,
        )
        assert cache.prune_images() == 0
        mock_run.assert_not_called()


class TestImageCacheIsStale:
    """Tests for ImageCache._is_stale()."""

    def test_fresh_image(self) -> None:
        """Recently created image is not stale."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        now = datetime.now(UTC)
        assert cache._is_stale(now) is False

    def test_stale_image(self) -> None:
        """Old image past max age is stale."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        old = datetime.now(UTC) - timedelta(hours=25)
        assert cache._is_stale(old) is True

    def test_boundary_slightly_under_max_age(self) -> None:
        """Image slightly under max age is not stale."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )
        almost = datetime.now(UTC) - timedelta(hours=23, minutes=59)
        assert cache._is_stale(almost) is False

    def test_custom_max_age(self) -> None:
        """Respects custom max_age_hours."""
        cache = ImageCache(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=1,
        )
        two_hours_ago = datetime.now(UTC) - timedelta(hours=2)
        assert cache._is_stale(two_hours_ago) is True
