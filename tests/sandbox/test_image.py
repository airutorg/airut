# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_image.py -- two-layer container image building."""

import subprocess
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from airut.sandbox._image import (
    ImageBuildError,
    _content_hash,
    _ImageInfo,
    _is_image_fresh,
    build_overlay_image,
    build_repo_image,
)


class TestContentHash:
    """Tests for _content_hash function."""

    def test_consistent_bytes(self) -> None:
        """Returns consistent hex digest for same bytes input."""
        h1 = _content_hash(b"hello")
        h2 = _content_hash(b"hello")
        assert h1 == h2

    def test_different_input_different_hash(self) -> None:
        """Returns different hex digest for different input."""
        h1 = _content_hash(b"hello")
        h2 = _content_hash(b"world")
        assert h1 != h2

    def test_returns_64_char_hex(self) -> None:
        """Returns 64-character SHA-256 hex digest."""
        h = _content_hash(b"test")
        assert len(h) == 64

    def test_accepts_str(self) -> None:
        """Accepts string input and produces same hash as equivalent bytes."""
        h1 = _content_hash("hello")
        h2 = _content_hash(b"hello")
        assert h1 == h2


class TestIsImageFresh:
    """Tests for _is_image_fresh function."""

    def test_fresh_image(self) -> None:
        """Returns True for recently built image."""
        info = _ImageInfo(tag="test:123", built_at=datetime.now(UTC))
        assert _is_image_fresh(info, max_age_hours=24) is True

    def test_stale_image(self) -> None:
        """Returns False for old image past max age."""
        info = _ImageInfo(
            tag="test:123",
            built_at=datetime.now(UTC) - timedelta(hours=25),
        )
        assert _is_image_fresh(info, max_age_hours=24) is False

    def test_custom_max_age(self) -> None:
        """Respects custom max_age_hours."""
        info = _ImageInfo(
            tag="test:123",
            built_at=datetime.now(UTC) - timedelta(hours=2),
        )
        assert _is_image_fresh(info, max_age_hours=1) is False
        assert _is_image_fresh(info, max_age_hours=3) is True

    def test_boundary_slightly_under_age(self) -> None:
        """Image slightly under max age is considered fresh."""
        info = _ImageInfo(
            tag="test:123",
            built_at=datetime.now(UTC) - timedelta(hours=23, minutes=59),
        )
        assert _is_image_fresh(info, max_age_hours=24) is True


class TestBuildRepoImage:
    """Tests for build_repo_image function."""

    @patch("airut.sandbox._image.subprocess.run")
    def test_builds_and_returns_tag(self, mock_run: MagicMock) -> None:
        """Builds repo image and returns tagged image name."""
        mock_run.return_value = MagicMock(returncode=0)
        repo_images: dict[str, _ImageInfo] = {}

        dockerfile = b"FROM ubuntu:24.04\nRUN echo hello\n"
        tag = build_repo_image("podman", dockerfile, {}, repo_images, 24)

        assert tag.startswith("airut-repo:")
        assert len(tag.split(":")[1]) == 64
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "build"
        assert "-t" in cmd
        assert tag in cmd

    @patch("airut.sandbox._image.subprocess.run")
    def test_caches_on_second_call(self, mock_run: MagicMock) -> None:
        """Reuses cached image on second call with same content."""
        mock_run.return_value = MagicMock(returncode=0)
        repo_images: dict[str, _ImageInfo] = {}

        dockerfile = b"FROM ubuntu:24.04\n"
        tag1 = build_repo_image("podman", dockerfile, {}, repo_images, 24)
        tag2 = build_repo_image("podman", dockerfile, {}, repo_images, 24)

        assert tag1 == tag2
        mock_run.assert_called_once()

    @patch("airut.sandbox._image.subprocess.run")
    def test_rebuilds_when_stale(self, mock_run: MagicMock) -> None:
        """Rebuilds image when cached version is stale."""
        mock_run.return_value = MagicMock(returncode=0)

        dockerfile = b"FROM ubuntu:24.04\n"
        content_hash = _content_hash(dockerfile)
        repo_images: dict[str, _ImageInfo] = {
            content_hash: _ImageInfo(
                tag=f"airut-repo:{content_hash}",
                built_at=datetime.now(UTC) - timedelta(hours=25),
            )
        }

        build_repo_image("podman", dockerfile, {}, repo_images, 24)
        mock_run.assert_called_once()

    @patch("airut.sandbox._image.subprocess.run")
    def test_context_files_included_in_hash(self, mock_run: MagicMock) -> None:
        """Context files affect the content hash."""
        mock_run.return_value = MagicMock(returncode=0)

        dockerfile = b"FROM ubuntu:24.04\n"
        context1 = {"file1.txt": b"content1"}
        context2 = {"file1.txt": b"content2"}

        repo_images1: dict[str, _ImageInfo] = {}
        repo_images2: dict[str, _ImageInfo] = {}

        tag1 = build_repo_image(
            "podman", dockerfile, context1, repo_images1, 24
        )
        tag2 = build_repo_image(
            "podman", dockerfile, context2, repo_images2, 24
        )

        assert tag1 != tag2

    @patch("airut.sandbox._image.subprocess.run")
    def test_context_files_written_to_build_dir(
        self, mock_run: MagicMock
    ) -> None:
        """Context files are written into the build context directory."""
        mock_run.return_value = MagicMock(returncode=0)
        repo_images: dict[str, _ImageInfo] = {}

        dockerfile = b"FROM ubuntu:24.04\nCOPY gitconfig /root/.gitconfig\n"
        context_files = {"gitconfig": b"[user]\n\tname = Test\n"}

        tag = build_repo_image(
            "podman", dockerfile, context_files, repo_images, 24
        )

        assert tag.startswith("airut-repo:")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "build"

    @patch("airut.sandbox._image.subprocess.run")
    def test_build_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Raises ImageBuildError when build command fails."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "build"], stderr="build error"
        )
        repo_images: dict[str, _ImageInfo] = {}

        with pytest.raises(ImageBuildError, match="Repo image build failed"):
            build_repo_image(
                "podman", b"FROM ubuntu:24.04\n", {}, repo_images, 24
            )

    @patch("airut.sandbox._image.subprocess.run")
    def test_build_failure_no_stderr(self, mock_run: MagicMock) -> None:
        """Handles build failure with no stderr output."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "build"], stderr=""
        )
        repo_images: dict[str, _ImageInfo] = {}

        with pytest.raises(ImageBuildError, match="Repo image build failed"):
            build_repo_image(
                "podman", b"FROM ubuntu:24.04\n", {}, repo_images, 24
            )

    @patch("airut.sandbox._image.subprocess.run")
    def test_custom_container_command(self, mock_run: MagicMock) -> None:
        """Uses specified container command instead of default."""
        mock_run.return_value = MagicMock(returncode=0)
        repo_images: dict[str, _ImageInfo] = {}

        build_repo_image("docker", b"FROM ubuntu:24.04\n", {}, repo_images, 24)

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "docker"

    @patch("airut.sandbox._image.subprocess.run")
    def test_stores_in_cache_after_build(self, mock_run: MagicMock) -> None:
        """Stores built image info in the repo_images cache dict."""
        mock_run.return_value = MagicMock(returncode=0)
        repo_images: dict[str, _ImageInfo] = {}

        dockerfile = b"FROM ubuntu:24.04\n"
        build_repo_image("podman", dockerfile, {}, repo_images, 24)

        assert len(repo_images) == 1
        info = next(iter(repo_images.values()))
        assert info.tag.startswith("airut-repo:")
        assert isinstance(info.built_at, datetime)


class TestBuildOverlayImage:
    """Tests for build_overlay_image function."""

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_builds_overlay(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Builds overlay image on top of repo image."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_entrypoint.return_value = b"#!/bin/bash\nexec claude\n"
        overlay_images: dict[str, _ImageInfo] = {}

        tag = build_overlay_image(
            "podman", "airut-repo:abc123", overlay_images, 24
        )

        assert tag.startswith("airut:")
        mock_run.assert_called_once()

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_overlay_caches(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Reuses cached overlay on second call with same inputs."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_entrypoint.return_value = b"#!/bin/bash\nexec claude\n"
        overlay_images: dict[str, _ImageInfo] = {}

        tag1 = build_overlay_image(
            "podman", "airut-repo:abc123", overlay_images, 24
        )
        tag2 = build_overlay_image(
            "podman", "airut-repo:abc123", overlay_images, 24
        )

        assert tag1 == tag2
        mock_run.assert_called_once()

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_overlay_rebuilds_when_stale(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Rebuilds overlay when cached version is stale."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_entrypoint.return_value = b"#!/bin/bash\nexec claude\n"

        repo_tag = "airut-repo:abc123"
        entrypoint = b"#!/bin/bash\nexec claude\n"
        overlay_hash = _content_hash(repo_tag.encode() + entrypoint)

        overlay_images: dict[str, _ImageInfo] = {
            overlay_hash: _ImageInfo(
                tag=f"airut:{overlay_hash}",
                built_at=datetime.now(UTC) - timedelta(hours=25),
            )
        }

        build_overlay_image("podman", repo_tag, overlay_images, 24)
        mock_run.assert_called_once()

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_overlay_failure_raises_error(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Raises ImageBuildError when overlay build fails."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "build"], stderr="overlay error"
        )
        mock_entrypoint.return_value = b"#!/bin/bash\n"
        overlay_images: dict[str, _ImageInfo] = {}

        with pytest.raises(ImageBuildError, match="Overlay image build failed"):
            build_overlay_image(
                "podman", "airut-repo:abc123", overlay_images, 24
            )

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_overlay_failure_no_stderr(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Handles overlay build failure with no stderr output."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "build"], stderr=""
        )
        mock_entrypoint.return_value = b"#!/bin/bash\n"
        overlay_images: dict[str, _ImageInfo] = {}

        with pytest.raises(ImageBuildError, match="Overlay image build failed"):
            build_overlay_image(
                "podman", "airut-repo:abc123", overlay_images, 24
            )

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_different_repo_tag_produces_different_overlay(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Different repo tags produce different overlay image tags."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_entrypoint.return_value = b"#!/bin/bash\nexec claude\n"

        overlay1: dict[str, _ImageInfo] = {}
        overlay2: dict[str, _ImageInfo] = {}

        tag1 = build_overlay_image("podman", "airut-repo:aaa", overlay1, 24)
        tag2 = build_overlay_image("podman", "airut-repo:bbb", overlay2, 24)

        assert tag1 != tag2

    @patch("airut.sandbox._image.get_entrypoint_content")
    @patch("airut.sandbox._image.subprocess.run")
    def test_stores_in_cache_after_build(
        self, mock_run: MagicMock, mock_entrypoint: MagicMock
    ) -> None:
        """Stores built overlay info in the overlay_images cache dict."""
        mock_run.return_value = MagicMock(returncode=0)
        mock_entrypoint.return_value = b"#!/bin/bash\nexec claude\n"
        overlay_images: dict[str, _ImageInfo] = {}

        build_overlay_image("podman", "airut-repo:abc123", overlay_images, 24)

        assert len(overlay_images) == 1
        info = next(iter(overlay_images.values()))
        assert info.tag.startswith("airut:")
        assert isinstance(info.built_at, datetime)


class TestImageInfo:
    """Tests for _ImageInfo dataclass."""

    def test_create(self) -> None:
        """Creates _ImageInfo with tag and built_at."""
        now = datetime.now(UTC)
        info = _ImageInfo(tag="airut:test", built_at=now)
        assert info.tag == "airut:test"
        assert info.built_at == now
