# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/image_pins.py."""

from pathlib import Path

import pytest
import scripts.image_pins as pins


_DIGEST = "sha256:" + "a" * 64
_IMAGE = "docker.io/library/python:3.13-slim"


class TestIsDockerfile:
    @pytest.mark.parametrize(
        "name",
        [
            "Dockerfile",
            "Containerfile",
            "Dockerfile.proxy",
            "Containerfile.proxy",
            "proxy.dockerfile",
            "proxy.Dockerfile",
            "proxy.containerfile",
            "proxy.Containerfile",
        ],
    )
    def test_dockerfiles(self, name: str) -> None:
        assert pins.is_dockerfile(name)

    @pytest.mark.parametrize(
        "name", ["requirements.txt", "dockerfile.md", "Dockerfiles"]
    )
    def test_other_files(self, name: str) -> None:
        assert not pins.is_dockerfile(name)


class TestFindDockerfiles:
    def test_finds_nested_dockerfiles_only(self, tmp_path: Path) -> None:
        bundled = tmp_path / "airut" / "_bundled"
        proxy = bundled / "proxy" / "proxy.dockerfile"
        other = bundled / "x" / "y" / "Dockerfile"
        for path in (proxy, other):
            path.parent.mkdir(parents=True)
            path.write_text("FROM scratch\n")
        (proxy.parent / "requirements.txt").write_text("")
        (proxy.parent / "dir.dockerfile").mkdir()
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")

        assert pins.find_dockerfiles(tmp_path) == [proxy, other]

    def test_defaults_to_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "airut" / "_bundled" / "Dockerfile"
        path.parent.mkdir(parents=True)
        path.write_text("FROM scratch\n")
        monkeypatch.chdir(tmp_path)

        assert pins.find_dockerfiles() == [Path("airut/_bundled/Dockerfile")]


class TestBaseImages:
    def test_plain_from(self) -> None:
        assert pins.base_images(f"FROM {_IMAGE}\nRUN true\n") == [_IMAGE]

    def test_keywords_are_case_insensitive(self) -> None:
        assert pins.base_images(f"from {_IMAGE}\n") == [_IMAGE]

    def test_any_whitespace_separates_keyword(self) -> None:
        """A tab after FROM does not hide the instruction."""
        dockerfile = f"FROM {_IMAGE}\nFROM\tpython:3.13-slim\n"
        assert pins.base_images(dockerfile) == [_IMAGE, "python:3.13-slim"]

    def test_skips_comments_and_blank_lines(self) -> None:
        dockerfile = f"# FROM python\n\n  # indented\nFROM {_IMAGE}\n"
        assert pins.base_images(dockerfile) == [_IMAGE]

    def test_continuation_lines(self) -> None:
        dockerfile = f"FROM \\\n\n  # comment\n  {_IMAGE} \\\n  AS base\n"
        assert pins.base_images(dockerfile) == [_IMAGE]

    def test_continuation_at_end_of_file(self) -> None:
        assert pins.base_images(f"FROM {_IMAGE} \\") == [_IMAGE]

    def test_instruction_without_arguments(self) -> None:
        assert pins.base_images(f"FROM {_IMAGE}\nUSER\n") == [_IMAGE]

    def test_skips_flags(self) -> None:
        dockerfile = f"FROM --platform=linux/amd64 {_IMAGE}\n"
        assert pins.base_images(dockerfile) == [_IMAGE]

    def test_skips_scratch_and_earlier_stages(self) -> None:
        dockerfile = (
            f"FROM {_IMAGE} AS Build\n"
            "FROM build\n"
            "FROM scratch\n"
            "FROM docker.io/library/debian:13 as other\n"
        )
        assert pins.base_images(dockerfile) == [
            _IMAGE,
            "docker.io/library/debian:13",
        ]

    def test_stage_named_like_its_own_image(self) -> None:
        """Only earlier stages can be referenced, not the current one."""
        dockerfile = f"FROM {_IMAGE} AS b\nFROM debian AS debian\n"
        assert pins.base_images(dockerfile) == [_IMAGE, "debian"]

    @pytest.mark.parametrize("ref", ["$BASE", "${BASE}"])
    def test_substitutes_build_argument_default(self, ref: str) -> None:
        dockerfile = f"ARG BASE={_IMAGE}\nFROM {ref}\n"
        assert pins.base_images(dockerfile) == [_IMAGE]

    def test_quoted_default_and_several_declarations(self) -> None:
        dockerfile = f'ARG OTHER BASE="{_IMAGE}"\nFROM ${{BASE}}\n'
        assert pins.base_images(dockerfile) == [_IMAGE]

    def test_build_args_override_defaults(self) -> None:
        dockerfile = f"ARG BASE={_IMAGE}\nARG UNSET\nFROM ${{BASE}}\n"
        assert pins.base_images(
            dockerfile, {"BASE": "localhost/base:1", "UNDECLARED": "x"}
        ) == ["localhost/base:1"]

    def test_override_of_undeclared_argument_is_ignored(self) -> None:
        with pytest.raises(pins.DockerfileError, match="BASE"):
            pins.base_images("FROM ${BASE}\n", {"BASE": "localhost/base:1"})

    def test_argument_without_default(self) -> None:
        with pytest.raises(pins.DockerfileError, match="BASE without"):
            pins.base_images("ARG BASE\nFROM ${BASE}\n")

    def test_stage_argument_is_not_visible_to_from(self) -> None:
        dockerfile = f"FROM {_IMAGE}\nARG BASE={_IMAGE}\nFROM ${{BASE}}\n"
        with pytest.raises(pins.DockerfileError, match="BASE"):
            pins.base_images(dockerfile)

    def test_unsupported_substitution(self) -> None:
        with pytest.raises(pins.DockerfileError, match="Unsupported"):
            pins.base_images("FROM ${BASE:-python}\n")

    def test_from_without_image(self) -> None:
        with pytest.raises(pins.DockerfileError, match="without an image"):
            pins.base_images("FROM --platform=linux/amd64\n")


class TestParseReference:
    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            ("python", (None, "python", None, None)),
            ("python:3.13-slim", (None, "python", "3.13-slim", None)),
            ("library/python", (None, "library/python", None, None)),
            (
                f"{_IMAGE}@{_DIGEST}",
                ("docker.io", "library/python", "3.13-slim", _DIGEST),
            ),
            (
                f"docker.io/library/python@{_DIGEST}",
                ("docker.io", "library/python", None, _DIGEST),
            ),
            ("localhost/base", ("localhost", "base", None, None)),
            (
                "registry:5000/team/base:1",
                ("registry:5000", "team/base", "1", None),
            ),
        ],
    )
    def test_parts(
        self,
        reference: str,
        expected: tuple[str | None, str, str | None, str | None],
    ) -> None:
        registry, repository, tag, digest = expected
        assert pins.parse_reference(reference) == pins.ImageReference(
            registry, repository, tag, digest
        )


class TestPinProblems:
    def test_pinned(self) -> None:
        assert pins.pin_problems(f"{_IMAGE}@{_DIGEST}") == []

    def test_short_name(self) -> None:
        assert pins.pin_problems("python:3.13-slim") == [
            "not fully qualified (no registry)",
            "not pinned by a sha256 digest",
        ]

    def test_no_tag(self) -> None:
        problems = pins.pin_problems(f"docker.io/library/python@{_DIGEST}")
        assert problems == [
            "no tag (the tag records what the digest stands for)"
        ]

    def test_malformed_digest(self) -> None:
        assert pins.pin_problems(f"{_IMAGE}@sha256:abc") == [
            "not pinned by a sha256 digest"
        ]
