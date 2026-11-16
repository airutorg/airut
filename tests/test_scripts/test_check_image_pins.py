# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/check_image_pins.py."""

import http.client
import json
import sys
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest
import scripts.check_image_pins as pins
from scripts.image_pins import ImageReference


_OLD = "sha256:" + "a" * 64
_NEW = "sha256:" + "b" * 64
_IMAGE = "docker.io/library/python:3.13-slim"
_OCI_INDEX = "application/vnd.oci.image.index.v1+json"


class _Response:
    """Minimal urlopen response for tests."""

    def __init__(
        self, headers: dict[str, str] | None = None, body: bytes = b""
    ) -> None:
        self.headers = headers or {}
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _manifest(digest: str = _NEW, media_type: str = _OCI_INDEX) -> _Response:
    return _Response(
        {"Docker-Content-Digest": digest, "Content-Type": media_type}
    )


def _http_error(code: int, headers: dict[str, str] | None = None) -> HTTPError:
    message = Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return HTTPError("https://example.com", code, "error", message, None)


def _write_dockerfile(root: Path, content: str) -> Path:
    path = root / "airut" / "_bundled" / "proxy" / "proxy.dockerfile"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


class TestRegistryApi:
    def test_docker_hub_official_image(self) -> None:
        assert pins._registry_api("docker.io", "python") == (
            "registry-1.docker.io",
            "library/python",
        )

    def test_docker_hub_namespaced(self) -> None:
        assert pins._registry_api("docker.io", "nixos/nix") == (
            "registry-1.docker.io",
            "nixos/nix",
        )

    def test_other_registry(self) -> None:
        assert pins._registry_api("ghcr.io", "org/image") == (
            "ghcr.io",
            "org/image",
        )


class TestBearerToken:
    _CHALLENGE = (
        'Bearer realm="https://auth.docker.io/token",'
        'service="registry.docker.io",'
        'scope="repository:library/python:pull"'
    )

    def test_fetches_token(self) -> None:
        requests: list[Request] = []

        def fake_urlopen(request: Request, **kwargs: object) -> _Response:
            requests.append(request)
            return _Response(body=json.dumps({"token": "t"}).encode())

        with patch.object(pins, "urlopen_with_retry", fake_urlopen):
            assert pins._bearer_token(self._CHALLENGE) == "t"
        assert requests[0].full_url == (
            "https://auth.docker.io/token?service=registry.docker.io"
            "&scope=repository%3Alibrary%2Fpython%3Apull"
        )

    def test_access_token_and_bare_realm(self) -> None:
        requests: list[Request] = []

        def fake_urlopen(request: Request, **kwargs: object) -> _Response:
            requests.append(request)
            return _Response(body=b'{"access_token": "t"}')

        with patch.object(pins, "urlopen_with_retry", fake_urlopen):
            token = pins._bearer_token('bearer realm="https://r.example/t"')
        assert token == "t"
        assert requests[0].full_url == "https://r.example/t"

    def test_rejects_other_scheme(self) -> None:
        with pytest.raises(pins.RegistryError, match="authentication"):
            pins._bearer_token('Basic realm="registry"')

    @pytest.mark.parametrize(
        "challenge", ["Bearer ", 'Bearer realm="http://r.example/t"']
    )
    def test_rejects_missing_or_insecure_realm(self, challenge: str) -> None:
        with pytest.raises(pins.RegistryError, match="realm"):
            pins._bearer_token(challenge)

    @pytest.mark.parametrize(
        ("body", "match"),
        [
            (b"<html>", "not JSON"),
            (b"[]", "not a JSON object"),
            (b'{"token": ""}', "no token"),
            (b'{"token": 1}', "no token"),
        ],
    )
    def test_rejects_bad_response(self, body: bytes, match: str) -> None:
        with (
            patch.object(
                pins, "urlopen_with_retry", return_value=_Response(body=body)
            ),
            pytest.raises(pins.RegistryError, match=match),
        ):
            pins._bearer_token(self._CHALLENGE)


class TestResolveDigest:
    _REF = ImageReference("docker.io", "python", "3.13-slim", None)
    _URL = "https://registry-1.docker.io/v2/library/python/manifests/3.13-slim"

    def test_anonymous_registry(self) -> None:
        requests: list[Request] = []

        def fake_urlopen(request: Request, **kwargs: object) -> _Response:
            requests.append(request)
            return _manifest()

        ref = ImageReference("ghcr.io", "org/image", "1", None)
        with patch.object(pins, "urlopen_with_retry", fake_urlopen):
            assert pins.resolve_digest(ref) == _NEW
        assert (
            requests[0].full_url == "https://ghcr.io/v2/org/image/manifests/1"
        )
        assert requests[0].get_method() == "HEAD"
        accept = requests[0].get_header("Accept")
        assert accept is not None
        assert accept.startswith(_OCI_INDEX)

    def test_token_challenge(self) -> None:
        requests: list[Request] = []

        def fake_urlopen(request: Request, **kwargs: object) -> _Response:
            requests.append(request)
            if request.full_url.startswith("https://auth.docker.io/"):
                return _Response(body=b'{"token": "secret"}')
            if request.get_header("Authorization") is None:
                raise _http_error(
                    401,
                    {
                        "WWW-Authenticate": (
                            'Bearer realm="https://auth.docker.io/token"'
                        )
                    },
                )
            return _manifest()

        with patch.object(pins, "urlopen_with_retry", fake_urlopen):
            assert pins.resolve_digest(self._REF) == _NEW
        assert [r.full_url for r in requests] == [
            self._URL,
            "https://auth.docker.io/token",
            self._URL,
        ]
        assert requests[2].get_header("Authorization") == "Bearer secret"

    @pytest.mark.parametrize(
        "media_type",
        [
            "application/vnd.docker.distribution.manifest.list.v2+json",
            f"{_OCI_INDEX}; charset=utf-8",
        ],
    )
    def test_index_media_types(self, media_type: str) -> None:
        response = _manifest(media_type=media_type)
        with patch.object(pins, "urlopen_with_retry", return_value=response):
            assert pins.resolve_digest(self._REF) == _NEW

    @pytest.mark.parametrize(
        ("headers", "match"),
        [
            (
                {
                    "Docker-Content-Digest": _NEW,
                    "Content-Type": (
                        "application/vnd.oci.image.manifest.v1+json"
                    ),
                },
                "Not a multi-platform index: application/vnd.oci",
            ),
            (
                {"Docker-Content-Digest": _NEW},
                "Not a multi-platform index: no Content-Type",
            ),
            ({"Content-Type": _OCI_INDEX}, "No sha256 digest"),
            (
                {
                    "Docker-Content-Digest": "sha256:a",
                    "Content-Type": _OCI_INDEX,
                },
                "No sha256 digest",
            ),
        ],
    )
    def test_rejects_unusable_response(
        self, headers: dict[str, str], match: str
    ) -> None:
        with (
            patch.object(
                pins, "urlopen_with_retry", return_value=_Response(headers)
            ),
            pytest.raises(pins.RegistryError, match=match),
        ):
            pins.resolve_digest(self._REF)

    def test_other_http_error_propagates(self) -> None:
        with (
            patch.object(
                pins, "urlopen_with_retry", side_effect=_http_error(404)
            ),
            pytest.raises(HTTPError),
        ):
            pins.resolve_digest(self._REF)

    @pytest.mark.parametrize(
        "ref",
        [
            ImageReference(None, "python", "3.13", None),
            ImageReference("docker.io", "python", None, _OLD),
        ],
    )
    def test_requires_registry_and_tag(self, ref: ImageReference) -> None:
        with pytest.raises(pins.RegistryError, match="registry and a tag"):
            pins.resolve_digest(ref)


class TestReplaceReference:
    def test_replaces_whole_references_only(self) -> None:
        content = (
            f"ARG A={_IMAGE}\n"
            f"ARG B={_IMAGE}-bookworm\n"
            f"ARG C={_IMAGE}@{_OLD}\n"
            f"ARG D=mirror.example.com/{_IMAGE}\n"
            f'# "{_IMAGE}" is the base, not {_IMAGE}.1\n'
        )
        assert pins._replace_reference(content, _IMAGE, "X") == (
            "ARG A=X\n"
            f"ARG B={_IMAGE}-bookworm\n"
            f"ARG C={_IMAGE}@{_OLD}\n"
            f"ARG D=mirror.example.com/{_IMAGE}\n"
            f'# "X" is the base, not {_IMAGE}.1\n',
            2,
        )


class TestCheckImagePins:
    def test_no_dockerfiles(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert pins.check_image_pins(root=tmp_path) == 0
        assert "No bundled Dockerfiles found." in capsys.readouterr().out

    def test_up_to_date(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_dockerfile(tmp_path, f"FROM {_IMAGE}@{_OLD}\nFROM scratch\n")
        with patch.object(pins, "resolve_digest", return_value=_OLD):
            assert pins.check_image_pins(root=tmp_path) == 0
        assert "All 1 pinned image(s) up to date." in capsys.readouterr().out

    def test_up_to_date_verbose(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_dockerfile(tmp_path, f"FROM {_IMAGE}@{_OLD}\n")
        with patch.object(pins, "resolve_digest", return_value=_OLD):
            assert pins.check_image_pins(root=tmp_path, verbose=True) == 0
        out = capsys.readouterr().out
        assert "Up to date:" in out
        assert f"proxy.dockerfile: {_IMAGE}\n" in out
        assert "All 1" not in out

    def test_repeated_reference_resolved_once(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pinned = f"{_IMAGE}@{_OLD}"
        _write_dockerfile(tmp_path, f"FROM {pinned} AS a\nFROM {pinned}\n")
        with patch.object(pins, "resolve_digest", return_value=_OLD) as res:
            assert pins.check_image_pins(root=tmp_path) == 0
        res.assert_called_once()
        assert "All 1 pinned image(s) up to date." in capsys.readouterr().out

    def test_outdated_report_only(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write_dockerfile(tmp_path, f"ARG B={_IMAGE}@{_OLD}\nFROM $B\n")
        with patch.object(pins, "resolve_digest", return_value=_NEW):
            assert pins.check_image_pins(root=tmp_path) == 1
        out = capsys.readouterr().out
        assert "Outdated:" in out
        assert f"{_IMAGE} ({_OLD[:19]} → {_NEW[:19]})" in out
        assert path.read_text() == f"ARG B={_IMAGE}@{_OLD}\nFROM $B\n"

    def test_outdated_fix(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write_dockerfile(tmp_path, f"ARG B={_IMAGE}@{_OLD}\nFROM $B\n")
        with patch.object(pins, "resolve_digest", return_value=_NEW):
            assert pins.check_image_pins(root=tmp_path, fix=True) == 0
        out = capsys.readouterr().out
        assert "Fixed (updated):" in out
        assert "Fixed 1 pin(s)." in out
        assert path.read_text() == f"ARG B={_IMAGE}@{_NEW}\nFROM $B\n"

    def test_fix_of_reference_assembled_from_build_args(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A reference that is not in the file literally is an error."""
        content = (
            f"ARG PY=3.13\nFROM docker.io/library/python:${{PY}}-slim@{_OLD}\n"
        )
        path = _write_dockerfile(tmp_path, content)
        with patch.object(pins, "resolve_digest", return_value=_NEW):
            assert pins.check_image_pins(root=tmp_path, fix=True) == 1
        out = capsys.readouterr().out
        assert f"{_IMAGE}@{_OLD} — cannot rewrite: not written literally" in out
        assert "Fixed" not in out
        assert path.read_text() == content

    def test_unpinned_report_only(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write_dockerfile(tmp_path, f"FROM {_IMAGE}\n")
        with patch.object(pins, "resolve_digest", return_value=_NEW):
            assert pins.check_image_pins(root=tmp_path) == 1
        out = capsys.readouterr().out
        assert f"Unpinned:\n  {path}: {_IMAGE} → {_NEW[:19]}" in out
        assert path.read_text() == f"FROM {_IMAGE}\n"

    def test_unpinned_fix(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write_dockerfile(tmp_path, f"FROM {_IMAGE}\n")
        with patch.object(pins, "resolve_digest", return_value=_NEW):
            assert pins.check_image_pins(root=tmp_path, fix=True) == 0
        assert "Fixed (pinned):" in capsys.readouterr().out
        assert path.read_text() == f"FROM {_IMAGE}@{_NEW}\n"

    def test_invalid_reference_needs_manual_fix(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write_dockerfile(tmp_path, "FROM python:3.13-slim\n")
        with patch.object(pins, "resolve_digest") as resolve:
            assert pins.check_image_pins(root=tmp_path, fix=True) == 1
        resolve.assert_not_called()
        out = capsys.readouterr().out
        assert "Cannot be pinned automatically (fix by hand):" in out
        assert "python:3.13-slim — not fully qualified (no registry)" in out
        assert "Fixed" not in out
        assert path.read_text() == "FROM python:3.13-slim\n"

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ("FROM ${BASE}\n", "FROM uses build argument BASE without"),
            ("FROM scratch\n", "no base image found"),
        ],
    )
    def test_dockerfile_error(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        content: str,
        message: str,
    ) -> None:
        _write_dockerfile(tmp_path, content)
        assert pins.check_image_pins(root=tmp_path) == 1
        out = capsys.readouterr().out
        assert "Errors:" in out
        assert message in out

    @pytest.mark.parametrize(
        "error",
        [
            URLError("blocked"),
            http.client.IncompleteRead(b""),
            pins.RegistryError("bad"),
        ],
    )
    def test_resolve_error(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        error: Exception,
    ) -> None:
        path = _write_dockerfile(tmp_path, f"FROM {_IMAGE}@{_OLD}\n")
        with patch.object(pins, "resolve_digest", side_effect=error):
            assert pins.check_image_pins(root=tmp_path, fix=True) == 1
        out = capsys.readouterr().out
        assert f"{_IMAGE}@{_OLD} — cannot resolve:" in out
        assert path.read_text() == f"FROM {_IMAGE}@{_OLD}\n"


class TestMain:
    def test_passes_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", ["check_image_pins.py", "--fix", "-v"])
        with patch.object(pins, "check_image_pins", return_value=0) as check:
            assert pins.main() == 0
        check.assert_called_once_with(fix=True, verbose=True)
