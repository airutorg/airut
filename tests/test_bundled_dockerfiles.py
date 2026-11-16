# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Bundled Dockerfiles build only from fully qualified, pinned images.

The proxy image holds every task's real credentials.  A short image name
resolves differently depending on the host's registries configuration,
and a tag without a digest trusts whatever the tag points at on the day
of the build.  See ``scripts/image_pins.py``.
"""

from pathlib import Path

import pytest
from scripts.image_pins import base_images, find_dockerfiles, pin_problems

from airut.sandbox._proxy import PROXY_BASE_IMAGE_ARG


_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROXY_DOCKERFILE = (
    _REPO_ROOT / "airut" / "_bundled" / "proxy" / "proxy.dockerfile"
)
_DOCKERFILES = find_dockerfiles(_REPO_ROOT)


def test_finds_bundled_dockerfiles() -> None:
    """The scan covers the proxy Dockerfile, so the checks below are live."""
    assert _PROXY_DOCKERFILE in _DOCKERFILES


@pytest.mark.parametrize(
    "path",
    _DOCKERFILES,
    ids=[str(p.relative_to(_REPO_ROOT)) for p in _DOCKERFILES],
)
def test_base_images_are_fully_qualified_and_pinned(path: Path) -> None:
    """Every FROM names registry, tag and sha256 digest."""
    images = base_images(path.read_text())
    assert images, f"{path}: no base image found"
    problems = {image: pin_problems(image) for image in images}
    assert not any(problems.values()), (
        f"{path}: base images must look like "
        f"docker.io/library/python:3.13-slim@sha256:<digest>: {problems}"
    )


def test_proxy_base_image_is_the_build_argument() -> None:
    """network.proxy_base_image (passed as the build argument) replaces it."""
    dockerfile = _PROXY_DOCKERFILE.read_text()
    custom = "localhost/proxy-base:1"
    assert base_images(dockerfile, {PROXY_BASE_IMAGE_ARG: custom}) == [custom]
