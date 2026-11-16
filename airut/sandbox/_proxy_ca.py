# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""mitmproxy CA certificate for the network sandbox.

The sandbox's proxies terminate TLS with a CA that every sandboxed
container trusts.  The CA lives in ``MITMPROXY_CONFDIR`` on the host,
shared by every sandbox instance of the user (the gateway and the
standalone CLI), and is generated from the proxy image when it is
missing or incomplete.

Generation runs mitmproxy's ``CertStore.from_store()`` in a container
that writes the CA files and exits.  The files are written to a staging
directory and moved into place only after the container has exited
successfully and every expected file is present, so a failed, timed-out
or interrupted generation never leaves a partial CA that a later start
would trust.  A lock file serializes generation between processes
sharing the directory.
"""

from __future__ import annotations

import contextlib
import fcntl
import logging
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Generator
from pathlib import Path


logger = logging.getLogger(__name__)

MITMPROXY_CONFDIR = Path.home() / ".airut-mitmproxy"
CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"

#: Every file mitmproxy's ``CertStore.create_store()`` writes (checked
#: against mitmproxy 12.3.1).  ``mitmproxy-ca.pem`` holds the key and
#: certificate the proxy signs with; ``CA_CERT_FILENAME`` is the
#: certificate containers trust.  The CA is complete when every file
#: exists and is non-empty.
CA_FILENAMES = (
    "mitmproxy-ca.pem",
    "mitmproxy-ca.p12",
    CA_CERT_FILENAME,
    "mitmproxy-ca-cert.cer",
    "mitmproxy-ca-cert.p12",
    "mitmproxy-dhparam.pem",
)

#: Maximum time for the CA generation container to exit.  Generation
#: takes about a second on a fast host; the margin is for slow ones
#: (loaded, emulated, or starting containers cold).
CA_GENERATION_TIMEOUT = 60.0

_LOCK_FILENAME = ".airut-ca.lock"
_STAGING_PREFIX = ".airut-ca-staging-"
_CONTAINER_CA_DIR = "/ca"

# Writes the CA into the directory given as the first argument, flushes
# it to disk, then exits.  from_store() generates the CA when it is
# missing and loads it back, so a CA that does not load fails the
# command.  The files are flushed here because the host user may not be
# able to open them: under a rootful runtime the key files are owned by
# root with mode 0600.
_GENERATE_SCRIPT = """\
import os, sys
from mitmproxy.certs import CertStore
from mitmproxy.options import CONF_BASENAME, KEY_SIZE
ca_dir = sys.argv[1]
CertStore.from_store(ca_dir, CONF_BASENAME, KEY_SIZE)
for name in os.listdir(ca_dir):
    fd = os.open(os.path.join(ca_dir, name), os.O_RDONLY)
    os.fsync(fd)
    os.close(fd)
"""


class CaCertError(Exception):
    """The CA certificate could not be generated."""


def ensure_ca_cert(
    confdir: Path,
    *,
    container_command: str,
    image_tag: str,
    container_name: str,
) -> Path:
    """Ensure *confdir* holds a complete CA, generating one if needed.

    A complete CA is reused.  Otherwise a new CA is generated and
    replaces any files of an incomplete one.

    Args:
        confdir: Host directory holding the CA (mounted into proxies).
        container_command: Container runtime command.
        image_tag: Proxy image to generate the CA with.
        container_name: Name for the generation container.

    Returns:
        Path to the CA certificate PEM file.

    Raises:
        CaCertError: If generation fails, does not finish within
            ``CA_GENERATION_TIMEOUT``, or does not write every expected
            file.
    """
    cert_path = confdir / CA_CERT_FILENAME
    if not _missing_files(confdir):
        logger.debug("CA certificate exists: %s", cert_path)
        return cert_path

    confdir.mkdir(parents=True, exist_ok=True)
    with _generation_lock(confdir):
        # Another process may have generated the CA while we waited.
        if not _missing_files(confdir):
            logger.debug("CA certificate generated concurrently")
            return cert_path

        logger.info("Generating mitmproxy CA certificate in %s", confdir)
        # Clean up after an interrupted generation: first its container,
        # which holds the name and may still write to its staging
        # directory, then the staging directories.
        _remove_container(container_command, container_name)
        for stale in confdir.glob(f"{_STAGING_PREFIX}*"):
            shutil.rmtree(stale, ignore_errors=True)
        staging = Path(tempfile.mkdtemp(prefix=_STAGING_PREFIX, dir=confdir))
        try:
            _generate(
                staging,
                container_command=container_command,
                image_tag=image_tag,
                container_name=container_name,
            )
            _install(staging, confdir)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    logger.info("CA certificate generated: %s", cert_path)
    return cert_path


def _missing_files(directory: Path) -> list[str]:
    """CA files that *directory* lacks or holds empty."""
    missing = []
    for name in CA_FILENAMES:
        try:
            st = (directory / name).stat()
        except FileNotFoundError:
            missing.append(name)
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
            missing.append(name)
    return missing


@contextlib.contextmanager
def _generation_lock(confdir: Path) -> Generator[None]:
    """Hold an exclusive lock on *confdir*'s CA lock file."""
    with open(confdir / _LOCK_FILENAME, "a") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _generate(
    staging: Path,
    *,
    container_command: str,
    image_tag: str,
    container_name: str,
) -> None:
    """Write a new CA into *staging* from a container that then exits.

    Raises:
        CaCertError: If the container exits non-zero or does not exit
            within ``CA_GENERATION_TIMEOUT``.
    """
    cmd = [
        container_command,
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--entrypoint",
        "python3",
        "-v",
        f"{staging}:{_CONTAINER_CA_DIR}:rw",
        image_tag,
        "-c",
        _GENERATE_SCRIPT,
        _CONTAINER_CA_DIR,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CA_GENERATION_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # Killing the client does not stop the container.
        _remove_container(container_command, container_name)
        raise CaCertError(
            "CA certificate generation did not finish within "
            f"{CA_GENERATION_TIMEOUT:g}s"
        ) from None
    if result.returncode != 0:
        raise CaCertError(
            f"CA certificate generation failed with exit status "
            f"{result.returncode}: {result.stderr.strip()}"
        )


def _install(staging: Path, confdir: Path) -> None:
    """Move a complete CA from *staging* into *confdir*.

    Raises:
        CaCertError: If *staging* lacks an expected file.
    """
    missing = _missing_files(staging)
    if missing:
        raise CaCertError(
            "CA certificate generation did not write " + ", ".join(missing)
        )
    # Remove an incomplete CA's files first: an interrupted install then
    # leaves files of one CA only, which the next start regenerates.
    # Renames need no access to the files themselves, which the host
    # user may not be able to open (see _GENERATE_SCRIPT).
    for name in CA_FILENAMES:
        (confdir / name).unlink(missing_ok=True)
    for name in CA_FILENAMES:
        os.replace(staging / name, confdir / name)
    fd = os.open(confdir, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_container(container_command: str, name: str) -> None:
    """Force-remove container *name* if it exists."""
    subprocess.run(
        [container_command, "rm", "-f", name],
        capture_output=True,
        check=False,
    )
