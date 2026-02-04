# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Git mirror cache for fast conversation creation.

This module provides a local git mirror that acts as a reference repository
for cloning conversations. The mirror is updated periodically from the origin
repository and uses file locking to ensure safe concurrent access.

Benefits:
- Fast clones: Objects are fetched from local disk instead of network
- Disk space savings: Shared objects between mirror and conversations
- Safe concurrent access: Shared locks for clones, exclusive lock for updates
"""

import fcntl
import logging
import subprocess
from pathlib import Path


logger = logging.getLogger(__name__)


class MirrorError(Exception):
    """Base exception for mirror-related errors."""


class GitMirrorCache:
    """Manages a local git mirror for fast conversation cloning.

    The mirror is a bare repository (--mirror) that contains all refs and
    objects from the origin. Conversations clone directly from the mirror,
    speeding up clones by avoiding network transfer.

    IMPORTANT: Clones do NOT use --reference because the resulting
    .git/objects/info/alternates file would point outside the workspace,
    breaking git operations when mounted in containers. Instead, we perform
    regular clones that copy all objects into the workspace.

    Thread safety:
    - Multiple clones can happen concurrently (shared lock)
    - Updates block clones and vice versa (exclusive lock)

    Attributes:
        mirror_path: Path to the bare mirror repository.
        origin_url: Git repository URL (GitHub).
        lock_file: Path to the lock file for synchronization.
    """

    def __init__(self, mirror_path: Path, origin_url: str) -> None:
        """Initialize mirror cache.

        Args:
            mirror_path: Path where mirror repository will be stored.
            origin_url: Git repository URL to mirror from.

        Raises:
            ValueError: If origin_url is empty.
        """
        if not origin_url:
            raise ValueError("Origin URL cannot be empty")

        self.mirror_path = mirror_path
        self.origin_url = origin_url
        # Lock file is placed next to mirror directory
        self.lock_file = mirror_path.parent / f".{mirror_path.name}.lock"

        logger.debug(
            "Initialized GitMirrorCache: mirror=%s, origin=%s",
            mirror_path,
            origin_url,
        )

    def ensure_mirror_exists(self) -> None:
        """Initialize mirror if it doesn't exist (one-time setup).

        Creates a bare mirror clone from origin. This is safe to call
        multiple times - if mirror exists, does nothing.

        Raises:
            MirrorError: If git clone fails.
        """
        if self.mirror_path.exists():
            logger.debug("Mirror already exists at %s", self.mirror_path)
            return

        logger.info("Creating git mirror at %s", self.mirror_path)
        logger.debug("Mirroring from %s", self.origin_url)

        try:
            # Create parent directory if needed
            self.mirror_path.parent.mkdir(parents=True, exist_ok=True)

            subprocess.run(
                [
                    "git",
                    "clone",
                    "--mirror",
                    self.origin_url,
                    str(self.mirror_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            logger.info("Git mirror created successfully")

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            logger.error("Failed to create git mirror: %s", error_msg)
            raise MirrorError(
                f"Failed to create git mirror: {error_msg}"
            ) from e

    def update_mirror(self) -> None:
        """Update mirror from origin (requires exclusive lock).

        Fetches all refs from origin and prunes deleted refs. This operation
        acquires an exclusive lock, blocking all clone operations until
        complete.

        Raises:
            MirrorError: If mirror doesn't exist or update fails.
        """
        if not self.mirror_path.exists():
            raise MirrorError(
                f"Mirror does not exist at {self.mirror_path}. "
                "Call ensure_mirror_exists() first."
            )

        logger.info("Updating git mirror from origin")
        logger.debug("Acquiring exclusive lock on %s", self.lock_file)

        # Create lock file if it doesn't exist
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.lock_file, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            logger.debug("Exclusive lock acquired, updating mirror")

            try:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.mirror_path),
                        "remote",
                        "update",
                        "--prune",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                logger.info("Git mirror updated successfully")

            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                logger.error("Failed to update git mirror: %s", error_msg)
                raise MirrorError(
                    f"Failed to update git mirror: {error_msg}"
                ) from e

            # Lock released automatically when context exits
            logger.debug("Exclusive lock released")

    def list_directory(self, path: str) -> list[str]:
        """List files in a directory from the mirror's default branch.

        Uses ``git ls-tree`` to enumerate files in a directory. Only returns
        regular files (blobs), not subdirectories.

        Args:
            path: Path relative to the repository root
                (e.g. ``.airut/container``).

        Returns:
            List of filenames (not full paths) in the directory.

        Raises:
            MirrorError: If the mirror doesn't exist, the directory is not
                found, or the default branch cannot be determined.
        """
        if not self.mirror_path.exists():
            raise MirrorError(
                f"Mirror does not exist at {self.mirror_path}. "
                "Call ensure_mirror_exists() first."
            )

        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.lock_file, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)

            branch = self._get_default_branch_from_mirror()
            ref = f"refs/heads/{branch}"

            # Ensure path ends with / to list directory contents
            dir_path = path.rstrip("/") + "/"

            try:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.mirror_path),
                        "ls-tree",
                        "--name-only",
                        ref,
                        dir_path,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                # ls-tree returns full paths, extract just filenames
                files = []
                for line in result.stdout.strip().split("\n"):
                    if line:
                        # Extract filename from path
                        filename = line.split("/")[-1]
                        files.append(filename)
                return files
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                raise MirrorError(
                    f"Failed to list {path} from mirror at {ref}: {error_msg}"
                ) from e

    def read_file(self, path: str) -> bytes:
        """Read a file from the mirror's default branch.

        Extracts a file from the mirror at the default branch ref.  Uses a
        shared lock so reads can happen concurrently with clones but are
        blocked during mirror updates.

        Args:
            path: Path relative to the repository root
                (e.g. ``.airut/network-allowlist.yaml``).

        Returns:
            File contents as bytes.

        Raises:
            MirrorError: If the mirror doesn't exist, the file is not found,
                or the default branch cannot be determined.
        """
        if not self.mirror_path.exists():
            raise MirrorError(
                f"Mirror does not exist at {self.mirror_path}. "
                "Call ensure_mirror_exists() first."
            )

        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.lock_file, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)

            branch = self._get_default_branch_from_mirror()
            ref = f"refs/heads/{branch}"

            try:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.mirror_path),
                        "show",
                        f"{ref}:{path}",
                    ],
                    check=True,
                    capture_output=True,
                )
                return result.stdout
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode().strip() if e.stderr else str(e)
                raise MirrorError(
                    f"Failed to read {path} from mirror at {ref}: {error_msg}"
                ) from e

    def _get_default_branch_from_mirror(self) -> str:
        """Get the default branch name from the bare mirror.

        In a ``--mirror`` clone, HEAD points directly to the default branch
        (e.g. ``refs/heads/main``).  This differs from a regular clone where
        ``refs/remotes/origin/HEAD`` is used.

        Returns:
            Default branch name (e.g., ``main``, ``master``).

        Raises:
            MirrorError: If unable to determine default branch.
        """
        try:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.mirror_path),
                    "symbolic-ref",
                    "HEAD",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            # Output format: "refs/heads/main" -> extract "main"
            full_ref = result.stdout.strip()
            branch_name = full_ref.removeprefix("refs/heads/")
            logger.debug("Detected mirror default branch: %s", branch_name)
            return branch_name
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            logger.error(
                "Failed to detect mirror default branch: %s", error_msg
            )
            raise MirrorError(
                f"Failed to detect mirror default branch: {error_msg}"
            ) from e

    def _get_default_branch(self, repo_path: Path) -> str:
        """Get the default branch name from a regular (non-bare) clone.

        Queries the symbolic ref for origin/HEAD to determine which branch
        is the default (typically 'main' or 'master').

        Args:
            repo_path: Path to the git repository.

        Returns:
            Default branch name (e.g., 'main', 'master').

        Raises:
            MirrorError: If unable to determine default branch.
        """
        try:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo_path),
                    "symbolic-ref",
                    "refs/remotes/origin/HEAD",
                    "--short",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            # Output format: "origin/main" -> extract "main"
            default_ref = result.stdout.strip()
            branch_name = default_ref.split("/")[-1]
            logger.debug("Detected default branch: %s", branch_name)
            return branch_name

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            logger.error("Failed to detect default branch: %s", error_msg)
            raise MirrorError(
                f"Failed to detect default branch: {error_msg}"
            ) from e

    def clone_from_mirror(self, dest: Path) -> None:
        """Clone from local mirror, set origin to GitHub (requires shared lock).

        Creates a new repository at dest by cloning from the local mirror,
        then sets the origin remote to GitHub, fetches latest refs, and
        resets the local branch to match the remote default branch.

        IMPORTANT: Does not use --reference flag because that would create an
        alternates file (.git/objects/info/alternates) pointing to the mirror
        path. When the conversation workspace is mounted into a container, the
        container cannot access files outside its workspace, causing git
        operations to fail with "unable to find alternate object database"
        errors.

        Instead, this performs a regular clone (copying all objects), which
        works correctly when mounted in containers since all objects are
        contained within the workspace directory.

        This operation acquires a shared lock, allowing multiple concurrent
        clones but blocking mirror updates.

        Args:
            dest: Destination path for the new clone.

        Raises:
            MirrorError: If mirror doesn't exist or clone fails.
            ValueError: If dest already exists.
        """
        if not self.mirror_path.exists():
            raise MirrorError(
                f"Mirror does not exist at {self.mirror_path}. "
                "Call ensure_mirror_exists() first."
            )

        if dest.exists():
            raise ValueError(f"Destination already exists: {dest}")

        logger.debug("Cloning from mirror to %s", dest)
        logger.debug("Acquiring shared lock on %s", self.lock_file)

        # Create lock file if it doesn't exist
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.lock_file, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            logger.debug("Shared lock acquired, cloning from mirror")

            try:
                # Step 1: Clone from local mirror (fast, local operation)
                # Do NOT use --reference flag - it creates alternates file
                # pointing outside the workspace, which breaks when mounted
                # in containers. Regular clone copies all objects into
                # workspace, making it container-safe.
                logger.debug("Step 1: Cloning from local mirror")
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--quiet",
                        str(self.mirror_path),
                        str(dest),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                logger.debug("Clone successful: %s", dest)

                # Step 2: Set origin to GitHub
                logger.debug(
                    "Step 2: Setting origin to GitHub: %s", self.origin_url
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(dest),
                        "remote",
                        "set-url",
                        "origin",
                        self.origin_url,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                # Step 3: Fetch from GitHub origin
                logger.debug("Step 3: Fetching from GitHub origin")
                subprocess.run(
                    ["git", "-C", str(dest), "fetch", "origin", "--prune"],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                # Step 4: Detect default branch and reset to match origin
                logger.debug("Step 4: Detecting default branch")
                default_branch = self._get_default_branch(dest)
                logger.debug(
                    "Step 5: Resetting %s to origin/%s",
                    default_branch,
                    default_branch,
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(dest),
                        "reset",
                        "--hard",
                        f"origin/{default_branch}",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                logger.error("Failed to clone from mirror: %s", error_msg)
                raise MirrorError(
                    f"Failed to clone from mirror: {error_msg}"
                ) from e

            # Lock released automatically when context exits
            logger.debug("Shared lock released")
