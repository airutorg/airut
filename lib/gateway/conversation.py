# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Conversation state management for email gateway.

This module manages git-based conversation isolation, where each email
conversation gets its own git clone with persistent Claude Code state.
"""

import logging
import re
import secrets
import shutil
from pathlib import Path

from lib.git_mirror import GitMirrorCache


logger = logging.getLogger(__name__)


CONVERSATION_ID_PATTERN = re.compile(r"^[0-9a-f]{8}$")


class ConversationError(Exception):
    """Base exception for conversation-related errors."""


class GitCloneError(ConversationError):
    """Raised when git clone operation fails."""


class ConversationManager:
    """Manages isolated git checkouts for email conversations.

    Each conversation is identified by an 8-character hex UUID and gets:
    - A conversation directory with metadata (context.json)
    - A workspace subdirectory with git repo and Claude state
    - An inbox/ directory for email attachments

    Storage structure:
        {storage_dir}/conversations/{id}/context.json - Session metadata
        {storage_dir}/conversations/{id}/workspace/ - Git repo & workspace

    Uses a local git mirror cache for fast clones and disk space savings.

    Attributes:
        repo_url: Git repository URL to clone from (ssh or https).
        storage_dir: Root storage directory for all data.
        conversations_dir: Directory for conversation data
            (storage_dir/conversations).
        mirror: GitMirrorCache instance for fast clones.
    """

    def __init__(self, repo_url: str, storage_dir: Path) -> None:
        """Initialize conversation manager.

        Args:
            repo_url: Git repository URL (e.g., git@github.com:user/repo.git).
            storage_dir: Root storage directory.

        Raises:
            ValueError: If repo_url is empty.
        """
        self.repo_url = repo_url
        self.storage_dir = storage_dir
        self.conversations_dir = storage_dir / "conversations"

        if not self.repo_url:
            raise ValueError("Repository URL cannot be empty")

        # Create storage directories if they don't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.conversations_dir.mkdir(parents=True, exist_ok=True)

        # Initialize git mirror cache (not hidden anymore)
        mirror_path = storage_dir / "git-mirror"
        self.mirror = GitMirrorCache(mirror_path, repo_url)
        self.mirror.ensure_mirror_exists()
        logger.info("Git mirror cache initialized at %s", mirror_path)

    @staticmethod
    def generate_id() -> str:
        """Generate a unique 8-character hex conversation ID.

        Uses secrets.token_hex(4) for cryptographically strong randomness.

        Returns:
            8-character lowercase hex string.
        """
        return secrets.token_hex(4)

    def initialize_new(self) -> tuple[str, Path]:
        """Initialize a new conversation with fresh git clone.

        Creates:
        1. 8-character hex conversation ID
        2. Session directory: sessions/{id}/
        3. Git clone from mirror to: sessions/{id}/workspace/

        Returns:
            Tuple of (conversation_id, workspace_path).

        Raises:
            GitCloneError: If git clone fails.
        """
        conversation_id = self.generate_id()
        conversation_dir = self.get_conversation_dir(conversation_id)
        workspace_path = self.get_workspace_path(conversation_id)

        logger.info("Creating new conversation: %s", conversation_id)
        logger.debug("Cloning from mirror to %s", workspace_path)

        try:
            # Create conversation directory
            conversation_dir.mkdir(parents=True, exist_ok=True)

            # Clone from mirror (acquires shared lock)
            self.mirror.clone_from_mirror(workspace_path)

            logger.info(
                "Conversation %s initialized successfully", conversation_id
            )
            return conversation_id, workspace_path

        except Exception as e:
            error_msg = str(e)
            logger.error(
                "Git clone failed for %s: %s", conversation_id, error_msg
            )

            # Cleanup partial directory if it exists
            if conversation_dir.exists():
                logger.debug(
                    "Cleaning up partial conversation at %s", conversation_dir
                )
                shutil.rmtree(conversation_dir)

            raise GitCloneError(
                f"Failed to clone repository for conversation "
                f"{conversation_id}: {error_msg}"
            ) from e

    def resume_existing(self, conversation_id: str) -> Path:
        """Resume an existing conversation.

        Verifies conversation workspace exists and returns its path.
        Does NOT pull from origin - preserves local state.

        Args:
            conversation_id: 8-character hex conversation ID.

        Returns:
            Path to conversation workspace.

        Raises:
            ConversationError: If conversation workspace doesn't exist.
            ValueError: If conversation_id format is invalid.
        """
        if not CONVERSATION_ID_PATTERN.match(conversation_id):
            raise ValueError(
                f"Invalid conversation ID format: {conversation_id}. "
                "Expected 8-character lowercase hex."
            )

        workspace_path = self.get_workspace_path(conversation_id)

        if not workspace_path.exists():
            raise ConversationError(
                f"Conversation {conversation_id} not found at {workspace_path}"
            )

        logger.info("Resuming conversation: %s", conversation_id)
        logger.debug("Workspace path: %s", workspace_path)

        return workspace_path

    def get_conversation_dir(self, conversation_id: str) -> Path:
        """Get conversation directory for a conversation ID.

        Args:
            conversation_id: 8-character hex conversation ID.

        Returns:
            Path to conversation directory (contains context.json).
            Example: /storage/conversations/abc12345/
        """
        return self.conversations_dir / conversation_id

    def get_workspace_path(self, conversation_id: str) -> Path:
        """Get workspace path for a conversation ID.

        Args:
            conversation_id: 8-character hex conversation ID.

        Returns:
            Path to workspace directory (contains git repo).
            Example: /storage/conversations/abc12345/workspace/
        """
        return self.get_conversation_dir(conversation_id) / "workspace"

    def exists(self, conversation_id: str) -> bool:
        """Check if a conversation exists.

        Args:
            conversation_id: 8-character hex conversation ID.

        Returns:
            True if conversation workspace exists.
        """
        return self.get_workspace_path(conversation_id).exists()

    def delete(self, conversation_id: str) -> bool:
        """Delete a conversation and all its files.

        Deletes the entire conversation directory (context.json + workspace/).

        Args:
            conversation_id: 8-character hex conversation ID.

        Returns:
            True if conversation was deleted, False if it didn't exist.
        """
        conversation_dir = self.get_conversation_dir(conversation_id)

        if not conversation_dir.exists():
            logger.debug(
                "Conversation %s does not exist, nothing to delete",
                conversation_id,
            )
            return False

        logger.info("Deleting conversation: %s", conversation_id)
        shutil.rmtree(conversation_dir)
        logger.debug("Deleted conversation directory at %s", conversation_dir)

        return True

    def list_all(self) -> list[str]:
        """List all conversation IDs in conversations directory.

        Returns:
            List of 8-character hex conversation IDs.
        """
        if not self.conversations_dir.exists():
            return []

        conversation_ids = []
        for item in self.conversations_dir.iterdir():
            if item.is_dir() and CONVERSATION_ID_PATTERN.match(item.name):
                conversation_ids.append(item.name)

        logger.debug("Found %d conversations", len(conversation_ids))
        return sorted(conversation_ids)
