# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for outbox cleanup after delivery."""

from pathlib import Path
from unittest.mock import patch

from airut.conversation import (
    ConversationLayout,
    ConversationStore,
    create_conversation_layout,
    prepare_conversation,
)
from airut.gateway.channel import UndeliveredFile
from airut.gateway.service.outbox import finish_delivery, undelivered_note


def _layout(tmp_path: Path) -> ConversationLayout:
    layout = create_conversation_layout(tmp_path / "conv1")
    prepare_conversation(layout)
    return layout


class TestFinishDelivery:
    def test_sets_aside_undelivered_and_clears_the_rest(
        self, tmp_path: Path
    ) -> None:
        layout = _layout(tmp_path)
        (layout.outbox / "sent.txt").write_text("delivered")
        dump = layout.outbox / "dump.bin"
        dump.write_bytes(b"data")

        finish_delivery(layout, "conv1", [UndeliveredFile(dump, "too big")])

        assert list(layout.outbox.iterdir()) == []
        assert (layout.storage / "undelivered" / "dump.bin").exists()
        store = ConversationStore(layout.conversation_dir)
        assert store.get_undelivered() == {"dump.bin": "too big"}

    def test_records_only_files_that_moved(self, tmp_path: Path) -> None:
        """A file that could not be moved is not reported to the agent."""
        layout = _layout(tmp_path)
        dump = layout.outbox / "dump.bin"
        dump.write_bytes(b"data")
        gone = layout.outbox / "gone.bin"

        finish_delivery(
            layout,
            "conv1",
            [UndeliveredFile(gone, "too big"), UndeliveredFile(dump, "huge")],
        )

        store = ConversationStore(layout.conversation_dir)
        assert store.get_undelivered() == {"dump.bin": "huge"}

    def test_nothing_undelivered(self, tmp_path: Path) -> None:
        layout = _layout(tmp_path)
        (layout.outbox / "sent.txt").write_text("delivered")

        finish_delivery(layout, "conv1", [])

        assert list(layout.outbox.iterdir()) == []
        assert ConversationStore(layout.conversation_dir).load() is None

    def test_record_failure_still_clears_outbox(self, tmp_path: Path) -> None:
        """The reply is out: a failed record must not re-send the files."""
        layout = _layout(tmp_path)
        (layout.outbox / "sent.txt").write_text("delivered")
        dump = layout.outbox / "dump.bin"
        dump.write_bytes(b"data")

        with patch.object(
            ConversationStore,
            "record_undelivered",
            side_effect=OSError("disk full"),
        ):
            finish_delivery(layout, "conv1", [UndeliveredFile(dump, "big")])

        assert list(layout.outbox.iterdir()) == []
        assert (layout.storage / "undelivered" / "dump.bin").exists()


class TestUndeliveredNote:
    def test_names_files_with_reasons(self) -> None:
        note = undelivered_note({"dump.bin": "too big", "a.png": "failed"})
        assert note == (
            " Some files you left in /outbox last time did not reach the "
            "user, so I have moved them to /storage/undelivered/: "
            "dump.bin (too big), a.png (failed)."
        )
