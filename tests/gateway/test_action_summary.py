# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for action_summary module."""

from airut.claude_output.types import ToolUseBlock
from airut.gateway.action_summary import summarize_action


def _block(tool_name: str, **tool_input: object) -> ToolUseBlock:
    """Create a ToolUseBlock for testing."""
    return ToolUseBlock(
        tool_id="t1",
        tool_name=tool_name,
        tool_input=dict(tool_input),
    )


class TestSummarizeAction:
    def test_todowrite_returns_none(self) -> None:
        assert summarize_action(_block("TodoWrite", todos=[])) is None

    def test_bash_with_description(self) -> None:
        result = summarize_action(
            _block("Bash", command="ls -la", description="List files")
        )
        assert result == "List files"

    def test_bash_with_command(self) -> None:
        result = summarize_action(_block("Bash", command="pytest tests/"))
        assert result == "Running: pytest tests/"

    def test_bash_empty(self) -> None:
        result = summarize_action(_block("Bash"))
        assert result == "Running command"

    def test_read(self) -> None:
        result = summarize_action(
            _block("Read", file_path="/workspace/src/main.py")
        )
        assert result == "Reading /workspace/src/main.py"

    def test_read_empty(self) -> None:
        result = summarize_action(_block("Read"))
        assert result == "Reading file"

    def test_write(self) -> None:
        result = summarize_action(
            _block("Write", file_path="/workspace/output.txt")
        )
        assert result == "Writing /workspace/output.txt"

    def test_write_empty(self) -> None:
        result = summarize_action(_block("Write"))
        assert result == "Writing file"

    def test_edit(self) -> None:
        result = summarize_action(
            _block("Edit", file_path="/workspace/src/app.py")
        )
        assert result == "Editing /workspace/src/app.py"

    def test_edit_empty(self) -> None:
        result = summarize_action(_block("Edit"))
        assert result == "Editing file"

    def test_grep(self) -> None:
        result = summarize_action(_block("Grep", pattern="def main"))
        assert result == 'Searching for "def main"'

    def test_grep_empty(self) -> None:
        result = summarize_action(_block("Grep"))
        assert result == "Searching files"

    def test_glob(self) -> None:
        result = summarize_action(_block("Glob", pattern="**/*.py"))
        assert result == "Finding files: **/*.py"

    def test_glob_empty(self) -> None:
        result = summarize_action(_block("Glob"))
        assert result == "Finding files"

    def test_task(self) -> None:
        result = summarize_action(_block("Task", description="Search codebase"))
        assert result == "Search codebase"

    def test_task_empty(self) -> None:
        result = summarize_action(_block("Task"))
        assert result == "Running sub-task"

    def test_webfetch(self) -> None:
        result = summarize_action(
            _block("WebFetch", url="https://example.com/api")
        )
        assert result == "Fetching https://example.com/api"

    def test_webfetch_empty(self) -> None:
        result = summarize_action(_block("WebFetch"))
        assert result == "Fetching URL"

    def test_websearch(self) -> None:
        result = summarize_action(_block("WebSearch", query="python asyncio"))
        assert result == "Searching: python asyncio"

    def test_websearch_empty(self) -> None:
        result = summarize_action(_block("WebSearch"))
        assert result == "Web search"

    def test_unknown_tool(self) -> None:
        result = summarize_action(_block("SomeFutureTool", data="x"))
        assert result == "Using SomeFutureTool"

    def test_truncates_long_command(self) -> None:
        long_cmd = "x" * 200
        result = summarize_action(_block("Bash", command=long_cmd))
        assert result is not None
        assert len(result) <= 90  # "Running: " + 80 chars
        assert result.endswith("\u2026")

    def test_truncates_long_path(self) -> None:
        long_path = "/workspace/" + "a" * 200
        result = summarize_action(_block("Read", file_path=long_path))
        assert result is not None
        assert len(result) <= 89  # "Reading " + 80 chars + ellipsis
        assert result.endswith("\u2026")

    def test_bash_description_preferred_over_command(self) -> None:
        """When both description and command are present, description wins."""
        result = summarize_action(
            _block(
                "Bash",
                command="very long complicated command",
                description="Run tests",
            )
        )
        assert result == "Run tests"
