# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard server module (WSGI application and routing)."""

import json
from unittest.mock import MagicMock, patch

from werkzeug.test import Client

from airut.dashboard.formatters import VersionInfo
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import (
    BootPhase,
    BootState,
    CompletionReason,
    RepoState,
    RepoStatus,
    TaskState,
    TaskStatus,
    TaskTracker,
)
from airut.dashboard.versioned import VersionClock, VersionedStore


class TestDashboardServer:
    """Tests for DashboardServer WSGI application."""

    def test_init(self) -> None:
        """Test server initialization."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, host="0.0.0.0", port=8080)

        assert server.tracker is tracker
        assert server.host == "0.0.0.0"
        assert server.port == 8080

    def test_init_defaults(self) -> None:
        """Test server initialization with defaults."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)

        assert server.host == "127.0.0.1"
        assert server.port == 5200
        assert server.version_info is None

    def test_init_with_version_info(self) -> None:
        """Test server initialization with version info."""
        tracker = TaskTracker()
        version_info = VersionInfo(
            version="v0.7.0",
            git_sha="abc1234",
            git_sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="=== HEAD COMMIT ===\ncommit abc1234",
            started_at=946684800.0,
        )
        server = DashboardServer(tracker, version_info=version_info)

        assert server.version_info is version_info

    def test_health_endpoint(self) -> None:
        """Test /api/health endpoint."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.add_task("t2", "Task 2")
        tracker.set_authenticating("t2")
        tracker.set_executing("t2")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        # When no repos are configured, status is degraded
        assert data["status"] == "degraded"
        assert data["tasks"]["queued"] == 1
        assert data["tasks"]["executing"] == 1
        assert data["tasks"]["completed"] == 0
        assert data["repos"]["live"] == 0
        assert data["repos"]["failed"] == 0
        assert data["repos"]["total"] == 0

    def test_health_endpoint_with_repos(self) -> None:
        """Test /api/health endpoint with repos configured."""
        tracker = TaskTracker()
        repo_states = [
            RepoState(
                repo_id="repo1",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo1",
                channel_info="imap.example.com",
                storage_dir="/storage/repo1",
            ),
            RepoState(
                repo_id="repo2",
                status=RepoStatus.FAILED,
                error_message="Auth failed",
                error_type="IMAPConnectionError",
                git_repo_url="https://github.com/test/repo2",
                channel_info="imap.example.com",
                storage_dir="/storage/repo2",
            ),
        ]

        clock = VersionClock()
        repos_store = VersionedStore(tuple(repo_states), clock)
        server = DashboardServer(tracker, repos_store=repos_store)
        client = Client(server._wsgi_app)

        response = client.get("/api/health")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["status"] == "ok"
        assert data["repos"]["live"] == 1
        assert data["repos"]["failed"] == 1
        assert data["repos"]["total"] == 2

    def test_version_endpoint(self) -> None:
        """Test /api/version endpoint returns structured JSON."""
        tracker = TaskTracker()
        version_info = VersionInfo(
            version="v0.8.0",
            git_sha="abc1234",
            git_sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="...",
            started_at=946684800.0,
        )
        server = DashboardServer(tracker, version_info=version_info)
        client = Client(server._wsgi_app)

        response = client.get("/api/version")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert data["version"] == "v0.8.0"
        assert data["sha_short"] == "abc1234"
        assert data["sha_full"] == "abc1234567890abcdef1234567890abcdef123456"

        # Check cache headers
        assert (
            response.headers.get("Cache-Control")
            == "no-cache, no-store, must-revalidate"
        )
        assert response.headers.get("Pragma") == "no-cache"
        assert response.headers.get("Expires") == "0"

    def test_version_endpoint_no_version_info(self) -> None:
        """Test /api/version endpoint returns 404 when no version info."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/version")
        assert response.status_code == 404
        data = json.loads(response.get_data(as_text=True))
        assert "error" in data

    def test_api_tasks_endpoint(self) -> None:
        """Test /api/conversations endpoint."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversations")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert len(data) == 1
        assert data[0]["conversation_id"] == "abc12345"
        assert data[0]["display_title"] == "Test Subject"
        assert data[0]["status"] == "queued"
        assert isinstance(data[0]["queued_at"], float)

    def test_api_task_endpoint(self) -> None:
        """Test /api/conversation/<id> endpoint."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert data["conversation_id"] == "abc12345"
        assert data["display_title"] == "Test Subject"

    def test_api_task_not_found(self) -> None:
        """Test /api/conversation/<id> returns 404 for unknown task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/nonexistent")
        assert response.status_code == 404
        assert response.content_type == "application/json"

    def test_api_tracker_endpoint(self) -> None:
        """Test /api/tracker endpoint returns full tracker state."""
        tracker = TaskTracker()
        tracker.add_task(
            "t1", "Task One", repo_id="repo-a", sender="alice@test.local"
        )
        tracker.set_authenticating("t1")
        tracker.set_executing("t1")
        tracker.add_task("t2", "Task Two", repo_id="repo-b")
        tracker.set_authenticating("t2")
        tracker.set_executing("t2")
        tracker.complete_task("t2", CompletionReason.SUCCESS)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/tracker")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))

        # Check top-level structure
        assert "version" in data
        assert isinstance(data["version"], int)
        assert "counts" in data
        assert "tasks" in data

        # Check counts
        assert data["counts"]["queued"] == 0
        assert data["counts"]["executing"] == 1
        assert data["counts"]["completed"] == 1

        # Check tasks (sorted newest first by queued_at)
        assert len(data["tasks"]) == 2
        # Find t1 in results
        t1 = next(t for t in data["tasks"] if t["conversation_id"] == "t1")
        assert t1["display_title"] == "Task One"
        assert t1["repo_id"] == "repo-a"
        assert t1["sender"] == "alice@test.local"
        assert t1["status"] == "executing"
        assert t1["started_at"] is not None
        assert t1["model"] is None

    def test_api_tracker_etag(self) -> None:
        """Test /api/tracker supports ETag conditional requests."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        # First request
        response = client.get("/api/tracker")
        assert response.status_code == 200
        etag = response.headers.get("ETag")
        assert etag is not None

        # Second request with matching ETag
        response = client.get("/api/tracker", headers={"If-None-Match": etag})
        assert response.status_code == 304

        # Mutate state
        tracker.add_task("t1", "New Task")

        # Third request with old ETag
        response = client.get("/api/tracker", headers={"If-None-Match": etag})
        assert response.status_code == 200

    def test_api_repos_endpoint(self) -> None:
        """Test /api/repos endpoint."""
        tracker = TaskTracker()
        repo_states = [
            RepoState(
                repo_id="repo1",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo1",
                channel_info="imap.example.com",
                storage_dir="/storage/repo1",
                initialized_at=1000.0,
            ),
            RepoState(
                repo_id="repo2",
                status=RepoStatus.FAILED,
                error_message="Auth failed",
                error_type="IMAPConnectionError",
                git_repo_url="https://github.com/test/repo2",
                channel_info="imap.example.com",
                storage_dir="/storage/repo2",
                initialized_at=1001.0,
            ),
        ]

        clock = VersionClock()
        repos_store = VersionedStore(tuple(repo_states), clock)
        server = DashboardServer(tracker, repos_store=repos_store)
        client = Client(server._wsgi_app)

        response = client.get("/api/repos")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert len(data) == 2

        # Find repo1 in results
        repo1 = next(r for r in data if r["repo_id"] == "repo1")
        assert repo1["status"] == "live"
        assert repo1["git_repo_url"] == "https://github.com/test/repo1"
        assert repo1["error_message"] is None

        # Find repo2 in results
        repo2 = next(r for r in data if r["repo_id"] == "repo2")
        assert repo2["status"] == "failed"
        assert repo2["error_message"] == "Auth failed"
        assert repo2["error_type"] == "IMAPConnectionError"

    def test_repo_detail_endpoint(self) -> None:
        """Test /repo/<id> endpoint."""
        tracker = TaskTracker()
        repo_states = [
            RepoState(
                repo_id="test-repo",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo",
                channel_info="imap.example.com",
                storage_dir="/storage/test-repo",
            ),
        ]

        clock = VersionClock()
        repos_store = VersionedStore(tuple(repo_states), clock)
        server = DashboardServer(tracker, repos_store=repos_store)
        client = Client(server._wsgi_app)

        response = client.get("/repo/test-repo")
        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"

        html = response.get_data(as_text=True)
        assert "test-repo" in html
        assert "LIVE" in html
        assert "github.com/test/repo" in html
        assert "imap.example.com" in html

    def test_repo_detail_failed_repo(self) -> None:
        """Test /repo/<id> shows error details for failed repos."""
        tracker = TaskTracker()
        repo_states = [
            RepoState(
                repo_id="failed-repo",
                status=RepoStatus.FAILED,
                error_message="Connection refused",
                error_type="IMAPConnectionError",
                git_repo_url="https://github.com/test/repo",
                channel_info="imap.example.com",
                storage_dir="/storage/failed-repo",
            ),
        ]

        clock = VersionClock()
        repos_store = VersionedStore(tuple(repo_states), clock)
        server = DashboardServer(tracker, repos_store=repos_store)
        client = Client(server._wsgi_app)

        response = client.get("/repo/failed-repo")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "FAILED" in html
        assert "Connection refused" in html
        assert "IMAPConnectionError" in html

    def test_repo_detail_not_found(self) -> None:
        """Test /repo/<id> returns 404 for unknown repo."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/repo/nonexistent")
        assert response.status_code == 404
        assert "Repository not found" in response.get_data(as_text=True)

    def test_index_shows_repos_section(self) -> None:
        """Test dashboard shows repos section with status."""
        tracker = TaskTracker()
        repo_states = [
            RepoState(
                repo_id="repo1",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo1",
                channel_info="imap.example.com",
                storage_dir="/storage/repo1",
            ),
            RepoState(
                repo_id="repo2",
                status=RepoStatus.FAILED,
                error_message="Auth failed",
                error_type="IMAPConnectionError",
                git_repo_url="https://github.com/test/repo2",
                channel_info="imap.example.com",
                storage_dir="/storage/repo2",
            ),
        ]

        clock = VersionClock()
        repos_store = VersionedStore(tuple(repo_states), clock)
        server = DashboardServer(tracker, repos_store=repos_store)
        client = Client(server._wsgi_app)

        response = client.get("/")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Repositories" in html
        assert "1 live" in html
        assert "1 failed" in html
        assert "repo1" in html
        assert "repo2" in html
        # Check for error type hint on failed repos
        assert "IMAPConnectionError" in html
        # Check for links to repo detail pages
        assert "/repo/repo1" in html
        assert "/repo/repo2" in html

    def test_index_endpoint(self) -> None:
        """Test / (dashboard) endpoint."""
        tracker = TaskTracker()
        tracker.add_task("q1", "Queued Task")
        tracker.add_task("p1", "Executing Task")
        tracker.set_authenticating("p1")
        tracker.set_executing("p1")
        tracker.add_task("c1", "Completed Task")
        tracker.set_authenticating("c1")
        tracker.set_executing("c1")
        tracker.complete_task("c1", CompletionReason.SUCCESS)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"

        html = response.get_data(as_text=True)

        # Check basic structure
        assert "Airut Dashboard" in html
        assert "Pending (1)" in html
        assert "Executing (1)" in html
        assert "Done (1)" in html

        # Check task IDs are present
        assert "q1" in html
        assert "p1" in html
        assert "c1" in html

        # Check SSE connectivity (replaced meta-refresh)
        assert "EventSource" in html
        assert "/api/events/stream" in html

    def test_index_shows_repo_badge_and_sender(self) -> None:
        """Test dashboard renders repo badge and sender for tasks."""
        tracker = TaskTracker()
        tracker.add_task(
            "t1", "Task 1", repo_id="airut", sender="user@example.com"
        )

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        assert "repo-badge" in html
        assert "airut" in html
        assert "task-sender" in html
        assert "user@example.com" in html

    def test_index_with_version_info_clean(self) -> None:
        """Test dashboard shows version info with update check placeholder."""
        tracker = TaskTracker()
        version_info = VersionInfo(
            version="",
            git_sha="abc1234",
            git_sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="=== HEAD COMMIT ===\ncommit abc1234",
            started_at=946684800.0,  # 2000-01-01 00:00:00 UTC
        )
        server = DashboardServer(tracker, version_info=version_info)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Check version info is displayed with link to GitHub commit
        assert "abc1234" in html
        sha_full = "abc1234567890abcdef1234567890abcdef123456"
        expected_url = f"https://github.com/airutorg/airut/commit/{sha_full}"
        assert f'href="{expected_url}"' in html
        # Startup time uses JavaScript for local timezone formatting
        assert 'data-timestamp="946684800.0"' in html
        assert 'class="local-time"' in html

        # Check CSS classes
        assert 'class="version-sha"' in html

        # Check update check placeholder
        assert 'id="update-status"' in html
        assert "checking..." in html

    def test_index_with_version_info_modified(self) -> None:
        """Test dashboard shows version info with update check placeholder."""
        tracker = TaskTracker()
        version_info = VersionInfo(
            version="",
            git_sha="def5678",
            git_sha_full="def5678901234567890abcdef1234567890abcdef",
            full_status="=== HEAD COMMIT ===\ncommit def5678",
            started_at=1000000000.0,  # 2001-09-09 01:46:40 UTC
        )
        server = DashboardServer(tracker, version_info=version_info)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Check version info is displayed
        assert "def5678" in html
        # Startup time uses JavaScript for local timezone formatting
        assert 'data-timestamp="1000000000.0"' in html

        # Check update check placeholder
        assert 'id="update-status"' in html

    def test_index_with_version_tag(self) -> None:
        """Test dashboard shows version tag when available."""
        tracker = TaskTracker()
        version_info = VersionInfo(
            version="v0.7.0",
            git_sha="abc1234",
            git_sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="=== VERSION ===\nv0.7.0 (abc1234)",
            started_at=946684800.0,
        )
        server = DashboardServer(tracker, version_info=version_info)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Version tag should be displayed as the link text
        assert "v0.7.0" in html
        expected_url = "https://github.com/airutorg/airut/releases/tag/v0.7.0"
        assert f'href="{expected_url}"' in html
        assert 'class="version-sha"' in html

    def test_index_with_non_exact_version_tag(self) -> None:
        """Test version links to commit for git describe suffix."""
        tracker = TaskTracker()
        version_info = VersionInfo(
            version="v0.9.0-4-gecb890e",
            git_sha="ecb890e",
            git_sha_full="ecb890e1234567890abcdef1234567890abcdef12",
            full_status="=== VERSION ===\nv0.9.0-4-gecb890e (ecb890e)",
            started_at=946684800.0,
        )
        server = DashboardServer(tracker, version_info=version_info)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Non-exact tag should link to commit, not release
        sha_full = "ecb890e1234567890abcdef1234567890abcdef12"
        expected_url = f"https://github.com/airutorg/airut/commit/{sha_full}"
        assert f'href="{expected_url}"' in html
        # Version label still shown
        assert "v0.9.0-4-gecb890e" in html
        # Should NOT link to release page
        assert "/releases/tag/" not in html

    def test_index_without_version_info(self) -> None:
        """Test dashboard works without version info."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)  # No version_info
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Version info section should not be present
        assert 'class="version-info"' not in html
        assert 'class="version-sha"' not in html

    def test_task_detail_endpoint(self) -> None:
        """Test /conversation/<id> endpoint."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject <script>alert(1)</script>")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"

        html = response.get_data(as_text=True)

        # Check content
        assert "Conversation: abc12345" in html
        assert "Test Subject" in html
        assert "QUEUED" in html
        assert "Back to Dashboard" in html

        # Check HTML escaping (XSS prevention)
        # The user-provided subject should be escaped
        assert "&lt;script&gt;" in html
        # alert(1) from the subject must not appear unescaped
        assert "alert(1)</script>" not in html

    def test_task_detail_not_found(self) -> None:
        """Test /conversation/<id> returns 404 for unknown task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/nonexistent")
        assert response.status_code == 404
        assert "Conversation not found" in response.get_data(as_text=True)

    def test_index_empty_state(self) -> None:
        """Test dashboard with no tasks."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "No conversations" in html

    def test_index_task_states_styling(self) -> None:
        """Test dashboard shows correct styling for task states."""
        tracker = TaskTracker()

        # Queued task
        tracker.add_task("queued", "Queued")

        # In-progress task
        tracker.add_task("progress", "Executing")
        tracker.set_authenticating("progress")
        tracker.set_executing("progress")

        # Successful task
        tracker.add_task("success", "Success")
        tracker.set_authenticating("success")
        tracker.set_executing("success")
        tracker.complete_task("success", CompletionReason.SUCCESS)

        # Failed task
        tracker.add_task("failed", "Failed")
        tracker.set_authenticating("failed")
        tracker.set_executing("failed")
        tracker.complete_task("failed", CompletionReason.EXECUTION_FAILED)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Check status icons
        assert "&#x2713;" in html  # Checkmark for success
        assert "&#x2717;" in html  # X mark for failure

    def test_status_css_covers_all_task_statuses(self) -> None:
        """Every TaskStatus value must have a .status.<value> CSS rule."""
        from airut.dashboard.views.styles import task_detail_styles

        css = task_detail_styles()
        for status in TaskStatus:
            # COMPLETED uses .status.completed.success / .failed
            if status == TaskStatus.COMPLETED:
                assert ".status.completed.success" in css
                assert ".status.completed.failed" in css
            else:
                assert f".status.{status.value}" in css, (
                    f"Missing CSS rule for .status.{status.value}"
                )

    def test_task_card_css_covers_executing_states(self) -> None:
        """Task card and column header CSS must cover dashboard columns."""
        from airut.dashboard.views.styles import dashboard_styles

        css = dashboard_styles()
        # Dashboard groups tasks into pending/executing/completed columns
        # and applies these as CSS classes to task cards and column headers
        for cls in ("pending", "executing"):
            assert f".task.{cls}" in css, f"Missing CSS rule for .task.{cls}"
            assert f".column-header.{cls}" in css, (
                f"Missing CSS rule for .column-header.{cls}"
            )

    def test_task_to_dict(self) -> None:
        """Test _task_to_dict conversion."""
        tracker = TaskTracker()
        task = TaskState(
            conversation_id="abc12345",
            display_title="Test",
            status=TaskStatus.EXECUTING,
            queued_at=1000.0,
            started_at=1030.0,
            message_count=2,
        )

        server = DashboardServer(tracker)

        with patch("airut.dashboard.tracker.time.time", return_value=1090.0):
            result = server._task_to_dict(task)

        assert result["conversation_id"] == "abc12345"
        assert result["display_title"] == "Test"
        assert result["status"] == "executing"
        assert result["queued_at"] == 1000.0
        assert result["started_at"] == 1030.0
        assert result["completed_at"] is None
        assert result["completion_reason"] is None
        assert result["message_count"] == 2
        assert result["queue_duration"] == 30.0
        assert result["execution_duration"] == 60.0
        assert result["total_duration"] == 90.0

    def test_subject_truncation(self) -> None:
        """Test long subjects are truncated in dashboard."""
        tracker = TaskTracker()
        long_subject = "A" * 100  # 100 characters
        tracker.add_task("t1", long_subject)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # Should be truncated to 50 chars + "..."
        assert "A" * 50 + "..." in html

        # Full subject should be in title attribute only
        assert f'title="{long_subject}"' in html

        # Truncated version should appear in the task-subject div
        # (full subject only appears in title attribute)
        assert 'class="task-subject"' in html

    def test_task_detail_executing_status_badge(self) -> None:
        """Test task detail shows styled badge for executing task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Executing")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        assert "EXECUTING" in html
        # The status span must use the "executing" CSS class for styling
        assert 'class="status executing' in html

    def test_task_detail_completed_success(self) -> None:
        """Test task detail page shows success styling for completed task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Success")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Check success styling and text
        assert "COMPLETED" in html
        assert "- Success" in html
        assert "success" in html  # CSS class

    def test_task_detail_completed_failed(self) -> None:
        """Test task detail page shows failed styling for failed task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Failed")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.EXECUTION_FAILED)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Check failed styling and text
        assert "COMPLETED" in html
        assert "- Execution Failed" in html
        assert "failed" in html  # CSS class

    def test_dispatch_error_handling(self) -> None:
        """Test _dispatch handles errors gracefully."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)

        # Patch handler in endpoint dict to raise exception
        def raise_error(*args, **kwargs):
            raise RuntimeError("Test error")

        original = server._endpoint_handlers["index"]
        server._endpoint_handlers["index"] = raise_error
        try:
            client = Client(server._wsgi_app)
            response = client.get("/")

            assert response.status_code == 500
            assert "Internal Server Error" in response.get_data(as_text=True)
        finally:
            server._endpoint_handlers["index"] = original

    def test_unknown_route_returns_404(self) -> None:
        """Test that unknown routes return 404 Not Found."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/nonexistent")
        assert response.status_code == 404
        assert "Not Found" in response.get_data(as_text=True)

        # favicon.ico is not served (we use SVG favicon)
        response = client.get("/favicon.ico")
        assert response.status_code == 404

    def test_favicon_svg_serves_logo(self) -> None:
        """Test that /favicon.svg serves the logo SVG."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/favicon.svg")
        assert response.status_code == 200
        assert response.content_type == "image/svg+xml"
        data = response.get_data(as_text=True)
        assert "<svg" in data
        assert "viewBox" in data

    def test_health_endpoint_boot_state_booting(self) -> None:
        """Test /api/health returns booting status during boot."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.PROXY,
            message="Building proxy image...",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/api/health")
        data = json.loads(response.get_data(as_text=True))
        assert data["status"] == "booting"
        assert data["boot"]["phase"] == "proxy"
        assert data["boot"]["message"] == "Building proxy image..."
        assert "error" not in data["boot"]

    def test_health_endpoint_boot_state_failed(self) -> None:
        """Test /api/health returns error status when boot failed."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.FAILED,
            message="Connection refused",
            error_message="Connection refused",
            error_type="RuntimeError",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/api/health")
        data = json.loads(response.get_data(as_text=True))
        assert data["status"] == "error"
        assert data["boot"]["phase"] == "failed"
        assert data["boot"]["error"] == "Connection refused"

    def test_health_endpoint_boot_state_ready_with_repos(self) -> None:
        """Test /api/health returns ok when boot is ready with live repos."""
        tracker = TaskTracker()
        boot_state = BootState(phase=BootPhase.READY, message="Service ready")
        repo_states = [
            RepoState(
                repo_id="r1",
                status=RepoStatus.LIVE,
                git_repo_url="https://example.com/r1",
                channel_info="imap.example.com",
                storage_dir="/s/r1",
            ),
        ]
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        repos_store = VersionedStore(tuple(repo_states), clock)
        server = DashboardServer(
            tracker, boot_store=boot_store, repos_store=repos_store
        )
        client = Client(server._wsgi_app)

        response = client.get("/api/health")
        data = json.loads(response.get_data(as_text=True))
        assert data["status"] == "ok"

    def test_index_shows_boot_progress_banner(self) -> None:
        """Test dashboard shows boot progress banner during boot."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.REPOS,
            message="Starting repository 'my-repo'...",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        assert "boot-banner" in html
        assert "boot-progress" in html
        assert "Starting repositories..." in html
        assert "Starting repository &#x27;my-repo&#x27;..." in html
        # SSE used for live updates (no meta-refresh)
        assert "EventSource" in html

    def test_index_shows_boot_error_banner(self) -> None:
        """Test dashboard shows error banner when boot failed."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.FAILED,
            message="All repos failed",
            error_message="All repos failed",
            error_type="RuntimeError",
            error_traceback="Traceback:\n  File test.py\nRuntimeError: fail",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        assert "boot-banner" in html
        assert "boot-error" in html
        assert "Boot Failed: RuntimeError" in html
        assert "All repos failed" in html
        assert "boot-traceback" in html
        assert "Traceback:" in html
        # SSE used for live updates (no meta-refresh)
        assert "EventSource" in html

    def test_index_no_boot_banner_when_ready(self) -> None:
        """Test dashboard hides boot banner when boot is complete."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.READY,
            message="Service ready",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        # The boot banner div should not be rendered in the body
        assert '<div class="boot-banner' not in html
        # SSE used for live updates (no meta-refresh)
        assert "EventSource" in html

    def test_index_no_boot_banner_when_no_boot_state(self) -> None:
        """Test dashboard hides boot banner when no boot state provided."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        assert '<div class="boot-banner' not in html

    def test_init_with_boot_state(self) -> None:
        """Test server initialization with boot state."""
        tracker = TaskTracker()
        boot_state = BootState()
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        assert server._handlers._boot_store is not None
        assert (
            server._handlers._boot_store.get().value.phase == BootPhase.STARTING
        )

    def test_boot_error_banner_without_traceback(self) -> None:
        """Test boot error banner without traceback."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.FAILED,
            message="Config error",
            error_message="Config error",
            error_type="ValueError",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        assert "boot-icon" in html  # Error icon rendered
        assert "Boot Failed: ValueError" in html
        # Extract boot container content and verify no traceback
        boot_start = html.index('id="boot-container"')
        boot_end = html.index("</div>", boot_start + 200) + 6
        boot_html = html[boot_start:boot_end]
        assert "boot-traceback" not in boot_html

    def test_boot_progress_starting_phase(self) -> None:
        """Test boot progress banner shows STARTING phase."""
        tracker = TaskTracker()
        boot_state = BootState(
            phase=BootPhase.STARTING,
            message="Initializing...",
        )
        clock = VersionClock()
        boot_store = VersionedStore(boot_state, clock)
        server = DashboardServer(tracker, boot_store=boot_store)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html = response.get_data(as_text=True)

        assert "Initializing..." in html
        assert "boot-spinner" in html

    def test_index_authenticating_task(self) -> None:
        """Test dashboard renders authenticating task with correct label."""
        tracker = TaskTracker()
        tracker.add_task("auth1", "Authenticating Task")
        tracker.set_authenticating("auth1")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html_text = response.get_data(as_text=True)

        # Authenticating tasks appear in the Pending column
        assert "Authenticating..." in html_text
        assert "auth1" in html_text

    def test_index_pending_task(self) -> None:
        """Test dashboard renders pending task with 'Queued behind' label."""
        tracker = TaskTracker()
        tracker.add_task("pend1", "Pending Task")
        tracker.set_authenticating("pend1")
        tracker.set_pending("pend1")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html_text = response.get_data(as_text=True)

        # Pending tasks appear in the Pending column
        assert "Queued behind active task" in html_text
        assert "pend1" in html_text

    def test_index_auth_failed_completion_icon(self) -> None:
        """Test dashboard renders ⊘ icon for AUTH_FAILED completion reason."""
        tracker = TaskTracker()
        tracker.add_task("afail", "Auth Failed Task")
        tracker.set_authenticating("afail")
        tracker.set_executing("afail")
        tracker.complete_task("afail", CompletionReason.AUTH_FAILED)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html_text = response.get_data(as_text=True)

        # AUTH_FAILED uses the ⊘ icon (&#x2298;), not the ✗ icon (&#x2717;)
        assert "&#x2298;" in html_text
        assert "afail" in html_text

    def test_index_unauthorized_completion_icon(self) -> None:
        """Test dashboard renders ⊘ icon for UNAUTHORIZED completion reason."""
        tracker = TaskTracker()
        tracker.add_task("unauth", "Unauthorized Task")
        tracker.set_authenticating("unauth")
        tracker.set_executing("unauth")
        tracker.complete_task("unauth", CompletionReason.UNAUTHORIZED)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html_text = response.get_data(as_text=True)

        assert "&#x2298;" in html_text

    def test_index_rejected_completion_icon(self) -> None:
        """Test dashboard renders ⊘ icon for REJECTED completion reason."""
        tracker = TaskTracker()
        tracker.add_task("rej", "Rejected Task")
        tracker.set_authenticating("rej")
        tracker.set_executing("rej")
        tracker.complete_task("rej", CompletionReason.REJECTED)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/")
        html_text = response.get_data(as_text=True)

        assert "&#x2298;" in html_text

    def test_task_detail_completed_no_reason(self) -> None:
        """Test task detail shows '- Failed' when completion_reason is None."""
        tracker = TaskTracker()
        # Construct a TaskState directly with COMPLETED status but no reason
        task = TaskState(
            conversation_id="noreason",
            display_title="No Reason Task",
            status=TaskStatus.COMPLETED,
            queued_at=1000.0,
            started_at=1010.0,
            completed_at=1020.0,
            completion_reason=None,
        )
        # Inject directly into the tracker's internal dict
        tracker._tasks["noreason"] = task

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/noreason")
        assert response.status_code == 200
        html_text = response.get_data(as_text=True)

        # Should show "- Failed" since completion_reason is None
        assert "- Failed" in html_text
        assert "COMPLETED" in html_text
        assert "failed" in html_text  # CSS class


class TestSSEEndpoint:
    """Tests for SSE streaming endpoint."""

    def test_events_stream_no_clock(self) -> None:
        """Test /api/events/stream returns 503 when no clock configured."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)  # No clock
        client = Client(server._wsgi_app)

        response = client.get("/api/events/stream")
        assert response.status_code == 503
        data = response.get_json()
        assert "error" in data

    def test_events_stream_returns_sse(self) -> None:
        """Test /api/events/stream returns SSE content type."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("t1", "Task 1")

        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/api/events/stream")
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"
        assert response.headers.get("Cache-Control") == "no-cache"
        assert response.headers.get("X-Accel-Buffering") == "no"

    def test_events_stream_last_event_id(self) -> None:
        """Test /api/events/stream uses Last-Event-ID header."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/events/stream",
            headers={"Last-Event-ID": "5"},
        )
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"

    def test_events_stream_last_event_id_invalid(self) -> None:
        """Test /api/events/stream handles invalid Last-Event-ID."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/events/stream",
            headers={"Last-Event-ID": "not-a-number"},
        )
        assert response.status_code == 200

    def test_events_stream_version_param(self) -> None:
        """Test /api/events/stream uses version query parameter."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/api/events/stream?version=3")
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"

    def test_events_stream_invalid_version_param(self) -> None:
        """Test /api/events/stream handles invalid version param."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/api/events/stream?version=abc")
        assert response.status_code == 200

    def test_events_stream_connection_limit(self) -> None:
        """Test /api/events/stream returns 429 when limit reached."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)

        # Exhaust all slots
        for _ in range(8):
            server._sse_manager.try_acquire()

        client = Client(server._wsgi_app)
        response = client.get("/api/events/stream")
        assert response.status_code == 429
        data = response.get_json()
        assert "Too many" in data["error"]
        assert response.headers.get("Retry-After") == "5"

    def test_events_stream_releases_on_close(self) -> None:
        """Test SSE connection releases slot when closed."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)

        assert server._sse_manager.active == 0

        # Make a request (werkzeug test client reads the response)
        client = Client(server._wsgi_app)
        client.get("/api/events/stream")

        # After response is consumed, slot should be released
        assert server._sse_manager.active == 0


class TestETagSupport:
    """Tests for ETag/304 conditional request support."""

    def test_api_tasks_etag_header(self) -> None:
        """Test /api/conversations returns ETag header."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversations")
        assert response.status_code == 200
        etag = response.headers.get("ETag")
        assert etag is not None
        assert etag.startswith('"v')
        assert response.headers.get("Cache-Control") == "no-cache"

    def test_api_tasks_304_on_match(self) -> None:
        """Test /api/conversations returns 304 when ETag matches."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        # First request to get ETag
        response = client.get("/api/conversations")
        etag = response.headers.get("ETag")

        # Second request with matching ETag
        response = client.get(
            "/api/conversations",
            headers={"If-None-Match": etag},
        )
        assert response.status_code == 304

    def test_api_tasks_200_on_mismatch(self) -> None:
        """Test /api/conversations returns 200 when ETag doesn't match."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversations",
            headers={"If-None-Match": '"v999"'},
        )
        assert response.status_code == 200

    def test_api_repos_etag(self) -> None:
        """Test /api/repos returns ETag and supports 304."""
        clock = VersionClock()
        repos_store: VersionedStore[tuple[RepoState, ...]] = VersionedStore(
            (), clock
        )
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock, repos_store=repos_store)
        client = Client(server._wsgi_app)

        response = client.get("/api/repos")
        assert response.status_code == 200
        etag = response.headers.get("ETag")
        assert etag is not None

        # 304 on match
        response = client.get("/api/repos", headers={"If-None-Match": etag})
        assert response.status_code == 304

    def test_health_etag(self) -> None:
        """Test /api/health returns ETag and supports 304."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/api/health")
        assert response.status_code == 200
        etag = response.headers.get("ETag")
        assert etag is not None

        # 304 on match
        response = client.get("/api/health", headers={"If-None-Match": etag})
        assert response.status_code == 304

    def test_etag_changes_after_state_update(self) -> None:
        """Test ETag changes when state is updated."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        server = DashboardServer(tracker, clock=clock)
        client = Client(server._wsgi_app)

        # Get initial ETag
        response1 = client.get("/api/conversations")
        etag1 = response1.headers.get("ETag")

        # Update state
        tracker.add_task("t1", "New Task")

        # Get new ETag
        response2 = client.get("/api/conversations")
        etag2 = response2.headers.get("ETag")

        assert etag1 != etag2


class TestDashboardServerStartStop:
    """Tests for server start/stop functionality."""

    def test_start_creates_server_and_thread(self) -> None:
        """Test that start() creates server and spawns thread."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, host="127.0.0.1", port=5200)

        # Mock make_server to avoid actual socket usage
        mock_wsgi_server = MagicMock()
        with patch(
            "airut.dashboard.server.make_server",
            return_value=mock_wsgi_server,
        ):
            server.start()

            # Server should be created
            assert server._server is mock_wsgi_server

            # Thread should be created
            assert server._thread is not None
            assert server._thread.daemon is True
            assert server._thread.name == "DashboardServer"

    def test_stop_calls_shutdown(self) -> None:
        """Test that stop() calls server.shutdown()."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, host="127.0.0.1", port=5200)

        # Set up mocked server
        mock_wsgi_server = MagicMock()
        server._server = mock_wsgi_server

        server.stop()

        mock_wsgi_server.shutdown.assert_called_once()

    def test_stop_without_server(self) -> None:
        """Test that stop() handles case where server wasn't started."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)

        # Should not raise
        server.stop()


class TestUpdateEndpoint:
    """Tests for /update endpoint."""

    @patch("airut.dashboard.handlers.check_upstream_version")
    def test_update_available(self, mock_check: MagicMock) -> None:
        """Test /api/update endpoint when update is available."""
        from airut.version import GitVersionInfo, UpstreamVersion

        git_info = GitVersionInfo(
            version="v0.8.0",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="...",
        )
        mock_check.return_value = UpstreamVersion(
            source="pypi",
            latest="0.9.0",
            current="0.8.0",
            update_available=True,
        )

        tracker = TaskTracker()
        server = DashboardServer(tracker, git_version_info=git_info)
        client = Client(server._wsgi_app)

        response = client.get("/api/update")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert data["current"] == "v0.8.0"
        assert data["latest"] == "0.9.0"
        assert data["update_available"] is True
        assert data["source"] == "pypi"
        assert data["release_url"] == (
            "https://github.com/airutorg/airut/releases/tag/v0.9.0"
        )

    @patch("airut.dashboard.handlers.check_upstream_version")
    def test_up_to_date(self, mock_check: MagicMock) -> None:
        """Test /api/update endpoint when up to date."""
        from airut.version import GitVersionInfo, UpstreamVersion

        git_info = GitVersionInfo(
            version="v0.8.0",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="...",
        )
        mock_check.return_value = UpstreamVersion(
            source="pypi",
            latest="0.8.0",
            current="0.8.0",
            update_available=False,
        )

        tracker = TaskTracker()
        server = DashboardServer(tracker, git_version_info=git_info)
        client = Client(server._wsgi_app)

        response = client.get("/api/update")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["current"] == "v0.8.0"
        assert data["latest"] == "0.8.0"
        assert data["update_available"] is False
        assert data["release_url"] is None

    @patch("airut.dashboard.handlers.check_upstream_version")
    def test_upstream_check_not_applicable(self, mock_check: MagicMock) -> None:
        """Test /api/update when upstream check returns None."""
        from airut.version import GitVersionInfo

        git_info = GitVersionInfo(
            version="v0.8.0",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="...",
        )
        mock_check.return_value = None

        tracker = TaskTracker()
        server = DashboardServer(tracker, git_version_info=git_info)
        client = Client(server._wsgi_app)

        response = client.get("/api/update")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["current"] == "v0.8.0"
        assert data["latest"] is None
        assert data["update_available"] is False
        assert data["release_url"] is None

    def test_no_version_info(self) -> None:
        """Test /api/update returns 404 when no version info."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/update")
        assert response.status_code == 404

    @patch("airut.dashboard.handlers.check_upstream_version")
    def test_current_falls_back_to_sha(self, mock_check: MagicMock) -> None:
        """Test /api/update uses sha_short when version is empty."""
        from airut.version import GitVersionInfo

        git_info = GitVersionInfo(
            version="",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="...",
        )
        mock_check.return_value = None

        tracker = TaskTracker()
        server = DashboardServer(tracker, git_version_info=git_info)
        client = Client(server._wsgi_app)

        response = client.get("/api/update")
        data = json.loads(response.get_data(as_text=True))
        assert data["current"] == "abc1234"

    @patch("airut.dashboard.handlers.check_upstream_version")
    def test_release_url_github_source(self, mock_check: MagicMock) -> None:
        """Test /api/update returns commit URL for GitHub source updates."""
        from airut.version import GitVersionInfo, UpstreamVersion

        git_info = GitVersionInfo(
            version="",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="...",
        )
        new_sha = "b" * 40
        mock_check.return_value = UpstreamVersion(
            source="github",
            latest=new_sha,
            current="abc1234567890abcdef1234567890abcdef123456",
            update_available=True,
        )

        tracker = TaskTracker()
        server = DashboardServer(tracker, git_version_info=git_info)
        client = Client(server._wsgi_app)

        response = client.get("/api/update")
        data = json.loads(response.get_data(as_text=True))
        assert data["update_available"] is True
        assert data["release_url"] == (
            f"https://github.com/airutorg/airut/commit/{new_sha}"
        )
