# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the network logs viewer page."""

from werkzeug.test import Client

from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import TaskTracker
from tests.dashboard.conftest import DashboardHarness, result_event


class TestNetworkLogsEndpoint:
    """Tests for the /conversation/<id>/network endpoint."""

    def test_returns_200_with_logs(self, harness: DashboardHarness) -> None:
        """Test network logs page renders with log content."""
        harness.write_log(
            "=== TASK START 2026-02-03T12:34:56Z ===\n"
            "allowed GET https://api.github.com/repos -> 200\n"
            "BLOCKED GET https://evil.com/exfiltrate -> 403\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert "Network Logs: abc12345" in html
        assert "Test Subject" in html
        assert "TASK START" in html
        assert "api.github.com" in html
        assert "evil.com" in html

    def test_not_found(self) -> None:
        """Test network page returns 404 for nonexistent task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/nonexistent/network")
        assert response.status_code == 404

    def test_no_conversation_dir(self) -> None:
        """Test message when conversation dir not found."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)
        assert "No network logs available" in html

    def test_empty_log_file(self, harness: DashboardHarness) -> None:
        """Test message for empty log file."""
        harness.write_log("")

        html = harness.get_html("/conversation/abc12345/network")
        assert "Network log is empty" in html

    def test_missing_log_file(self, harness: DashboardHarness) -> None:
        """Test message when log file doesn't exist."""
        # conv_dir exists but no log file written
        html = harness.get_html("/conversation/abc12345/network")
        assert "No network logs available" in html

    def test_read_error(self, harness: DashboardHarness) -> None:
        """Test graceful handling when log file is a directory."""
        log_path = harness.conv_dir / "network-sandbox.log"
        log_path.mkdir()

        html = harness.get_html("/conversation/abc12345/network")
        assert "No network logs available" in html

    def test_scrolls_to_end(self, harness: DashboardHarness) -> None:
        """Test network logs page scrolls to end by default."""
        harness.write_log("allowed GET https://api.github.com -> 200\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert "window.scrollTo(0, document.body.scrollHeight)" in html

    def test_back_link(self, harness: DashboardHarness) -> None:
        """Test network logs page has back link to task detail."""
        harness.write_log("allowed GET https://api.github.com -> 200\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert 'href="/conversation/abc12345"' in html
        assert "&larr; Back" in html

    def test_detail_page_has_network_link(
        self, harness: DashboardHarness
    ) -> None:
        """Test task detail page links to network logs viewer."""
        harness.add_events(result_event())

        html = harness.get_html("/conversation/abc12345")
        assert "/conversation/abc12345/network" in html
        assert "View Network Logs" in html


class TestNetworkLogLineStyling:
    """Tests for log line classification and CSS styling."""

    def test_blocked_class(self, harness: DashboardHarness) -> None:
        """Test BLOCKED entries have special styling class."""
        harness.write_log(
            "allowed GET https://api.github.com -> 200\n"
            "BLOCKED GET https://evil.com -> 403\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line blocked"' in html
        assert 'class="log-line allowed"' in html

    def test_task_start_class(self, harness: DashboardHarness) -> None:
        """Test TASK START lines have blue styling."""
        harness.write_log("=== TASK START 2026-02-03T12:34:56Z ===\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line task-start"' in html

    def test_error_responses(self, harness: DashboardHarness) -> None:
        """Test error responses (4xx/5xx) have orange styling."""
        harness.write_log(
            "allowed GET https://api.github.com -> 200\n"
            "allowed GET https://api.example.com -> 404\n"
            "allowed POST https://api.example.com/fail -> 500\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line allowed"' in html
        assert html.count('class="log-line error"') == 2

    def test_3xx_not_error(self, harness: DashboardHarness) -> None:
        """Test 3xx responses are treated as success, not error."""
        harness.write_log(
            "allowed GET https://api.example.com -> 301\n"
            "allowed GET https://api.example.com -> 304\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert html.count('class="log-line allowed"') == 2
        assert 'class="log-line error"' not in html

    def test_allowed_without_status_code(
        self, harness: DashboardHarness
    ) -> None:
        """Test allowed lines without status code are rendered as allowed."""
        harness.write_log("allowed GET https://api.example.com\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line allowed"' in html
        assert 'class="log-line error"' not in html

    def test_unknown_format(self, harness: DashboardHarness) -> None:
        """Test unknown log format renders as plain log-line."""
        harness.write_log("some unknown log format\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert "some unknown log format" in html
        assert 'class="log-line">' in html

    def test_skips_empty_lines(self, harness: DashboardHarness) -> None:
        """Test empty lines are skipped in rendering."""
        harness.write_log(
            "allowed GET https://api.github.com -> 200\n"
            "\n"
            "allowed GET https://api.example.com -> 200\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert "api.github.com" in html
        assert "api.example.com" in html
        assert html.count('class="log-line') == 2

    def test_conn_error_lines(self, harness: DashboardHarness) -> None:
        """Test ERROR lines (upstream failures) get conn-error styling."""
        harness.write_log(
            "ERROR GET https://api.example.com/path"
            " -> Connection failed: Name or service not known\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line conn-error"' in html
        assert '<span class="highlight">ERROR</span>' in html


class TestNetworkLogHighlighting:
    """Tests for bold/highlight spans in log lines."""

    def test_bold_error_status_code(self, harness: DashboardHarness) -> None:
        """Test error status codes are bold in error lines."""
        harness.write_log("allowed GET https://api.example.com -> 500\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert '<span class="highlight">500</span>' in html

    def test_bold_blocked(self, harness: DashboardHarness) -> None:
        """Test BLOCKED text is bold in blocked lines."""
        harness.write_log("BLOCKED GET https://evil.com -> 403\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert '<span class="highlight">BLOCKED</span>' in html

    def test_bold_error_prefix(self, harness: DashboardHarness) -> None:
        """Test ERROR prefix is bold in conn-error lines."""
        harness.write_log(
            "ERROR GET https://api.example.com -> Connection failed\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert '<span class="highlight">ERROR</span>' in html

    def test_escapes_html(self, harness: DashboardHarness) -> None:
        """Test HTML in log content is escaped."""
        harness.write_log(
            "allowed GET https://example.com/<script>alert(1)</script> -> 200\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


class TestNetworkLogDNS:
    """Tests for DNS log line rendering."""

    def test_dns_blocked(self, harness: DashboardHarness) -> None:
        """Test DNS BLOCKED lines get blocked styling."""
        harness.write_log(
            "BLOCKED DNS A evil.com -> NXDOMAIN\n"
            "BLOCKED DNS AAAA evil.com -> NOTIMP\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert html.count('class="log-line blocked"') == 2
        assert '<span class="highlight">BLOCKED</span>' in html

    def test_dns_allowed(self, harness: DashboardHarness) -> None:
        """Test DNS allowed lines get allowed (green) styling."""
        harness.write_log("allowed DNS A api.github.com -> 10.199.1.100\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line allowed"' in html
        assert 'class="log-line error"' not in html

    def test_mixed_dns_and_http(self, harness: DashboardHarness) -> None:
        """Test mixed DNS and HTTP log lines render correctly."""
        harness.write_log(
            "=== TASK START 2026-02-03T12:34:56Z ===\n"
            "allowed DNS A api.github.com -> 10.199.1.100\n"
            "BLOCKED DNS A evil.com -> NXDOMAIN\n"
            "allowed GET https://api.github.com/repos -> 200\n"
            "BLOCKED GET https://evil.com/exfiltrate -> 403\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line task-start"' in html
        assert html.count('class="log-line allowed"') == 2
        assert html.count('class="log-line blocked"') == 2

    def test_mixed_with_error_lines(self, harness: DashboardHarness) -> None:
        """Test ERROR lines render correctly alongside other types."""
        harness.write_log(
            "=== TASK START 2026-02-03T12:34:56Z ===\n"
            "allowed DNS A api.github.com -> 10.199.1.100\n"
            "allowed DNS A down.example.com -> 10.199.1.100\n"
            "allowed GET https://api.github.com/repos -> 200\n"
            "ERROR GET https://down.example.com"
            " -> Connection failed: Name or service not known\n"
            "BLOCKED DNS A evil.com -> NXDOMAIN\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert 'class="log-line task-start"' in html
        assert html.count('class="log-line allowed"') == 3
        assert html.count('class="log-line conn-error"') == 1
        assert html.count('class="log-line blocked"') == 1


class TestNetworkLogCSS:
    """Tests for CSS presence in the network logs page."""

    def test_error_css_styling(self, harness: DashboardHarness) -> None:
        """Test error class has orange styling in CSS."""
        harness.write_log("allowed GET https://api.example.com -> 500\n")

        html = harness.get_html("/conversation/abc12345/network")
        assert ".log-line.error" in html
        assert ".highlight" in html

    def test_conn_error_css_styling(self, harness: DashboardHarness) -> None:
        """Test conn-error class has red styling in CSS."""
        harness.write_log(
            "ERROR GET https://api.example.com -> Connection failed\n"
        )

        html = harness.get_html("/conversation/abc12345/network")
        assert ".log-line.conn-error" in html
        assert "#e05f5f" in html
