# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Network logs viewer page."""

import html
import re

from airut.dashboard.tracker import TaskState, TaskStatus
from airut.dashboard.views.styles import network_styles


# Pattern to extract status code from log lines: "allowed GET ... -> 200"
_STATUS_CODE_PATTERN = re.compile(r"-> (\d{3})(?:\s|$)")


def render_network_page(
    task: TaskState,
    log_content: str | None,
    *,
    network_log_offset: int = 0,
) -> str:
    """Render network logs viewer page HTML.

    Args:
        task: Task to display.
        log_content: Raw network log content, or None if unavailable.
        network_log_offset: Current byte offset in the network log file.
            Used as the starting offset for SSE streaming so the
            client only receives lines written after the page rendered.

    Returns:
        HTML string for network logs page.
    """
    escaped_subject = html.escape(task.subject)

    # Build network logs content
    if log_content is None:
        logs_html = '<div class="no-logs">No network logs available</div>'
    elif not log_content.strip():
        logs_html = '<div class="no-logs">Network log is empty</div>'
    else:
        logs_html = render_network_log_lines(log_content)

    is_active = task.status in (TaskStatus.QUEUED, TaskStatus.IN_PROGRESS)
    sse_script = (
        _sse_network_script(task.conversation_id, network_log_offset)
        if is_active
        else ""
    )
    status_notice = (
        '<div id="stream-status" class="stream-status">Connecting...</div>'
        if is_active
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Logs - {task.conversation_id}</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {network_styles()}
    </style>
</head>
<body>
    <div class="header">
        <a href="/conversation/{task.conversation_id}">&larr; Back</a>
        <h1>Network Logs: {task.conversation_id}</h1>
        <span class="subtitle">{escaped_subject}</span>
    </div>
    <div class="terminal" id="logs-container">
        {logs_html}
    </div>
    {status_notice}
    <script>window.scrollTo(0, document.body.scrollHeight);</script>
    {sse_script}
</body>
</html>"""


def _is_error_status(status_code: int) -> bool:
    """Check if status code indicates an error (not 2xx or 3xx)."""
    return status_code < 200 or status_code >= 400


def _extract_status_code(line: str) -> int | None:
    """Extract HTTP status code from a log line."""
    match = _STATUS_CODE_PATTERN.search(line)
    if match:
        return int(match.group(1))
    return None


def _highlight_status_code(escaped_line: str, status_code: int) -> str:
    """Wrap the status code in a highlight span."""
    # Status code is already escaped. The arrow -> becomes -&gt; after escaping.
    code_str = str(status_code)
    return escaped_line.replace(
        f"-&gt; {code_str}", f'-&gt; <span class="highlight">{code_str}</span>'
    )


def _highlight_blocked(escaped_line: str) -> str:
    """Wrap 'BLOCKED' in a highlight span."""
    return escaped_line.replace(
        "BLOCKED", '<span class="highlight">BLOCKED</span>', 1
    )


def _highlight_error_prefix(escaped_line: str) -> str:
    """Wrap 'ERROR' in a highlight span."""
    return escaped_line.replace(
        "ERROR", '<span class="highlight">ERROR</span>', 1
    )


def render_network_log_line(line: str) -> str:
    """Render a single network log line with appropriate styling.

    Args:
        line: Raw log line (must not be empty).

    Returns:
        HTML string for the styled log line.

    Line types and their styling:
        - Task start headers (=== TASK START ...): blue
        - BLOCKED requests: red with dark red background, BLOCKED in bold
        - ERROR lines (upstream failures): red with dark red background,
          ERROR in bold
        - Allowed requests with error status (4xx/5xx): orange with dark orange
          background, status code in bold
        - Allowed requests with success status (2xx/3xx): green
    """
    escaped = html.escape(line)

    if line.startswith("=== TASK START"):
        return f'<div class="log-line task-start">{escaped}</div>'
    elif line.startswith("BLOCKED"):
        highlighted = _highlight_blocked(escaped)
        return f'<div class="log-line blocked">{highlighted}</div>'
    elif line.startswith("ERROR"):
        highlighted = _highlight_error_prefix(escaped)
        return f'<div class="log-line conn-error">{highlighted}</div>'
    elif line.startswith("allowed"):
        status_code = _extract_status_code(line)
        if status_code is not None and _is_error_status(status_code):
            highlighted = _highlight_status_code(escaped, status_code)
            return f'<div class="log-line error">{highlighted}</div>'
        else:
            return f'<div class="log-line allowed">{escaped}</div>'
    else:
        return f'<div class="log-line">{escaped}</div>'


def render_network_log_lines(log_content: str) -> str:
    """Render network log lines with appropriate styling.

    Args:
        log_content: Raw log file content.

    Returns:
        HTML string with styled log lines.
    """
    lines: list[str] = []
    for line in log_content.splitlines():
        if not line:
            continue
        lines.append(render_network_log_line(line))

    return "\n".join(lines)


def _sse_network_script(conversation_id: str, initial_offset: int = 0) -> str:
    """JavaScript for SSE-based live network log streaming.

    Connects to the per-conversation network log stream endpoint and
    appends new lines to the terminal DOM as they arrive.

    Args:
        conversation_id: Conversation ID to stream network logs for.
        initial_offset: Byte offset to start streaming from.
            Set to the current network log file size so the SSE
            only sends lines written after the page rendered.

    Returns:
        HTML <script> tag with SSE network log streaming logic.
    """
    return f"""
    <script>
        var currentOffset = {initial_offset};
        var autoScroll = true;

        window.addEventListener('scroll', function() {{
            var nearBottom = (
                window.innerHeight + window.scrollY
                >= document.body.offsetHeight - 100
            );
            autoScroll = nearBottom;
        }});

        function appendHtml(html) {{
            var container = document.getElementById('logs-container');
            if (html) {{
                container.insertAdjacentHTML('beforeend', html);
            }}
            if (html && autoScroll) {{
                window.scrollTo(0, document.body.scrollHeight);
            }}
        }}

        function connectNetworkSSE() {{
            var url = '/api/conversation/{conversation_id}/network/stream'
                + '?offset=' + currentOffset;
            var source = new EventSource(url);
            var status = document.getElementById('stream-status');

            source.addEventListener('html', function(e) {{
                try {{
                    var data = JSON.parse(e.data);
                    currentOffset = data.offset || currentOffset;
                    appendHtml(data.html);
                    if (status) status.textContent = 'Live';
                }} catch (err) {{ /* ignore parse errors */ }}
            }});

            source.addEventListener('done', function(e) {{
                source.close();
                if (status) status.textContent = 'Complete';
            }});

            source.onerror = function() {{
                source.close();
                if (status) status.textContent = 'Polling (3s)';
                startNetworkPolling();
            }};

            if (status) status.textContent = 'Live';
        }}

        function startNetworkPolling() {{
            var status = document.getElementById('stream-status');
            var timer = setInterval(function() {{
                var url = '/api/conversation/{conversation_id}/network/poll'
                    + '?offset=' + currentOffset;
                fetch(url).then(function(resp) {{
                    if (resp.status === 304) return null;
                    if (resp.status === 200) return resp.json();
                    return null;
                }}).then(function(data) {{
                    if (!data) return;
                    currentOffset = data.offset || currentOffset;
                    appendHtml(data.html);
                    if (data.done) {{
                        clearInterval(timer);
                        if (status) status.textContent = 'Complete';
                    }}
                }}).catch(function() {{ /* ignore fetch errors */ }});
            }}, 3000);
        }}

        connectNetworkSSE();
    </script>"""
