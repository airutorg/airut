# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared CSS stylesheets for dashboard views.

Provides CSS generation functions for the light-theme pages (dashboard,
task detail, repo detail) and the dark-theme pages (actions viewer,
network logs viewer). Each page composes its stylesheet from shared
base styles plus page-specific rules.

Light-theme pages automatically switch to dark mode via
``@media (prefers-color-scheme: dark)`` to respect the OS preference.
"""


def _light_base() -> str:
    """Base CSS rules shared across all light-theme pages.

    Includes reset, body font/background, link styles, card styles,
    field styles, and the refresh-notice footer.

    Returns:
        CSS string (without <style> tags).
    """
    return """\
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #f5f5f5;
            color: #333;
        }
        .page {
            padding: 20px;
        }
        a { color: #337ab7; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .card {
            background: white;
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 16px;
        }
        .field {
            margin-bottom: 16px;
        }
        .field-label {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #666;
            margin-bottom: 4px;
        }
        .field-value {
            font-size: 14px;
        }
        .field-value.mono {
            font-family: "SF Mono", Consolas, monospace;
        }
        .refresh-notice {
            font-size: 12px;
            color: #999;
            margin-top: 20px;
        }
        .stream-status {
            position: fixed;
            bottom: 12px;
            right: 16px;
            font-size: 11px;
            color: #999;
            background: rgba(255,255,255,0.9);
            padding: 4px 10px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }"""


def _dark_mode_overrides() -> str:
    """``prefers-color-scheme: dark`` overrides for light-theme pages.

    Provides dark equivalents for every colour used across the light
    base, logo, version-info, boot-state, repos, task-card, task-detail,
    repo-detail, and conversation-detail styles.

    Returns:
        CSS string wrapped in a ``@media`` query.
    """
    return """\
        @media (prefers-color-scheme: dark) {
            body {
                background: #1a1a1a;
                color: #d4d4d4;
            }
            a { color: #6db3f2; }
            .card {
                background: #252526;
                box-shadow: 0 1px 3px rgba(0,0,0,0.4);
            }
            .field-label { color: #999; }
            .refresh-notice { color: #777; }
            .stream-status {
                background: rgba(37,37,38,0.95);
                color: #888;
                box-shadow: 0 1px 3px rgba(0,0,0,0.4);
            }

            /* Version info */
            .version-info { color: #999; }
            .version-sha {
                background: #333;
                color: #6db3f2;
            }
            .version-sha:hover { background: #3a3a3a; }
            .version-status.up-to-date {
                background: #1e3a1e;
                color: #73c991;
            }
            .version-status.update-available {
                background: #3a3520;
                color: #dca35a;
            }
            .version-status.checking,
            .version-status.check-failed {
                background: #333;
                color: #888;
            }
            .version-started { color: #888; }

            /* Boot state */
            .boot-banner {
                box-shadow: 0 1px 3px rgba(0,0,0,0.4);
            }
            .boot-progress {
                background: #1a2a3a;
                border-left-color: #5bc0de;
            }
            .boot-error {
                background: #3c1f1f;
                border-left-color: #d9534f;
            }
            .boot-error .boot-title { color: #f48771; }
            .boot-progress .boot-title { color: #6db3f2; }
            .boot-message { color: #aaa; }
            .boot-traceback {
                background: #1e1e1e;
                border-color: #5a2a2a;
                color: #f48771;
            }

            /* Repos section */
            .repos-header { color: #999; }
            .repo-card {
                background: #252526;
                box-shadow: 0 1px 3px rgba(0,0,0,0.4);
            }
            .repo-name { color: #d4d4d4; }

            /* Task cards / dashboard columns */
            .column {
                background: #252526;
                box-shadow: 0 1px 3px rgba(0,0,0,0.4);
            }
            .column-header { border-bottom-color: #444; }
            .task {
                background: #1e1e1e;
                border-left-color: #555;
            }
            .task-id { color: #999; }
            .task-id a { color: #6db3f2; }
            .task-time { color: #888; }
            .task-sender { color: #888; }
            .task-subject { color: #d4d4d4; }
            .repo-badge {
                background: #333;
                color: #aaa;
            }
            .conv-badge {
                background: #333;
                color: #999;
            }
            .conv-badge:hover { background: #3a3a3a; }
            .empty { color: #777; }

            /* Task detail page */
            h2 { color: #ccc; }
            .summary-item { background: #1e1e1e; }
            .summary-value { color: #d4d4d4; }
            .summary-label { color: #999; }
            .reply {
                background: #1e1e1e;
            }
            .reply-number { color: #d4d4d4; }
            .reply-timestamp { color: #999; }
            .reply-stat-label { color: #888; }
            .reply-stat-value { color: #d4d4d4; }
            .usage-grid { border-top-color: #444; }
            .usage-label { color: #888; }
            .usage-value { color: #aaa; }
            .text-section { border-top-color: #444; }
            .text-section-header { color: #999; }
            .text-content {
                background: #1a1a1a;
                border-color: #444;
                color: #d4d4d4;
            }
            .action-btn.primary {
                background: #2a6496;
            }
            .action-btn.primary:hover {
                background: #1e4e78;
            }
            .stop-result.info {
                background: #1a2a3a;
                color: #6db3f2;
            }
            .stop-result.error {
                background: #3c1f1f;
                color: #f48771;
            }
            .no-conversation { color: #777; }
            .detail-item { background: #1e1e1e; }
            .details-grid .field-label { color: #999; }
            .todo-item.completed { color: #73c991; }
            .todo-item.in-progress {
                color: #6db3f2;
                background: #1a2a3a;
            }
            .todo-item.pending { color: #777; }
            .todo-icon.completed { color: #73c991; }
            .todo-icon.pending { color: #555; }
            .todo-spinner {
                border-color: #5bc0de;
                border-top-color: transparent;
            }
            .reply-list { border-top-color: #444; }

            /* Status badges */
            .status.queued,
            .status.authenticating,
            .status.pending {
                background: #3a3520;
                color: #dca35a;
            }
            .status.executing {
                background: #1a2a3a;
                color: #6db3f2;
            }
            .status.completed.success {
                background: #1e3a1e;
                color: #73c991;
            }
            .status.completed.failed {
                background: #3c1f1f;
                color: #f48771;
            }

            /* Repo detail page */
            .back-link a { color: #6db3f2; }
            .status-badge.live {
                background: #1e3a1e;
                color: #73c991;
            }
            .status-badge.failed {
                background: #3c1f1f;
                color: #f48771;
            }
            .detail-card {
                background: #252526;
                box-shadow: 0 1px 3px rgba(0,0,0,0.4);
            }
            .detail-label { color: #999; }
            .detail-value { color: #d4d4d4; }
            .detail-value.mono {
                background: #1e1e1e;
            }
            .error-section {
                background: #2a1515;
                border-left-color: #d9534f;
            }
            .error-type { color: #f48771; }
            .error-message {
                background: #1e1e1e;
                color: #d4d4d4;
            }

            /* Conversation detail inline styles */
            .task-row {
                background: #1e1e1e;
                border-left-color: #555;
            }
            .task-row-id a { color: #6db3f2; }
            .task-row-time { color: #888; }

            /* Column headers preserve their semantic colors in dark mode */
            .column-header.queued,
            .column-header.pending { border-color: #b8860b; color: #dca35a; }
            .column-header.executing { border-color: #3a8db5; color: #6db3f2; }
            .column-header.completed { border-color: #4a8c4a; color: #73c991; }
        }"""


def _logo_styles() -> str:
    """CSS for the title row and inline SVG logo.

    Returns:
        CSS string.
    """
    return """\
        .title-row {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }
        .title-row h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }
        .logo {
            height: 1.2em;
            width: auto;
        }"""


def _version_info_styles() -> str:
    """CSS for the version-info bar below the title.

    Returns:
        CSS string.
    """
    return """\
        .version-info {
            font-size: 12px;
            color: #666;
            margin-bottom: 20px;
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .version-sha {
            font-family: "SF Mono", Consolas, monospace;
            background: #eee;
            padding: 2px 6px;
            border-radius: 3px;
            color: #337ab7;
            text-decoration: none;
        }
        .version-sha:hover {
            text-decoration: underline;
            background: #e0e0e0;
        }
        .version-status {
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: 500;
            cursor: default;
        }
        .version-status.up-to-date {
            background: #dff0d8;
            color: #3c763d;
        }
        .version-status.update-available {
            background: #fcf8e3;
            color: #8a6d3b;
        }
        .version-status.checking {
            background: #eee;
            color: #888;
        }
        .version-status.check-failed {
            background: #eee;
            color: #888;
        }
        .version-started {
            color: #888;
        }"""


def _boot_state_styles() -> str:
    """CSS for the boot-state banner (progress and error).

    Returns:
        CSS string.
    """
    return """\
        .boot-banner {
            max-width: 1400px;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .boot-progress {
            background: #d9edf7;
            border-left: 4px solid #5bc0de;
        }
        .boot-error {
            background: #f2dede;
            border-left: 4px solid #d9534f;
        }
        .boot-icon {
            font-size: 20px;
            color: #d9534f;
            flex-shrink: 0;
        }
        .boot-spinner {
            width: 20px;
            height: 20px;
            border: 3px solid #5bc0de;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            flex-shrink: 0;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .boot-content {
            flex: 1;
            min-width: 0;
        }
        .boot-title {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 4px;
        }
        .boot-error .boot-title {
            color: #a94442;
        }
        .boot-progress .boot-title {
            color: #31708f;
        }
        .boot-message {
            font-size: 13px;
            color: #555;
        }
        .boot-traceback {
            margin-top: 8px;
            padding: 12px;
            background: #fff;
            border: 1px solid #ebccd1;
            border-radius: 4px;
            font-family: "SF Mono", Consolas, monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 400px;
            overflow-y: auto;
            color: #a94442;
        }"""


def _repos_section_styles() -> str:
    """CSS for the repositories grid on the dashboard.

    Returns:
        CSS string.
    """
    return """\
        .repos-section {
            margin-bottom: 24px;
            max-width: 1400px;
        }
        .repos-header {
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            color: #666;
        }
        .repos-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }
        .repo-card {
            background: white;
            border-radius: 6px;
            padding: 12px 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 200px;
        }
        .repo-card a {
            text-decoration: none;
            color: inherit;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .repo-card a:hover {
            text-decoration: underline;
        }
        .repo-status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .repo-status-indicator.live {
            background: #5cb85c;
        }
        .repo-status-indicator.failed {
            background: #d9534f;
        }
        .repo-name {
            font-weight: 500;
            font-size: 14px;
        }
        .repo-error-hint {
            font-size: 12px;
            color: #d9534f;
            margin-left: auto;
        }"""


def _task_card_styles() -> str:
    """CSS for task cards and the three-column dashboard grid.

    Returns:
        CSS string.
    """
    return """\
        .dashboard {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            max-width: 1400px;
        }
        @media (max-width: 900px) {
            .dashboard { grid-template-columns: 1fr; }
        }
        .column {
            background: white;
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .column-header {
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 2px solid #eee;
        }
        .column-header.queued { border-color: #f0ad4e; color: #8a6d3b; }
        .column-header.pending { border-color: #f0ad4e; color: #8a6d3b; }
        .column-header.executing { border-color: #5bc0de; color: #31708f; }
        .column-header.completed { border-color: #5cb85c; color: #3c763d; }
        .task {
            padding: 12px;
            margin-bottom: 8px;
            background: #fafafa;
            border-radius: 4px;
            border-left: 3px solid #ddd;
        }
        .task.queued { border-left-color: #f0ad4e; }
        .task.pending { border-left-color: #f0ad4e; }
        .task.executing { border-left-color: #5bc0de; }
        .task.completed.success { border-left-color: #5cb85c; }
        .task.completed.failed { border-left-color: #d9534f; }
        .task-id {
            font-family: "SF Mono", Consolas, monospace;
            font-size: 12px;
            color: #666;
            margin-bottom: 4px;
        }
        .task-id a {
            color: #337ab7;
            text-decoration: none;
        }
        .task-id a:hover { text-decoration: underline; }
        .task-subject {
            font-size: 14px;
            margin-bottom: 4px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .task-time {
            font-size: 12px;
            color: #888;
        }
        .task-sender {
            font-size: 12px;
            color: #888;
        }
        .repo-badge {
            display: inline-block;
            background: #e8e8e8;
            color: #555;
            font-size: 11px;
            padding: 1px 6px;
            border-radius: 3px;
            margin-left: 4px;
            vertical-align: middle;
        }
        .status-icon {
            font-size: 14px;
            margin-left: 4px;
        }
        .conv-badge {
            display: inline-block;
            background: #f0f0f0;
            color: #666;
            font-size: 10px;
            padding: 1px 5px;
            border-radius: 3px;
            margin-left: 4px;
            vertical-align: middle;
            text-decoration: none;
        }
        .conv-badge:hover {
            background: #e0e0e0;
            text-decoration: none;
        }
        .empty {
            color: #999;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }"""


def dashboard_styles() -> str:
    """Complete CSS for the main dashboard page.

    Returns:
        CSS string (without <style> tags).
    """
    return "\n".join(
        [
            _light_base(),
            _logo_styles(),
            _version_info_styles(),
            _boot_state_styles(),
            _repos_section_styles(),
            _task_card_styles(),
            _dark_mode_overrides(),
        ]
    )


def _task_detail_specific() -> str:
    """CSS specific to the task detail page.

    Returns:
        CSS string.
    """
    return """\
        .page {
            max-width: 900px;
        }
        .back { margin-bottom: 20px; }
        h1 {
            margin: 0 0 20px 0;
            font-size: 20px;
            font-weight: 600;
            font-family: "SF Mono", Consolas, monospace;
        }
        h2 {
            margin: 0 0 16px 0;
            font-size: 16px;
            font-weight: 600;
            color: #444;
        }
        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .status.queued { background: #fcf8e3; color: #8a6d3b; }
        .status.authenticating { background: #fcf8e3; color: #8a6d3b; }
        .status.pending { background: #fcf8e3; color: #8a6d3b; }
        .status.executing { background: #d9edf7; color: #31708f; }
        .status.completed.success { background: #dff0d8; color: #3c763d; }
        .status.completed.failed { background: #f2dede; color: #a94442; }
        .conversation-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .summary-item {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            text-align: center;
        }
        .summary-value {
            font-size: 24px;
            font-weight: 600;
            color: #333;
            font-family: "SF Mono", Consolas, monospace;
        }
        .summary-label {
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }
        .reply-list {
            border-top: 1px solid #eee;
            padding-top: 16px;
        }
        .reply {
            background: #f8f9fa;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
            border-left: 3px solid #5bc0de;
        }
        .reply.error {
            border-left-color: #d9534f;
        }
        .reply-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }
        .reply-number {
            font-weight: 600;
            color: #333;
        }
        .reply-timestamp {
            font-size: 12px;
            color: #666;
            font-family: "SF Mono", Consolas, monospace;
        }
        .reply-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 12px;
            font-size: 13px;
        }
        .reply-stat {
            display: flex;
            flex-direction: column;
        }
        .reply-stat-label {
            font-size: 10px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        .reply-stat-value {
            font-family: "SF Mono", Consolas, monospace;
            color: #333;
        }
        .usage-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 8px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e0e0e0;
        }
        .usage-item {
            font-size: 12px;
        }
        .usage-label {
            color: #888;
            font-size: 10px;
        }
        .usage-value {
            font-family: "SF Mono", Consolas, monospace;
            color: #555;
        }
        .json-link {
            font-size: 12px;
            margin-top: 12px;
        }
        .action-buttons {
            display: flex;
            gap: 8px;
            margin-top: 16px;
        }
        .action-btn {
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-family: inherit;
            text-decoration: none;
            display: inline-block;
            box-sizing: border-box;
            line-height: 1.2;
        }
        .action-btn.primary {
            background: #337ab7;
        }
        .action-btn.primary:hover {
            background: #286090;
        }
        .stop-btn {
            background: #d9534f;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-family: inherit;
            box-sizing: border-box;
            line-height: 1.2;
        }
        .stop-btn:hover {
            background: #c9302c;
        }
        .stop-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .stop-result:empty {
            display: none;
        }
        .stop-result {
            margin-top: 12px;
            padding: 12px;
            border-radius: 4px;
            font-size: 14px;
        }
        .stop-result.info {
            background: #d9edf7;
            color: #31708f;
        }
        .stop-result.error {
            background: #f2dede;
            color: #a94442;
        }
        .no-conversation {
            color: #888;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
        }
        .detail-item {
            background: #f8f9fa;
            padding: 10px 12px;
            border-radius: 6px;
        }
        .progress-card h2 {
            margin: 0 0 12px 0;
        }
        .todo-list {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .todo-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 6px 8px;
            border-radius: 4px;
            font-size: 14px;
        }
        .todo-item.completed {
            color: #3c763d;
        }
        .todo-item.in-progress {
            color: #31708f;
            background: #d9edf7;
        }
        .todo-item.pending {
            color: #888;
        }
        .todo-icon {
            font-size: 14px;
            width: 16px;
            text-align: center;
            flex-shrink: 0;
        }
        .todo-icon.completed {
            color: #5cb85c;
        }
        .todo-icon.pending {
            color: #ccc;
        }
        .todo-spinner {
            width: 14px;
            height: 14px;
            border: 2px solid #5bc0de;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            flex-shrink: 0;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .todo-label {
            line-height: 1.3;
        }
        .text-section {
            margin-top: 12px;
            border-top: 1px solid #e0e0e0;
            padding-top: 12px;
        }
        .text-section-header {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            color: #666;
            margin-bottom: 8px;
        }
        .text-content {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 12px;
            font-family: "SF Mono", Consolas, monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 300px;
            overflow-y: auto;
            color: #333;
        }
        .text-content.request {
            border-left: 3px solid #5bc0de;
        }
        .text-content.response {
            border-left: 3px solid #5cb85c;
        }"""


def task_detail_styles() -> str:
    """Complete CSS for the task detail page.

    Returns:
        CSS string (without <style> tags).
    """
    return "\n".join(
        [
            _light_base(),
            _task_detail_specific(),
            _dark_mode_overrides(),
        ]
    )


def _repo_detail_specific() -> str:
    """CSS specific to the repo detail page.

    Returns:
        CSS string.
    """
    return """\
        .back-link {
            font-size: 14px;
            margin-bottom: 16px;
        }
        .back-link a { color: #337ab7; text-decoration: none; }
        .back-link a:hover { text-decoration: underline; }
        .repo-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
        }
        .repo-header h1 {
            margin: 0;
            font-size: 24px;
        }
        .status-badge {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status-badge.live {
            background: #dff0d8;
            color: #3c763d;
        }
        .status-badge.failed {
            background: #f2dede;
            color: #a94442;
        }
        .detail-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            max-width: 800px;
        }
        .detail-section {
            margin-bottom: 20px;
        }
        .detail-section:last-child {
            margin-bottom: 0;
        }
        .detail-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }
        .detail-value {
            font-size: 14px;
            word-break: break-all;
            margin-bottom: 12px;
        }
        .detail-value:last-child {
            margin-bottom: 0;
        }
        .detail-value.mono {
            font-family: "SF Mono", Consolas, monospace;
            background: #f5f5f5;
            padding: 8px;
            border-radius: 4px;
        }
        .error-section {
            background: #fdf2f2;
            border-left: 3px solid #d9534f;
            padding: 16px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .error-type {
            font-family: "SF Mono", Consolas, monospace;
            color: #a94442;
            font-weight: 600;
        }
        .error-message {
            font-family: "SF Mono", Consolas, monospace;
            white-space: pre-wrap;
            background: #fff;
            padding: 8px;
            border-radius: 4px;
        }"""


def repo_detail_styles() -> str:
    """Complete CSS for the repo detail page.

    Returns:
        CSS string (without <style> tags).
    """
    return "\n".join(
        [
            _light_base(),
            _repo_detail_specific(),
            _dark_mode_overrides(),
        ]
    )


def _dark_base() -> str:
    """Base CSS for dark-themed terminal pages (actions, network).

    Returns:
        CSS string.
    """
    return """\
        * { box-sizing: border-box; }
        body {
            font-family: "SF Mono", Consolas, "Liberation Mono", Menlo,
                         monospace;
            margin: 0;
            padding: 0;
            background: #1e1e1e;
            color: #d4d4d4;
            font-size: 13px;
            line-height: 1.5;
        }
        a { color: #569cd6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .header {
            background: #252526;
            padding: 12px 20px;
            border-bottom: 1px solid #333;
            position: sticky;
            top: 0;
            z-index: 10;
            display: flex;
            align-items: center;
            gap: 16px;
        }
        h1 {
            margin: 0;
            font-size: 14px;
            font-weight: 600;
            color: #e0e0e0;
        }
        .subtitle {
            color: #888;
            font-size: 12px;
        }
        .terminal {
            padding: 12px 20px 40px 20px;
        }
        .stream-status {
            position: fixed;
            bottom: 12px;
            right: 16px;
            font-size: 11px;
            color: #888;
            background: rgba(37,37,38,0.9);
            padding: 4px 10px;
            border-radius: 4px;
        }"""


def _actions_specific() -> str:
    """CSS specific to the actions viewer page.

    Returns:
        CSS string.
    """
    return """\
        .reply-section {
            margin-bottom: 16px;
        }
        .reply-header {
            color: #569cd6;
            font-weight: 600;
            padding: 8px 0 4px 0;
            border-bottom: 1px solid #333;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .reply-timestamp {
            font-size: 11px;
            color: #666;
        }
        .event {
            margin-bottom: 2px;
            padding: 2px 0;
        }
        .event.error {
            background: #3c1f1f;
            border-left: 2px solid #d9534f;
            padding-left: 8px;
        }
        .ev-system {
            color: #666;
            font-size: 12px;
            padding: 2px 0;
        }
        .ev-text {
            color: #b5cea8;
            padding: 4px 0;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .ev-tool-use {
            padding: 4px 0;
        }
        .tool-name {
            color: #dcdcaa;
            font-weight: 600;
        }
        .tool-desc {
            color: #808080;
            margin-left: 8px;
        }
        .tool-input-json {
            color: #808080;
            padding: 2px 0 2px 16px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 400px;
            overflow-y: auto;
        }
        .bash-cmd {
            color: #ce9178;
            padding: 2px 0 2px 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .tool-detail {
            color: #9cdcfe;
            padding: 2px 0 2px 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .diff-removed {
            color: #c97070;
            padding: 0 0 0 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .diff-added {
            color: #73c991;
            padding: 0 0 0 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .tool-detail-dim {
            color: #666;
            padding: 0 0 0 16px;
            font-size: 12px;
        }
        .ev-tool-result {
            padding: 2px 0 2px 16px;
            color: #808080;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .ev-tool-result.error {
            color: #f48771;
            background: #3c1f1f;
            padding: 4px 8px 4px 16px;
        }
        .ev-tool-result-label {
            color: #666;
            font-size: 11px;
        }
        .ev-result {
            color: #569cd6;
            padding: 4px 0;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .ev-raw {
            color: #808080;
            padding: 4px 0;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .ev-request {
            color: #c586c0;
            padding: 4px 0;
            white-space: pre-wrap;
            word-break: break-word;
            border-left: 2px solid #c586c0;
            padding-left: 8px;
            margin-bottom: 4px;
        }
        .ev-request-label {
            color: #888;
            font-size: 11px;
            font-weight: 600;
        }
        .no-actions {
            color: #888;
            font-style: italic;
            padding: 40px;
            text-align: center;
        }
        /* collapsible raw JSON blocks */
        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            padding: 2px 0;
        }
        .event-type {
            font-weight: 600;
            font-size: 12px;
        }
        .event-meta {
            font-size: 11px;
            color: #666;
        }
        .event-body {
            display: none;
        }
        .event-body.expanded {
            display: block;
        }
        .toggle-icon {
            font-size: 12px;
            color: #666;
        }"""


def actions_styles() -> str:
    """Complete CSS for the actions viewer page.

    Returns:
        CSS string (without <style> tags).
    """
    return "\n".join(
        [
            _dark_base(),
            _actions_specific(),
        ]
    )


def _network_specific() -> str:
    """CSS specific to the network logs viewer page.

    Returns:
        CSS string.
    """
    return """\
        .log-line {
            padding: 2px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .log-line.allowed {
            color: #73c991;
        }
        .log-line.error {
            color: #e09c5f;
        }
        .log-line.conn-error {
            color: #e05f5f;
        }
        .log-line.blocked {
            color: #f48771;
            background: #3c1f1f;
            padding: 2px 8px;
            margin: 0 -8px;
        }
        .log-line.task-start {
            color: #569cd6;
        }
        .log-line .highlight {
            font-weight: bold;
        }
        .no-logs {
            color: #888;
            font-style: italic;
            padding: 40px;
            text-align: center;
        }"""


def network_styles() -> str:
    """Complete CSS for the network logs viewer page.

    Returns:
        CSS string (without <style> tags).
    """
    return "\n".join(
        [
            _dark_base(),
            _network_specific(),
        ]
    )
