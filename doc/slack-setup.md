# Slack Setup

This guide covers setting up Slack as a channel for Airut, enabling users to
interact with Claude Code through Slack DMs (using Slack's Agents & AI Apps
platform) and through workspace channels the bot has been invited to.

For email setup, see [email-setup.md](email-setup.md). Both channels can run
simultaneously for the same repository.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Prerequisites](#prerequisites)
- [How It Works](#how-it-works)
- [Step 1: Create the Slack App](#step-1-create-the-slack-app)
- [Step 2: Generate Tokens](#step-2-generate-tokens)
  - [App-Level Token (`xapp-...`)](#app-level-token-xapp-)
  - [Bot Token (`xoxb-...`)](#bot-token-xoxb-)
  - [App Icon (Optional)](#app-icon-optional)
- [Step 3: Configure Airut](#step-3-configure-airut)
- [Step 4: Test the Setup](#step-4-test-the-setup)
- [Authorization Rules](#authorization-rules)
  - [`workspace_members`](#workspace_members)
  - [`user_group`](#user_group)
  - [`user_id`](#user_id)
  - [Combining Rules](#combining-rules)
- [Required Scopes](#required-scopes)
- [Troubleshooting](#troubleshooting)
  - [Socket Mode Connection Failures](#socket-mode-connection-failures)
  - [Authentication Failures](#authentication-failures)
  - [User Group Rule Not Working](#user-group-rule-not-working)
  - [Rate Limit Errors](#rate-limit-errors)
  - [Messages Not Appearing](#messages-not-appearing)

<!-- mdformat-toc end -->

## Prerequisites

- Airut server deployed (see [deployment.md](deployment.md))
- **Slack workspace** where you have permission to install apps
- Admin access to create Slack apps (or approval from a workspace admin)

## How It Works

Airut's Slack integration offers two surfaces over a single **Socket Mode**
connection:

- **DMs (Agents & AI Apps mode)** — the standard bot DM interface is replaced
  with a Chat tab and History tab. Every interaction is automatically threaded —
  users cannot send unthreaded messages — which maps cleanly to Airut's
  conversation model.
- **Channels** — once invited to a public or private channel via
  `/invite @airut`, the bot engages whenever it is `@`-mentioned. The triggering
  message's thread becomes a new Airut conversation; every subsequent message in
  that thread is treated as additional input without needing to re-mention the
  bot. Mid-thread mentions cause the bot to pull prior thread history into
  context.
- **Socket Mode** means Airut initiates an outbound WebSocket connection to
  Slack. No inbound HTTP endpoint, public DNS, or TLS certificates are needed —
  compatible with deployment behind a firewall.

Each Slack thread maps to one Airut conversation, regardless of whether the
thread lives in a DM or a channel. Opening the Chat tab starts a new
conversation; replying in an existing thread (DM or channel) resumes the
previous one.

## Step 1: Create the Slack App

A ready-to-use app manifest is provided at
[`config/slack-app-manifest.json`](../config/slack-app-manifest.json).

1. Go to [api.slack.com/apps?new_app=1](https://api.slack.com/apps?new_app=1)
2. Choose **From a manifest**, select your workspace
3. Switch to the **JSON** tab and paste the contents of
   `config/slack-app-manifest.json`
4. Click **Create**

The manifest configures all required features, scopes, and event subscriptions
automatically. See [Required Scopes](#required-scopes) below for details on what
each scope does.

## Step 2: Generate Tokens

You need two tokens:

### App-Level Token (`xapp-...`)

1. In your app's settings, go to **Basic Information**
2. Scroll to **App-Level Tokens** and click **Generate Token and Scopes**
3. Name it (e.g., `airut-socket-mode`)
4. Add the `connections:write` scope
5. Click **Generate**
6. Copy the `xapp-...` token — this is your `SLACK_APP_TOKEN`

### Bot Token (`xoxb-...`)

1. Go to **OAuth & Permissions**
2. Click **Install to Workspace** and authorize
3. Copy the **Bot User OAuth Token** (`xoxb-...`) — this is your
   `SLACK_BOT_TOKEN`

### App Icon (Optional)

Under **Basic Information → Display Information**, upload the app icon. The
Airut logo is available at `https://airut.org/assets/logo-square-white-bg.png`.
The manifest format does not support icon URLs — they must be uploaded via the
UI.

## Step 3: Configure Airut

You can configure the Slack channel using the config editor in the dashboard
(`http://localhost:5200` → **Configure**), or by editing
`~/.config/airut/airut.yaml` directly. The field paths below (e.g.,
`repos.<repo>.slack.bot_token`) match the labels shown in the config editor.

Add the Slack channel to your server config:

```yaml
repos:
  my-project:
    slack:
      bot_token: !env SLACK_BOT_TOKEN
      app_token: !env SLACK_APP_TOKEN

      # Authorization rules (at least one required).
      # Evaluated in order; first match wins.
      authorized:
        - workspace_members: true

      # Optional: restrict channel mode to specific channels.
      # If omitted or empty, the bot engages in any channel it has
      # been invited to. Use Slack channel IDs (stable across renames).
      # DM events bypass this list.
      # allowed_channels:
      #   - C0123456789
      #   - C9876543210

    repo_url: https://github.com/your-org/your-repo.git

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
        headers:
          - "Authorization"
```

Add the tokens to `~/.config/airut/.env`:

```bash
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
```

**Slack and email can coexist.** To run both channels for the same repo, include
both `email:` and `slack:` blocks under the repo. Each channel operates
independently with its own listener and authentication.

If using the config editor, changes are saved and reloaded automatically — no
restart needed. If editing the YAML file directly, changes are also picked up
via live config reload (the channel restarts once any in-flight task completes).

## Step 4: Test the Setup

1. Open Slack and find **Airut** in the Apps section (left sidebar or top bar)
2. Click on it to open the **Chat tab**
3. Send a test message:
   ```
   Please verify you can access the repository by listing the files in the
   root directory.
   ```
4. You should see:
   - A status indicator ("is getting ready...")
   - An acknowledgment message with a dashboard link (if configured)
   - A reply with the file listing
   - A thread title set from your message

Check the service logs if something goes wrong:

```bash
journalctl --user -u airut -f
```

## Authorization Rules

Authorization rules control which Slack users can interact with the bot. At
least one rule is required. Rules are evaluated in order — the first matching
rule determines the outcome. If no rule matches, the request is rejected.

Before evaluating rules, baseline checks are always applied:

- **Bots are rejected** — prevents bot-to-bot loops
- **Deactivated users are rejected** — no access for disabled accounts
- **External users are rejected** — users from other workspaces (via Slack
  Connect) are blocked by `team_id` mismatch

### `workspace_members`

Allows all full members of the workspace. Guest accounts (single-channel and
multi-channel guests) are excluded.

```yaml
authorized:
  - workspace_members: true
```

This is the simplest rule and works well for small teams where all workspace
members should have access.

### `user_group`

Restricts access to members of a specific Slack user group (the `@handle` groups
shown in the sidebar). Requires the `usergroups:read` scope (included in the app
manifest).

```yaml
authorized:
  - user_group: engineering
```

The group handle is resolved to a group ID at startup and membership is cached
with a 5-minute TTL. If the group doesn't exist, the rule rejects all users with
a warning in logs.

### `user_id`

Restricts access to a specific Slack user ID. Find user IDs by clicking a user's
profile in Slack → **More** → **Copy member ID**.

```yaml
authorized:
  - user_id: U12345678
```

### Combining Rules

Rules can be combined. First match wins:

```yaml
authorized:
  # Allow anyone in the engineering group
  - user_group: engineering
  # Also allow this specific user from another team
  - user_id: U98765432
```

## Required Scopes

The app manifest includes these bot token scopes:

| Scope               | Purpose                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| `assistant:write`   | Thread titles, status indicators (DM-only, auto-added)                                         |
| `chat:write`        | Send messages and replies in threads                                                           |
| `im:history`        | Read DM history for thread context                                                             |
| `users:read`        | User info for authorization and display-name resolution                                        |
| `files:read`        | Read files uploaded by users                                                                   |
| `files:write`       | Upload outbox files to threads                                                                 |
| `app_mentions:read` | Receive `app_mention` events in channels                                                       |
| `channels:history`  | Read public-channel thread history                                                             |
| `groups:history`    | Read private-channel thread history                                                            |
| `reactions:write`   | Add `:eyes:` acknowledgement reaction in channels                                              |
| `usergroups:read`   | User group membership (for `user_group` rules and outbound `@group` rewriting)                 |
| `channels:read`     | Outbound `#channel` rewriting and dashboard channel-ID lookup by name (optional, add manually) |

The `usergroups:read` scope is only needed if you use `user_group` authorization
rules or rely on outbound `@group` mention rewriting. If you only use
`workspace_members` or `user_id` rules, you can remove it from the manifest
before creating the app.

The `channels:read` scope is **not** in the manifest and must be added manually
if you want it. It is only needed to rewrite `#channel` references in outbound
replies into real channel links (and for dashboard channel-ID lookup by name).
Without it, `#channel` tokens are left as plain text and a warning is logged;
everything else works.

The channel-mode scopes (`app_mentions:read`, `channels:history`,
`groups:history`, `reactions:write`) are required even for DM-only deployments
in the current manifest; removing them disables channel mode without affecting
DM operation.

## Troubleshooting

### Socket Mode Connection Failures

```bash
# Check service logs for WebSocket errors
journalctl --user -u airut | grep -i "socket\|websocket\|slack"

# Common causes:
# - Invalid app-level token (xapp-...)
# - Socket Mode not enabled in app settings
# - Network firewall blocking outbound WebSocket connections
```

Verify Socket Mode is enabled: in your app settings, go to **Settings → Socket
Mode** and confirm it shows "Enabled".

### Authentication Failures

```bash
# Symptom: Bot doesn't respond to messages, logs show "unauthorized"

# Check:
# 1. Bot token (xoxb-...) is valid and installed to the correct workspace
# 2. authorized rules are configured (at least one required)
# 3. User is not a bot, guest, or external user
```

Test the bot token manually:

```bash
curl -s -H "Authorization: Bearer $SLACK_BOT_TOKEN" \
  https://slack.com/api/auth.test | python3 -m json.tool
```

### User Group Rule Not Working

```bash
# Symptom: Users in the group are rejected

# Check:
# 1. Group handle matches exactly (case-sensitive)
# 2. usergroups:read scope is present
# 3. Group is not disabled/archived
```

The group handle is the name shown after `@` in Slack (e.g., for `@engineering`,
use `engineering`). Group membership is cached for 5 minutes — changes may take
up to 5 minutes to take effect.

### Rate Limit Errors

Slack rate limits API calls. Airut mitigates this through caching, but high
message volumes may still trigger limits. The adapter logs rate limit responses
as warnings. Caching TTLs:

- User info (`users.info`): 5 minutes
- Group membership (`usergroups.users.list`): 5 minutes
- Workspace team ID (`auth.test`): cached once at startup

### Messages Not Appearing

If the bot connects but messages don't appear:

1. Verify the app has the required event subscriptions
   (`assistant_thread_started`, `assistant_thread_context_changed`, `message.im`
   for DM mode; `app_mention`, `message.channels`, `message.groups` for channel
   mode) — these are configured by the manifest.
2. For DMs: check that the user is interacting through the Chat tab, not a
   standard DM.
3. For channels: confirm the bot is a member of the channel (`/invite @airut`),
   and that the channel ID is in `allowed_channels` if that list is configured.
4. Look for errors in the service logs during message handling.
