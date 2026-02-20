# Slack Setup

This guide covers setting up Slack as a channel for Airut, enabling users to
interact with Claude Code through Slack DMs using Slack's Agents & AI Apps
platform.

For email setup, see [email-setup.md](email-setup.md). Both channels can run
simultaneously for the same repository.

## Prerequisites

- Airut server deployed (see [deployment.md](deployment.md))
- **Slack workspace** where you have permission to install apps
- Admin access to create Slack apps (or approval from a workspace admin)

## How It Works

Airut's Slack integration uses **Agents & AI Apps** mode with **Socket Mode**:

- **Agents & AI Apps** replaces the standard bot DM interface with a Chat tab
  and History tab. Every interaction is automatically threaded — users cannot
  send unthreaded messages. This maps cleanly to Airut's conversation model.
- **Socket Mode** means Airut initiates an outbound WebSocket connection to
  Slack. No inbound HTTP endpoint, public DNS, or TLS certificates are needed —
  compatible with deployment behind a firewall.

Each Slack thread maps to one Airut conversation. Opening the Chat tab starts a
new conversation; replying in an existing thread resumes the previous one.

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

Add the Slack channel to your server config (`~/.config/airut/airut.yaml`):

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

    git:
      repo_url: https://github.com/your-org/your-repo.git

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
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

Restart the service to pick up the new configuration:

```bash
systemctl --user restart airut
```

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

| Scope             | Purpose                                        |
| ----------------- | ---------------------------------------------- |
| `assistant:write` | Thread titles, status indicators (auto-added)  |
| `chat:write`      | Send messages and replies in threads           |
| `im:history`      | Read DM history for thread context             |
| `users:read`      | User info for authorization checks             |
| `files:read`      | Read files uploaded by users                   |
| `files:write`     | Upload outbox files to threads                 |
| `usergroups:read` | User group membership (for `user_group` rules) |

The `usergroups:read` scope is only needed if you use `user_group` authorization
rules. If you only use `workspace_members` or `user_id` rules, you can remove it
from the manifest before creating the app.

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
   (`assistant_thread_started`, `assistant_thread_context_changed`,
   `message.im`) — these are configured by the manifest
2. Check that the user is interacting through the Chat tab, not a standard DM
3. Look for errors in the service logs during message handling
