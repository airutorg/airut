# GitHub App Setup

This guide covers setting up a GitHub App as the agent's GitHub identity. GitHub
Apps are the **recommended** authentication method for Airut, replacing the
classic PAT + dedicated machine user approach.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Why GitHub App Over Classic PAT](#why-github-app-over-classic-pat)
- [Prerequisites](#prerequisites)
- [App Ownership](#app-ownership)
- [Step 1: Create the GitHub App](#step-1-create-the-github-app)
- [Step 2: Configure Permissions](#step-2-configure-permissions)
- [Step 3: Generate a Private Key](#step-3-generate-a-private-key)
- [Step 4: Install the App](#step-4-install-the-app)
- [Step 5: Configure Airut](#step-5-configure-airut)
- [Step 6: Configure Git Identity](#step-6-configure-git-identity)
- [Step 7: Verify](#step-7-verify)
- [GitHub Enterprise Server (GHES)](#github-enterprise-server-ghes)
- [PAT vs GitHub App Comparison](#pat-vs-github-app-comparison)
- [Troubleshooting](#troubleshooting)

<!-- mdformat-toc end -->

## Why GitHub App Over Classic PAT

| Concern                      | Classic PAT                                                           | GitHub App                                                     |
| ---------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------- |
| **Token lifetime**           | Months to years (or never expires)                                    | 1 hour (installation tokens, auto-rotated by proxy)            |
| **Repository creation**      | Cannot prevent -- classic PATs inherently allow repo creation via API | Impossible unless explicitly granted `Administration: write`   |
| **Permission granularity**   | Coarse (`repo` scope grants broad access)                             | Fine-grained per-permission (Contents, PRs, Issues separately) |
| **Workflow file protection** | Must manually omit `workflow` scope; easy to miss                     | Simply don't grant `Workflows` permission -- clean separation  |
| **Dedicated user needed**    | Yes -- consumes a seat, requires separate account management          | No -- app has its own bot identity, no seat consumed           |
| **Response echo risk**       | High -- leaked PAT provides persistent access                         | Low -- leaked installation token expires in 1 hour             |
| **Rate limits**              | 5,000 requests/hour (fixed)                                           | 5,000-12,500 requests/hour (scales with org size)              |

**Key motivation:** Classic PATs cannot limit repository creation. Even with the
network allowlist restricting which hosts the agent can reach, a compromised
agent could create public repositories under the dedicated user's account via
the GraphQL endpoint and leak information through repository names or
descriptions. GitHub Apps eliminate this risk entirely -- they cannot create
repositories unless explicitly granted `Administration: write` permission.

## Prerequisites

- **Organization owner** access (or personal account owner) on GitHub
- Airut server deployed (see [deployment.md](deployment.md))

## App Ownership

**Register the app under the organization** that owns the target repositories.
This is the recommended approach.

| Ownership            | Pros                                                                                                                                                                                                                                                                                                | Cons                                                                                              |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **Organization**     | Survives personnel changes; any org owner can manage; shared management via [GitHub App managers](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/adding-and-removing-github-app-managers-in-your-organization); private app installs only on owning org | Requires org owner access to create                                                               |
| **Personal account** | Quick to set up                                                                                                                                                                                                                                                                                     | Tied to one person; no management delegation; if account is suspended or deleted, the app is gone |

**Do not create a dedicated user to own the app.** The whole point of GitHub
Apps is to eliminate dedicated user accounts. A dedicated user adds account
management overhead (password, 2FA, recovery), may consume a seat, and provides
no advantage over org ownership -- org-owned apps already survive admin
departures and support delegated management.

The app's bot identity (`your-app-name[bot]`) is the same regardless of who owns
the app. Ownership only affects who can modify the app's settings and where it
can be privately installed.

## Step 1: Create the GitHub App

1. Navigate to your organization's Settings (or your personal Settings for
   personal repos)
2. Go to **Developer settings > GitHub Apps > New GitHub App**
3. Fill in the required fields:
   - **GitHub App name**: e.g., `your-org-airut` (must be globally unique)
   - **Homepage URL**: Your organization's URL or the Airut repository URL
4. Under **Webhook**:
   - **Uncheck** "Active" -- Airut does not use GitHub webhooks
5. Under **Where can this GitHub App be installed?**:
   - Select "Only on this account"
6. Click **Create GitHub App**

Note the **App ID** (or **Client ID** starting with `Iv` on github.com) from the
app's settings page -- you'll need this for configuration.

## Step 2: Configure Permissions

Under the app's **Permissions & events** settings, grant the following
**Repository permissions**:

| Permission        | Level          | Rationale                                  |
| ----------------- | -------------- | ------------------------------------------ |
| **Contents**      | Read and write | Push branches, create commits              |
| **Pull requests** | Read and write | Create and manage pull requests            |
| **Metadata**      | Read-only      | Required by GitHub (automatically granted) |

Optional permissions depending on your use case:

| Permission  | Level          | When needed                                      |
| ----------- | -------------- | ------------------------------------------------ |
| **Issues**  | Read and write | If the agent needs to read or create issues      |
| **Actions** | Read-only      | If the agent checks CI status via the GitHub API |
| **Checks**  | Read-only      | If the agent reads check run results             |

**Do NOT grant these permissions:**

| Permission         | Why not                                                          |
| ------------------ | ---------------------------------------------------------------- |
| **Workflows**      | Prevents writing to `.github/workflows/` -- key security control |
| **Administration** | Prevents repository creation and settings changes                |

**How workflow file protection works:** GitHub treats `Contents` and `Workflows`
as separate permissions. A GitHub App with `Contents: Read and write` but
**without** `Workflows` will be **rejected by GitHub** when pushing changes that
include modifications to `.github/workflows/` files. This is cleaner than the
classic PAT approach where the `workflow` scope must be manually omitted.

Branch protection rules are still recommended as defense-in-depth. See
[ci-sandbox.md](ci-sandbox.md#1-protecting-workflow-files).

## Step 3: Generate a Private Key

1. On the app's settings page, scroll to **Private keys**
2. Click **Generate a private key**
3. A `.pem` file downloads automatically
4. Store the PEM file securely -- you'll reference it in your `.env` file

The private key is used by the proxy to generate short-lived installation
tokens. It never enters the container -- only the proxy sees it.

## Step 4: Install the App

1. On the app's settings page, click **Install App** in the sidebar
2. Select your organization (or personal account)
3. Choose **Only select repositories** and pick the repos the agent will operate
   on
4. Click **Install**

After installation, note the **Installation ID** from the URL:
`https://github.com/settings/installations/<INSTALLATION_ID>` (or
`https://github.com/organizations/<org>/settings/installations/<INSTALLATION_ID>`).

## Step 5: Configure Airut

Add the GitHub App credentials to your server configuration.

**Environment file** (`~/.config/airut/.env`):

```bash
GH_APP_ID=Iv23liXXXXXXXXXX            # Client ID from app settings
GH_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAK...
-----END RSA PRIVATE KEY-----"
GH_APP_INSTALLATION_ID=12345678        # From installation URL
```

**Server config** (`~/.config/airut/airut.yaml`):

```yaml
repos:
  my-project:
    github_app_credentials:
      GH_TOKEN:
        app_id: !env GH_APP_ID
        private_key: !env GH_APP_PRIVATE_KEY
        installation_id: !env GH_APP_INSTALLATION_ID
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
        # Optional: restrict token to minimum required permissions
        permissions:
          contents: write
          pull_requests: write
        # Optional: restrict token to specific repos
        repositories:
          - "my-repo"

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
```

No repo-side configuration is needed. The `GH_TOKEN` surrogate is auto-injected
into containers from the server config. The container receives a surrogate
token; the proxy transparently replaces it with a short-lived installation token
for requests to scoped hosts. See
[network-sandbox.md](network-sandbox.md#github-app-credentials-proxy-managed-token-rotation)
for the security model.

## Step 6: Configure Git Identity

GitHub Apps act as their own bot identity. Configure the container's git
identity to match.

In `.airut/container/gitconfig`:

```ini
[user]
    name = your-app-name[bot]
    email = <ID>+your-app-name[bot]@users.noreply.github.com
[credential "https://github.com"]
    helper = !gh auth git-credential
```

To find the bot user ID for the email address: visit
`https://api.github.com/users/your-app-name[bot]` and note the `id` field.

## Step 7: Verify

1. Restart the Airut service: `systemctl --user restart airut`
2. Send a test task that pushes a branch and creates a PR
3. Verify the PR is created by `your-app-name[bot]`
4. Check service logs for successful token refresh:
   `journalctl --user -u airut -f`

## GitHub Enterprise Server (GHES)

For GHES, add a `base_url` field pointing to your instance's API:

```yaml
github_app_credentials:
  GH_TOKEN:
    app_id: "12345"                          # Numeric App ID for GHES < 3.19
    private_key: !env GH_APP_PRIVATE_KEY
    installation_id: "67890"
    base_url: "https://github.example.com/api/v3"
    scopes:
      - "github.example.com"
      - "*.github.example.com"
```

On GHES < 3.19, use the numeric App ID (not the Client ID). On GHES 3.19+ and
github.com, use the Client ID (`Iv23li...`).

## PAT vs GitHub App Comparison

| Aspect                        | Classic PAT (Dedicated User)          | GitHub App                                    |
| ----------------------------- | ------------------------------------- | --------------------------------------------- |
| Token lifetime                | Months to years                       | 1 hour (auto-rotated)                         |
| Dedicated user needed         | Yes (consumes a seat)                 | No (app has bot identity)                     |
| Repository creation risk      | Cannot prevent                        | Impossible without explicit permission        |
| Workflow file protection      | Omit `workflow` scope (error-prone)   | Don't grant `Workflows` permission (explicit) |
| Fine-grained scoping          | Not viable with classic PATs          | Per-permission, per-repository                |
| Response echo risk            | High (long-lived token)               | Low (1-hour expiry)                           |
| Setup complexity              | Simple (create account, generate PAT) | Moderate (create app, configure, install)     |
| Proxy complexity              | Stateless string replacement          | Stateful (token cache + periodic refresh)     |
| Rate limits                   | 5,000/hr                              | 5,000-12,500/hr                               |
| Persists across admin changes | Tied to user account                  | App survives admin departures                 |

**Dedicated user no longer needed:** With a GitHub App, the app acts as its own
bot identity (`your-app-name[bot]`). PRs are created by the bot user, commits
are attributed to it, and no organization seat is consumed. The app persists
even if the administrator who installed it leaves the organization.

## Troubleshooting

**"401 Unauthorized" on token refresh:**

- Verify `app_id` matches the Client ID (or numeric ID for GHES < 3.19) from the
  app's settings page
- Verify the private key PEM is correct and complete (including header/footer
  lines)
- Check that the key hasn't been revoked -- regenerate if needed

**"404 Not Found" on token refresh:**

- Verify `installation_id` is correct (check the URL after installing the app)
- Ensure the app is still installed on the target organization/account

**"403 Forbidden" on API calls:**

- The app may lack the required permissions -- check **Permissions & events** in
  the app settings
- If using `permissions` in config, verify the requested permissions are a
  subset of the app's granted permissions

**"Resource not accessible by integration":**

- The installation token may not have access to the target repository -- ensure
  the app is installed on that repository (or all repositories)
- If using `repositories` in config, verify the repo names are correct

**Push rejected with workflow file error:**

- This is expected behavior -- the app correctly lacks `Workflows` permission.
  The agent should not modify `.github/workflows/` files.

**Token expired errors in container logs:**

- The proxy handles token rotation transparently. If the container sees expired
  token errors, check that the network sandbox is enabled (surrogate replacement
  requires the proxy).
