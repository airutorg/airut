# Microsoft OAuth2 for M365 (IMAP/SMTP)

If your mailbox is hosted on Microsoft 365 (Exchange Online), you can use OAuth2
instead of password authentication. This is required for organizations that have
disabled Basic Authentication, and Microsoft is enforcing this for SMTP AUTH
starting
[April 30, 2026](https://techcommunity.microsoft.com/blog/exchange/exchange-online-to-retire-basic-auth-for-client-submission-smtp-auth/4114750).

Airut uses the **OAuth2 Client Credentials flow** with the XOAUTH2 SASL
mechanism. This authenticates as a service principal (application identity)
rather than a user, which is the correct approach for headless/daemon services.

## Prerequisites

- **Global Admin** (or Application Administrator + Exchange Administrator)
  access to your Microsoft 365 tenant
- **PowerShell** with the
  [ExchangeOnlineManagement](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
  module for Exchange configuration
- A dedicated mailbox for Airut (see
  [Dedicated Inbox Requirement](deployment.md#dedicated-inbox-requirement))

## Step 1: Register the Application in Entra ID (Azure AD)

1. Go to the [Microsoft Entra admin center](https://entra.microsoft.com/) >
   **App registrations** > **New registration**
2. Name it (e.g., `airut-email-service`), leave the redirect URI empty
3. Note the **Application (client) ID** and **Directory (tenant) ID** from the
   overview page

## Step 2: Create a Client Secret

1. In your app registration, go to **Certificates & secrets** > **New client
   secret**
2. Set a description and expiry (e.g., 24 months)
3. **Copy the secret `Value` immediately** — it is only shown once

## Step 3: Add API Permissions

1. Go to **API permissions** > **Add a permission**
2. Select the **APIs my organization uses** tab
3. Search for **Office 365 Exchange Online** (not Microsoft Graph)
4. Select **Application permissions**
5. Add both:
   - **`IMAP.AccessAsApp`** — for reading the inbox
   - **`SMTP.SendAsApp`** — for sending replies
6. Click **Grant admin consent for [Your Organization]**

## Step 4: Register the Service Principal in Exchange Online

This is the step most people miss. Azure AD permissions alone are not enough —
you must explicitly register the application as a service principal in Exchange
Online.

First, find the correct Object ID:

1. In the Entra admin center, go to **Enterprise applications** (not App
   registrations)
2. Find your application and note the **Object ID** from its overview page

> **⚠️ Warning:** There are two different Object IDs — one under **App
> registrations** and one under **Enterprise applications**. You must use the
> one from **Enterprise applications**. Using the wrong one causes
> authentication failures that are difficult to diagnose.

Then run the PowerShell commands:

```powershell
# Install the Exchange Online module (one-time)
Install-Module -Name ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline

# Register the service principal
# -AppId: Application (client) ID from App registrations
# -ObjectId: Object ID from Enterprise applications (NOT App registrations)
New-ServicePrincipal -AppId <CLIENT_ID> -ObjectId <ENTERPRISE_APP_OBJECT_ID>
```

> **Note:** If your tenant doesn't recognize the `-ObjectId` parameter, use
> `-ServiceId` instead (older alias):
> `New-ServicePrincipal -AppId <CLIENT_ID> -ServiceId <ENTERPRISE_APP_OBJECT_ID>`

## Step 5: Grant Mailbox Permissions

Grant the service principal access to the Airut mailbox:

> **⚠️ Security Warning:** The Azure AD permissions (`IMAP.AccessAsApp`) enable
> the capability for this app to access mailboxes, but they do not grant access
> to any specific mailbox content by default.
>
> You must strictly limit the `Add-MailboxPermission` command to the dedicated
> Airut mailbox.
>
> **Do not** run this command against a user group, a list of users, or your
> entire tenant. If you inadvertently grant this permission to a sensitive user
> (e.g., a CEO), the application — and anyone with its client secret — will have
> full access to that person's email.

```powershell
# Get the service principal identity
Get-ServicePrincipal | fl

# Grant FullAccess to the mailbox (for IMAP reading and SMTP sending)
# -User: the Identity value from Get-ServicePrincipal output
Add-MailboxPermission -Identity "airut@company.com" -User <SERVICE_PRINCIPAL_ID> -AccessRights FullAccess
```

## Step 6: Enable SMTP AUTH

SMTP AUTH must be enabled for the mailbox, even with OAuth2. Without this, SMTP
sending silently fails.

```powershell
# Enable SMTP AUTH for the specific mailbox
Set-CASMailbox -Identity "airut@company.com" -SmtpClientAuthenticationDisabled $false

# Verify the setting
Get-CASMailbox -Identity "airut@company.com" | fl SmtpClientAuthenticationDisabled
```

If SMTP AUTH is disabled at the organization level, you may also need:

```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $false
```

## Step 7: Configure Airut

Add the OAuth2 credentials to `~/.config/airut/airut.yaml`:

```yaml
repos:
  my-project:
    email:
      imap_server: outlook.office365.com
      imap_port: 993
      smtp_server: smtp.office365.com
      smtp_port: 587
      username: airut@company.com
      from: "Airut <airut@company.com>"
      # password is not needed when using OAuth2

      microsoft_oauth2:
        tenant_id: !env AZURE_TENANT_ID
        client_id: !env AZURE_CLIENT_ID
        client_secret: !env AZURE_CLIENT_SECRET

    # Microsoft 365 omits authserv-id from Authentication-Results
    # headers — set to empty string to skip the authserv-id check
    trusted_authserv_id: ""

    # Accept X-MS-Exchange-Organization-AuthAs: Internal for intra-org
    # email where Microsoft 365 omits Authentication-Results entirely
    microsoft_internal_auth_fallback: true

    authorized_senders:
      - you@company.com
```

Add the corresponding values to your `.env` file:

```bash
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret-value
```

When `microsoft_oauth2` is configured, Airut uses XOAUTH2 for both IMAP and SMTP
instead of password authentication. The `password` field can be omitted.

> **Important: `trusted_authserv_id` must be empty string for Microsoft 365.**
> Microsoft's Exchange Online Protection (EOP) omits the RFC 8601 `authserv-id`
> from `Authentication-Results` headers. Setting `trusted_authserv_id: ""` tells
> Airut to skip the authserv-id check and rely solely on the first-header-only
> policy for DMARC verification. See
> [Anti-spam message headers (Microsoft Learn)](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo)
> for details on Microsoft's header format.

> **Internal (intra-org) email:** Microsoft 365 does not generate
> `Authentication-Results` headers at all for email sent within the same tenant.
> Instead, it stamps the message with
> `X-MS-Exchange-Organization-AuthAs: Internal`. Set
> `microsoft_internal_auth_fallback: true` to accept this header as
> authentication proof when no `Authentication-Results` header is present.
> Authorization (sender allowlist) still applies. See
> [Demystifying Hybrid Mail Flow (Microsoft Tech Community)](https://techcommunity.microsoft.com/blog/exchange/demystifying-and-troubleshooting-hybrid-mail-flow-when-is-a-message-internal/1420838)
> for background.

## Step 8: Verify

Restart the service and check the logs:

```bash
systemctl --user restart airut
journalctl --user -u airut -f
```

You should see successful IMAP connections and no authentication errors. If you
see `AUTHENTICATE failed`, check the troubleshooting section below.

## Troubleshooting OAuth2

**`AUTHENTICATE failed` despite valid token:**

- Verify you used the Object ID from **Enterprise applications**, not App
  registrations
- Confirm `New-ServicePrincipal` and `Add-MailboxPermission` were run
  successfully
- Wait 15–30 minutes — Exchange Online permission propagation can be slow

**SMTP sending fails silently:**

- Ensure SMTP AUTH is enabled on the mailbox (`Set-CASMailbox`)
- Verify `SMTP.SendAsApp` permission was granted and admin-consented

**`invalid_client` error in logs:**

- Double-check the tenant ID, client ID, and client secret values
- Verify the client secret hasn't expired

**Token scope errors:**

- Airut uses the scope `https://outlook.office365.com/.default`, which is the
  only valid scope for M365 IMAP/SMTP client credentials. This is hardcoded and
  cannot be changed.
