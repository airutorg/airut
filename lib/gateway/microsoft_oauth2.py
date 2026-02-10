# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Microsoft OAuth2 token provider for M365 IMAP/SMTP access.

Uses MSAL (Microsoft Authentication Library) to acquire OAuth2 tokens via the
Client Credentials flow for Azure AD / Entra ID service principals.  Tokens
are used with the XOAUTH2 SASL mechanism for IMAP and SMTP authentication.

The scope is hardcoded to ``https://outlook.office365.com/.default`` — the only
valid scope for M365 IMAP/SMTP client credentials.
"""

import logging

from msal import ConfidentialClientApplication


logger = logging.getLogger(__name__)

#: OAuth2 scope for M365 IMAP/SMTP access via client credentials.
_M365_SCOPE = ["https://outlook.office365.com/.default"]


class MicrosoftOAuth2TokenError(Exception):
    """Raised when Microsoft OAuth2 token acquisition fails."""


class MicrosoftOAuth2TokenProvider:
    """Acquires OAuth2 tokens via MSAL Client Credentials flow.

    Uses Microsoft's MSAL library to authenticate against Azure AD / Entra ID
    for M365 IMAP/SMTP access.  MSAL handles token caching internally — cached
    tokens are returned when still valid, and new tokens are acquired
    automatically when expired.

    Attributes:
        tenant_id: Azure AD tenant ID.
        client_id: Application (client) ID from Azure AD app registration.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        """Initialize the token provider.

        Args:
            tenant_id: Azure AD tenant ID.
            client_id: Application (client) ID from Azure AD app registration.
            client_secret: Client secret value from Azure AD app registration.
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        logger.debug(
            "Initialized Microsoft OAuth2 token provider: tenant=%s, client=%s",
            tenant_id,
            client_id,
        )

    def get_access_token(self) -> str:
        """Return a valid access token (from cache or freshly acquired).

        MSAL handles token caching internally.  This method will return a
        cached token if still valid, or acquire a new one from Azure AD.

        Returns:
            OAuth2 access token string.

        Raises:
            MicrosoftOAuth2TokenError: If token acquisition fails.
        """
        result = self._app.acquire_token_for_client(scopes=_M365_SCOPE)

        if "access_token" in result:
            logger.debug("Acquired Microsoft OAuth2 access token")
            return result["access_token"]

        error = result.get("error", "unknown_error")
        description = result.get("error_description", "No description")
        raise MicrosoftOAuth2TokenError(
            f"Failed to acquire token: {error}: {description}"
        )

    def generate_xoauth2_string(self, user: str) -> str:
        r"""Build the SASL XOAUTH2 authentication string.

        Acquires a fresh token and formats it for the XOAUTH2 SASL mechanism
        used by IMAP ``AUTHENTICATE`` and SMTP ``AUTH`` commands.

        Format: ``user={user}\x01auth=Bearer {token}\x01\x01``

        Args:
            user: Email address of the mailbox to authenticate as.

        Returns:
            XOAUTH2 authentication string.

        Raises:
            MicrosoftOAuth2TokenError: If token acquisition fails.
        """
        token = self.get_access_token()
        return f"user={user}\x01auth=Bearer {token}\x01\x01"
