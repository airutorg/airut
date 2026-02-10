# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for Microsoft OAuth2 token provider."""

from unittest.mock import MagicMock, patch

import pytest

from lib.gateway.microsoft_oauth2 import (
    MicrosoftOAuth2TokenError,
    MicrosoftOAuth2TokenProvider,
)


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_init_creates_msal_app(mock_msal_cls):
    """Test provider initializes MSAL ConfidentialClientApplication."""
    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
    )

    mock_msal_cls.assert_called_once_with(
        "test-client",
        authority="https://login.microsoftonline.com/test-tenant",
        client_credential="test-secret",
    )
    assert provider.tenant_id == "test-tenant"
    assert provider.client_id == "test-client"


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_get_access_token_success(mock_msal_cls):
    """Test successful token acquisition."""
    mock_app = MagicMock()
    mock_msal_cls.return_value = mock_app
    mock_app.acquire_token_for_client.return_value = {
        "access_token": "eyJ0eXAi...",
    }

    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="t", client_id="c", client_secret="s"
    )

    token = provider.get_access_token()

    assert token == "eyJ0eXAi..."
    mock_app.acquire_token_for_client.assert_called_once_with(
        scopes=["https://outlook.office365.com/.default"]
    )


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_get_access_token_failure(mock_msal_cls):
    """Test token acquisition failure raises MicrosoftOAuth2TokenError."""
    mock_app = MagicMock()
    mock_msal_cls.return_value = mock_app
    mock_app.acquire_token_for_client.return_value = {
        "error": "invalid_client",
        "error_description": "Bad client secret",
    }

    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="t", client_id="c", client_secret="s"
    )

    with pytest.raises(
        MicrosoftOAuth2TokenError,
        match="Failed to acquire token: invalid_client: Bad client secret",
    ):
        provider.get_access_token()


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_get_access_token_failure_no_description(mock_msal_cls):
    """Test token failure with missing error_description."""
    mock_app = MagicMock()
    mock_msal_cls.return_value = mock_app
    mock_app.acquire_token_for_client.return_value = {
        "error": "unknown_error",
    }

    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="t", client_id="c", client_secret="s"
    )

    with pytest.raises(
        MicrosoftOAuth2TokenError,
        match="unknown_error: No description",
    ):
        provider.get_access_token()


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_get_access_token_failure_no_error_field(mock_msal_cls):
    """Test token failure with empty result."""
    mock_app = MagicMock()
    mock_msal_cls.return_value = mock_app
    mock_app.acquire_token_for_client.return_value = {}

    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="t", client_id="c", client_secret="s"
    )

    with pytest.raises(
        MicrosoftOAuth2TokenError,
        match="unknown_error: No description",
    ):
        provider.get_access_token()


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_generate_xoauth2_string(mock_msal_cls):
    """Test XOAUTH2 string generation."""
    mock_app = MagicMock()
    mock_msal_cls.return_value = mock_app
    mock_app.acquire_token_for_client.return_value = {
        "access_token": "my-token-123",
    }

    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="t", client_id="c", client_secret="s"
    )

    auth_string = provider.generate_xoauth2_string("user@example.com")

    expected = "user=user@example.com\x01auth=Bearer my-token-123\x01\x01"
    assert auth_string == expected


@patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication")
def test_generate_xoauth2_string_token_failure(mock_msal_cls):
    """Test XOAUTH2 string generation propagates token errors."""
    mock_app = MagicMock()
    mock_msal_cls.return_value = mock_app
    mock_app.acquire_token_for_client.return_value = {
        "error": "expired_token",
        "error_description": "Token expired",
    }

    provider = MicrosoftOAuth2TokenProvider(
        tenant_id="t", client_id="c", client_secret="s"
    )

    with pytest.raises(MicrosoftOAuth2TokenError, match="expired_token"):
        provider.generate_xoauth2_string("user@example.com")
