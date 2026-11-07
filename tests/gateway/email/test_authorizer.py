# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email sender authorization."""

from airut.gateway.email.authorization import SenderAuthorizer


AUTHORIZED = "authorized@example.com"


class TestAuthorizer:
    """Test sender authorization against allowed list."""

    def test_authorized_sender(self):
        authz = SenderAuthorizer([AUTHORIZED])
        assert authz.is_authorized(AUTHORIZED) is True

    def test_unauthorized_sender(self):
        authz = SenderAuthorizer([AUTHORIZED])
        assert authz.is_authorized("evil@hacker.com") is False

    def test_case_insensitive(self):
        authz = SenderAuthorizer(["USER@EXAMPLE.COM"])
        assert authz.is_authorized("user@example.com") is True

    def test_different_domain(self):
        authz = SenderAuthorizer([AUTHORIZED])
        assert authz.is_authorized("authorized@other.com") is False


class TestAuthorizerMultipleSenders:
    """Test authorization with multiple senders."""

    def test_multiple_exact_matches(self):
        authz = SenderAuthorizer(["alice@example.com", "bob@example.com"])
        assert authz.is_authorized("alice@example.com") is True
        assert authz.is_authorized("bob@example.com") is True
        assert authz.is_authorized("carol@example.com") is False

    def test_domain_wildcard(self):
        authz = SenderAuthorizer(["*@company.com"])
        assert authz.is_authorized("alice@company.com") is True
        assert authz.is_authorized("bob@company.com") is True
        assert authz.is_authorized("admin@company.com") is True
        assert authz.is_authorized("alice@other.com") is False

    def test_domain_wildcard_case_insensitive(self):
        """Pattern is case-insensitive, sender is always lowercase from auth."""
        authz = SenderAuthorizer(["*@COMPANY.COM"])
        # SenderAuthenticator always returns lowercase addresses
        assert authz.is_authorized("alice@company.com") is True
        assert authz.is_authorized("bob@company.com") is True

    def test_mixed_exact_and_wildcard(self):
        authz = SenderAuthorizer(
            [
                "external@partner.org",
                "*@company.com",
            ]
        )
        assert authz.is_authorized("alice@company.com") is True
        assert authz.is_authorized("external@partner.org") is True
        assert authz.is_authorized("internal@partner.org") is False

    def test_wildcard_does_not_match_subdomain(self):
        authz = SenderAuthorizer(["*@company.com"])
        # The domain must be exactly company.com
        assert authz.is_authorized("user@sub.company.com") is False

    def test_empty_list_rejects_all(self):
        authz = SenderAuthorizer([])
        assert authz.is_authorized("anyone@anywhere.com") is False

    def test_first_match_wins(self):
        """Authorization succeeds on first pattern match."""
        authz = SenderAuthorizer(["alice@example.com", "*@example.com"])
        # alice@example.com matches the exact pattern first
        assert authz.is_authorized("alice@example.com") is True
