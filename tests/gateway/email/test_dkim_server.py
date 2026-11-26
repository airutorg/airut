# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for reading the mail server's recorded DKIM result."""

import pytest

from airut.gateway.email.authres import parse_authentication_results
from airut.gateway.email.dkim import server_dkim_passes


def _results(header: str):
    return parse_authentication_results(header)


class TestServerDkimPasses:
    @pytest.mark.parametrize(
        "header",
        [
            "mx; dkim=pass header.d=example.com header.s=s",
            "mx; dkim=pass header.d=EXAMPLE.com",
            "mx; dkim=pass header.i=@example.com",
            'mx; dkim=pass header.i="user@example.com"',
            "mx; dkim=pass header.d=other.example;"
            " dkim=pass header.d=example.com",
        ],
    )
    def test_passes(self, header: str):
        assert server_dkim_passes(_results(header), "example.com") is True

    @pytest.mark.parametrize(
        "header",
        [
            "mx; dmarc=pass header.from=example.com",
            "mx; dkim=fail header.d=example.com",
            "mx; dkim=neutral header.d=example.com",
            "mx; dkim=pass header.d=other.example",
            "mx; dkim=pass header.d=sub.example.com",
            "mx; dkim-atps=pass header.d=example.com",
            "mx; dkim=pass header.d=example.com header.d=example.com",
            "mx; dkim=pass header.i=example.com",
            "mx; dkim=pass",
            "mx; dkim=pass header.d=example.Kom",
            # The Stalwart header of a forged signature: identity in a
            # quoted value, result not pass.
            'mx; dkim=neutral header.i="a dkim=pass b@example.com"',
        ],
    )
    def test_fails(self, header: str):
        assert server_dkim_passes(_results(header), "example.com") is False

    def test_non_ascii_domain_does_not_fold(self):
        results = _results("mx; dkim=pass header.d=example.Kom")
        assert server_dkim_passes(results, "example.kom") is False
