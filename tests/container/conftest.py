# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures for container tests."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _mock_network_sandbox():
    """Disable network sandbox for container tests.

    The network module calls podman which isn't available in test
    environments. Return empty args so executor tests run without it.
    """
    mock_pm_class = MagicMock()
    mock_pm_instance = MagicMock()
    mock_pm_instance.start_task_proxy.return_value = None
    mock_pm_class.return_value = mock_pm_instance
    with patch("lib.container.executor.get_network_args", return_value=[]):
        yield
