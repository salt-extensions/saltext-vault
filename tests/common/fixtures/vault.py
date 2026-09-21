"""
Shared fixtures for the core vault test suites.
"""

from unittest.mock import patch

import pytest


@pytest.fixture
def _event():
    with patch("saltext.vault.utils.vault.factory._get_event", autospec=True) as evt:
        yield evt


@pytest.fixture(params=("secret", "secret-v1"))
def secret_mount(request):
    return request.param
