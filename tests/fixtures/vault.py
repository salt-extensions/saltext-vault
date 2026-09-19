"""
Shared fixtures for the core vault test suites.
"""

from unittest.mock import patch

import pytest


@pytest.fixture
def _event():
    with patch("saltext.vault.utils.vault.factory._get_event", autospec=True) as evt:
        yield evt


@pytest.fixture
def approles_synced(
    salt_run_cli,
    minion,
):
    ret = salt_run_cli.run("vault.sync_approles", minion.id)
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_run_cli.run("vault.list_approles")
    assert ret.returncode == 0
    assert minion.id.lower() in ret.data
    return ret.data


@pytest.fixture(params=("secret", "secret-v1"))
def secret_mount(request):
    return request.param
