import logging

import pytest

from tests.common.containers import genmarks

pytestmark = genmarks(internal_logic=True, mounts=True, policies=True, secrets=True)

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_defaults():
    # Ensure the master cannot issue anything
    return {}


def test_minion_can_authenticate(salt_call_cli):
    """
    Test that salt-call --local works with the Vault module.
    Salt core issue #58580
    """
    ret = salt_call_cli.run("--local", "vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
