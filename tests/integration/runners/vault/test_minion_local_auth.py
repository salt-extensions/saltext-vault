import logging

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies", "vault_secrets"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


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
