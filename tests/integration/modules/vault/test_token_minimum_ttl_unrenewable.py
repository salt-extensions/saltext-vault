import logging
import time

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "file",
            },
            "issue": {
                "token": {
                    "params": {
                        "num_uses": 0,
                        "explicit_max_ttl": 180,
                    }
                }
            },
        }
    }


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "vault": {
            "auth": {
                "token_lifecycle": {
                    "minimum_ttl": 178,
                    "renew_increment": None,
                }
            }
        }
    }


def test_minimum_ttl_is_respected(salt_call_cli):
    """
    Test that a new token is requested when the current one does not
    fulfill minimum_ttl and cannot be renewed
    """
    # create token by looking it up
    ret = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.data
    assert ret.returncode == 0
    # wait
    time_before = time.time()
    while time.time() - time_before < 3:
        time.sleep(0.1)
    # reissue token by looking it up
    ret_new = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret_new.returncode == 0
    assert ret_new.data
    # ensure a new token was created, even though the previous one would have been
    # valid still
    assert ret_new.data["data"]["id"] != ret.data["data"]["id"]
