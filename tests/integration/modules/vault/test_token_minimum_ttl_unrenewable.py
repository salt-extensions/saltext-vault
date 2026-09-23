import logging
import time

import pytest

from tests.common import gen_master_opts
from tests.common import gen_minion_opts
from tests.common.containers import genmarks

log = logging.getLogger(__name__)

pytestmark = genmarks(internal_logic=True, policies=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="file", params={"num_uses": 0, "explicit_max_ttl": 180})


@pytest.fixture(scope="module")
def minion_config_overrides():
    return gen_minion_opts(
        token_lifecycle={
            "minimum_ttl": 178,
            "renew_increment": None,
        }
    )


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
