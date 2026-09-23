import logging

import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks

pytestmark = genmarks(
    "master_approle_mount", internal_logic=True, mounts=True, policies=True, secrets=True
)

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_overrides(master_approle_mount):  # pylint: disable=unused-argument
    return gen_master_opts(
        backend="file",
        issue="approle",
        params={
            "bind_secret_id": False,
            # "at least one constraint should be enabled on the role"
            # this should be quite secure :)
            "token_bound_cidrs": ["0.0.0.0/0"],
            "token_explicit_max_ttl": 1800,
            "token_num_uses": 0,
        },
        policies="salt_minion_{minion}",
    )


@pytest.mark.usefixtures("conn_cache_absent")
def test_minion_can_authenticate(salt_call_cli, caplog):
    """
    Test that the minion can run queries against Vault.
    The master impersonating the minion is already tested in the fixture setup
    (ext_pillar).
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
    assert "Minion AppRole does not require a secret ID" not in caplog.text
