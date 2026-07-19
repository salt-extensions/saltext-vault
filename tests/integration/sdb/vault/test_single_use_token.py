import logging

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts"),
    pytest.mark.parametrize(
        "secret_mounts",
        [[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
        indirect=True,
    ),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "issue": {
                "token": {
                    "params": {
                        # Ensure we test the SDB module's fallback for VaultAuthExpired on KV v1
                        "num_uses": 1,
                    }
                }
            },
        }
    }


def test_sdb_get_or_set_hash_single_use_token(salt_call_cli, secret_mount):
    """
    Test that sdb.get_or_set_hash works with uses=1.
    Salt core issue #60779
    """
    ret = salt_call_cli.run(
        "sdb.get_or_set_hash",
        f"sdb://sdbvault/{secret_mount}/test/sdb_get_or_set_hash/foo",
        10,
    )
    assert ret.returncode == 0
    result = ret.data
    assert result
    ret = salt_call_cli.run(
        "sdb.get_or_set_hash",
        f"sdb://sdbvault/{secret_mount}/test/sdb_get_or_set_hash/foo",
        10,
    )
    assert ret.returncode == 0
    assert ret.data
    assert ret.data == result
