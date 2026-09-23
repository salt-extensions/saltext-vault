import logging

import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks

pytestmark = genmarks(
    internal_logic=True,
    mounts=[[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
    policies=True,
)

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_overrides():
    # Ensure we test the SDB module's fallback for VaultAuthExpired on KV v1
    return gen_master_opts(params={"num_uses": 1})


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "sdbvault": {
            "patch": True,
        }
    }


def test_sdb_set(salt_call_cli, kv_mount):
    # Write to an empty path
    ret = salt_call_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{kv_mount}/test/test_sdb_patch/foo", value="bar"
    )
    assert ret.returncode == 0
    assert ret.data is True
    # Write to an existing path, this should not overwrite the previous key
    ret = salt_call_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{kv_mount}/test/test_sdb_patch/bar", value="baz"
    )
    assert ret.returncode == 0
    assert ret.data is True
    # Ensure all values are still present
    ret = salt_call_cli.run("sdb.get", uri=f"sdb://sdbvault/{kv_mount}/test/test_sdb_patch")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data == {"foo": "bar", "bar": "baz"}


def test_sdb_get_or_set_hash_single_use_token(salt_call_cli, kv_mount):
    """
    Test that sdb.get_or_set_hash works with uses=1.
    Salt core issue #60779
    """
    ret = salt_call_cli.run(
        "sdb.get_or_set_hash",
        f"sdb://sdbvault/{kv_mount}/test/sdb_get_or_set_hash/foo",
        10,
    )
    assert ret.returncode == 0
    result = ret.data
    assert result
    ret = salt_call_cli.run(
        "sdb.get_or_set_hash",
        f"sdb://sdbvault/{kv_mount}/test/sdb_get_or_set_hash/foo",
        10,
    )
    assert ret.returncode == 0
    assert ret.data
    assert ret.data == result
