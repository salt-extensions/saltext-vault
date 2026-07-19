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
                        "num_uses": 1,
                    }
                }
            },
        }
    }


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "sdbvault": {
            "patch": True,
        }
    }


def test_sdb_set(salt_call_cli, secret_mount):
    # Write to an empty path
    ret = salt_call_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb_patch/foo", value="bar"
    )
    assert ret.returncode == 0
    assert ret.data is True
    # Write to an existing path, this should not overwrite the previous key
    ret = salt_call_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb_patch/bar", value="baz"
    )
    assert ret.returncode == 0
    assert ret.data is True
    # Ensure all values are still present
    ret = salt_call_cli.run("sdb.get", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb_patch")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data == {"foo": "bar", "bar": "baz"}
