import logging

import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_delete_secret

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


@pytest.fixture(params=("secret", "secret-v1"))
def secret_mount(request):
    return request.param


@pytest.fixture
def _get_or_set_absent(secret_mount):
    secret = f"{secret_mount}/test/sdb_get_or_set_hash"
    vault_delete_secret(secret, metadata=True)
    try:
        yield
    finally:
        vault_delete_secret(secret, metadata=True)


@pytest.mark.usefixtures("_get_or_set_absent")
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
