"""
Ensure ``sdb.set`` with ``patch: true`` never destroys existing sibling keys,
even when the token is not allowed to read the secret before patching it.

The KV v2 ``patch`` capability does not require ``read``, so a write/patch-only
policy is legitimate. Falling back to a full overwrite when the pre-patch read
fails silently drops all other keys in the secret.
"""

import logging

import pytest
import salt.exceptions

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_write
from tests.support.vault import vault_write_policy
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "_cleanup"),
    pytest.mark.parametrize(
        "secret_mounts",
        [[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
        indirect=True,
    ),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]

POLICY_NAME = "test-sdb-write-only"

WRITE_ONLY_POLICY = """\
path "secret/data/*" {
    capabilities = ["create", "update", "patch"]
}

path "secret-v1/*" {
    capabilities = ["create", "update"]
}
"""


@pytest.fixture(scope="module")
def write_only_token(container):  # pylint: disable=unused-argument
    vault_write_policy(POLICY_NAME, WRITE_ONLY_POLICY)
    try:
        res = vault_write("auth/token/create", policies=[POLICY_NAME], ttl="1h")
        yield res["auth"]["client_token"]
    finally:
        vault_delete_policy(POLICY_NAME)


@pytest.fixture(scope="module")
def minion_config_overrides(write_only_token, vault_port):
    return {
        "vault": {
            "auth": {
                "method": "token",
                "token": write_only_token,
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
    }


@pytest.fixture
def vault(loaders, secret_mounts):  # pylint: disable=unused-argument
    return loaders.sdb.vault


def test_write_only_token_can_write(vault, secret_mount):
    """
    Sanity check for this module's setup: the restricted token must be able
    to write secrets via the SDB module (including KV v2 path detection).
    Without this, the test below could pass vacuously.
    """
    path = f"{secret_mount}/write-only/sanity"
    assert vault.set(f"{path}/foo", "bar") is True
    assert vault_read_secret(path) == {"foo": "bar"}


def test_set_patch_write_only_does_not_destroy_secret(vault, secret_mount):
    """
    When patching is requested, but the current data cannot be read,
    existing keys in the secret must not be silently dropped by a
    fallback to a full overwrite.
    """
    path = f"{secret_mount}/write-only/testsecret"
    vault_write_secret(path, existing="important")
    try:
        res = vault.set(f"{path}/newkey", "newvalue", {"patch": True})
    except salt.exceptions.CommandExecutionError:
        res = False
    data = vault_read_secret(path)
    assert data is not None, "the whole secret was deleted"
    assert data.get("existing") == "important", "existing secret data was destroyed"
    if res:
        # If the operation reported success, the new key must have been written
        assert data.get("newkey") == "newvalue"
