import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.vault.test_vault_kv import existing_secret
from tests.functional.modules.vault.test_vault_kv import existing_secret_all_deleted
from tests.functional.modules.vault.test_vault_kv import existing_secret_deleted
from tests.functional.modules.vault.test_vault_kv import existing_secret_destroyed
from tests.functional.modules.vault.test_vault_kv import existing_secret_version
from tests.functional.modules.vault.test_vault_kv import test_delete_secret_all_versions
from tests.functional.modules.vault.test_vault_kv import test_delete_secret_latest
from tests.functional.modules.vault.test_vault_kv import test_delete_secret_version
from tests.functional.modules.vault.test_vault_kv import test_destroy_secret_all_versions
from tests.functional.modules.vault.test_vault_kv import test_destroy_secret_latest
from tests.functional.modules.vault.test_vault_kv import test_destroy_secret_versions
from tests.functional.modules.vault.test_vault_kv import test_list_secrets as _test_list_secrets
from tests.functional.modules.vault.test_vault_kv import test_patch_secret
from tests.functional.modules.vault.test_vault_kv import test_read_secret
from tests.functional.modules.vault.test_vault_kv import test_read_secret_meta
from tests.functional.modules.vault.test_vault_kv import test_read_secret_version
from tests.functional.modules.vault.test_vault_kv import test_restore_secret
from tests.functional.modules.vault.test_vault_kv import test_restore_secret_all_versions
from tests.functional.modules.vault.test_vault_kv import test_wipe_secret
from tests.functional.modules.vault.test_vault_kv import test_write_raw
from tests.functional.modules.vault.test_vault_kv import test_write_secret
from tests.functional.modules.vault.test_vault_policies import existing_policy
from tests.functional.modules.vault.test_vault_policies import policy_rules
from tests.functional.modules.vault.test_vault_policies import test_policies_list
from tests.functional.modules.vault.test_vault_policies import test_policy_delete
from tests.functional.modules.vault.test_vault_policies import test_policy_fetch
from tests.functional.modules.vault.test_vault_policies import test_policy_write

# pylint: enable=unused-import
from tests.support.helpers import WrapperFuncProxy
from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_list_policies

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies", "vault_secrets"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {
        "vault": {
            "cache": {
                "backend": "disk",
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "policy_admin",
                ],
            },
        }
    }


@pytest.fixture
def _policies_clean():
    try:
        yield
    finally:
        policies = vault_list_policies()
        for policy in ("functional_test_policy", "policy_write_test"):
            if policy in policies:
                vault_delete_policy(policy)


@pytest.fixture(scope="module")
def vault(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    return WrapperFuncProxy("vault", salt_ssh_cli)


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }


@pytest.fixture
def secret_mount():
    return "secret"


@pytest.mark.parametrize("keys_only", (True,))
def test_list_secrets(vault, keys_only, secret_mount):
    _test_list_secrets(vault, keys_only, secret_mount)


def test_clear_cache(salt_ssh_cli):
    """
    Ensure that the revocation client also respects Salt-SSH master opts
    and does not crash with InvalidConfig.
    """
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    token_id = ret.data["data"]["id"]
    ret = salt_ssh_cli.run("vault.clear_cache")
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data["data"]["id"] != token_id
