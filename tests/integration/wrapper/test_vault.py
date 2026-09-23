import pytest

from tests.common import CliFuncProxy
from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import clean_policies
from tests.common.fixtures.vault import kv_mount
from tests.common.fixtures.vault import temp_policy
from tests.common.fixtures.vault import temp_policy_rules
from tests.common.fixtures.vault import versionable_secret
from tests.common.fixtures.vault import versioned_secret
from tests.common.fixtures.vault import versioned_secret_all_deleted
from tests.common.fixtures.vault import versioned_secret_deleted
from tests.functional.modules.vault.test_vault_kv import test_delete_secret_all_versions
from tests.functional.modules.vault.test_vault_kv import test_delete_secret_latest
from tests.functional.modules.vault.test_vault_kv import test_delete_secret_version
from tests.functional.modules.vault.test_vault_kv import test_destroy_secret_all_versions
from tests.functional.modules.vault.test_vault_kv import test_destroy_secret_latest
from tests.functional.modules.vault.test_vault_kv import test_destroy_secret_versions
from tests.functional.modules.vault.test_vault_kv import test_list_secrets as _test_list_secrets
from tests.functional.modules.vault.test_vault_kv import test_patch_raw
from tests.functional.modules.vault.test_vault_kv import test_patch_secret
from tests.functional.modules.vault.test_vault_kv import test_read_secret
from tests.functional.modules.vault.test_vault_kv import test_read_secret_meta
from tests.functional.modules.vault.test_vault_kv import test_read_secret_version
from tests.functional.modules.vault.test_vault_kv import test_restore_secret
from tests.functional.modules.vault.test_vault_kv import test_restore_secret_all_versions
from tests.functional.modules.vault.test_vault_kv import test_wipe_secret
from tests.functional.modules.vault.test_vault_kv import test_write_raw
from tests.functional.modules.vault.test_vault_kv import test_write_secret
from tests.functional.modules.vault.test_vault_policies import test_policies_list
from tests.functional.modules.vault.test_vault_policies import test_policy_delete
from tests.functional.modules.vault.test_vault_policies import test_policy_fetch
from tests.functional.modules.vault.test_vault_policies import test_policy_write

# pylint: enable=unused-import

pytestmark = genmarks(
    "clean_policies",
    internal_logic=True,
    mounts=True,
    policies=True,
    secrets=True,
    kv_mount="secret",
)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk", policies="policy_admin")


@pytest.fixture(scope="module")
def vault(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }


@pytest.mark.parametrize("keys_only", (True,))
def test_list_secrets(vault, keys_only, kv_mount):
    _test_list_secrets(vault, keys_only, kv_mount)


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
