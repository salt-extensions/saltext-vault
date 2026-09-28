import pytest

from tests.common import CliFuncProxy
from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import kv_mount
from tests.common.fixtures.vault import versionable_secret
from tests.common.fixtures.vault import versioned_secret
from tests.common.fixtures.vault import versioned_secret_all_deleted
from tests.common.fixtures.vault import versioned_secret_deleted
from tests.functional.modules.test_vault_secret import test_delete_all_versions
from tests.functional.modules.test_vault_secret import test_delete_latest
from tests.functional.modules.test_vault_secret import test_delete_version
from tests.functional.modules.test_vault_secret import test_destroy_all_versions
from tests.functional.modules.test_vault_secret import test_destroy_latest
from tests.functional.modules.test_vault_secret import test_destroy_versions
from tests.functional.modules.test_vault_secret import test_list
from tests.functional.modules.test_vault_secret import test_patch
from tests.functional.modules.test_vault_secret import test_read
from tests.functional.modules.test_vault_secret import test_read_meta
from tests.functional.modules.test_vault_secret import test_read_version
from tests.functional.modules.test_vault_secret import test_restore
from tests.functional.modules.test_vault_secret import test_restore_all_versions
from tests.functional.modules.test_vault_secret import test_wipe
from tests.functional.modules.test_vault_secret import test_write

# pylint: enable=unused-import

pytestmark = genmarks(
    internal_logic=True,
    mounts=True,
    policies=True,
    secrets=True,
    kv_mount="secret",
)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk")


@pytest.fixture(scope="module")
def vault_secret(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault_secret


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }
