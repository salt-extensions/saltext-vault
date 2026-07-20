import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_approle import _cached_approle
from tests.functional.modules.test_vault_approle import approle_auth
from tests.functional.modules.test_vault_approle import roles_setup
from tests.functional.modules.test_vault_approle import test_clear_cached
from tests.functional.modules.test_vault_approle import test_delete
from tests.functional.modules.test_vault_approle import test_destroy_secret_id
from tests.functional.modules.test_vault_approle import test_get_role_id
from tests.functional.modules.test_vault_approle import test_get_secret_id
from tests.functional.modules.test_vault_approle import test_get_secret_id_cached
from tests.functional.modules.test_vault_approle import test_get_secret_id_cached_destroyed
from tests.functional.modules.test_vault_approle import test_get_secret_id_wrapped
from tests.functional.modules.test_vault_approle import test_list
from tests.functional.modules.test_vault_approle import test_list_cached
from tests.functional.modules.test_vault_approle import test_lookup_secret_id
from tests.functional.modules.test_vault_approle import test_read
from tests.functional.modules.test_vault_approle import test_write
from tests.functional.modules.test_vault_approle import testreissuerole
from tests.functional.modules.test_vault_approle import testrole

# pylint: enable=unused-import
from tests.support.helpers import WrapperFuncProxy

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_secret_id
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "approle_admin",
                ],
            },
        }
    }


@pytest.fixture(scope="module")
def vault_approle(salt_ssh_cli, approle_auth, vault_policies):  # pylint: disable=unused-argument
    return WrapperFuncProxy("vault_approle", salt_ssh_cli)
