import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_approle import approle_auth
from tests.common.fixtures.vault_approle import roles_setup
from tests.common.fixtures.vault_approle import testrole
from tests.functional.modules.test_vault_approle import _cached_approle
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

# pylint: enable=unused-import
from tests.support.vault import vault_delete

pytestmark = genmarks(internal_logic=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    # ensure a persistent cache is available for get_secret_id
    return gen_master_opts(backend="disk")


@pytest.fixture
def vault_approle(runners, approle_auth):  # pylint: disable=unused-argument
    try:
        yield runners.vault_approle
    finally:
        vault_delete(f"auth/{approle_auth}/role/testrole")
