import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.mysql import mysql_container
from tests.common.fixtures.vault_db import clean_db_mount
from tests.common.fixtures.vault_db import connection_setup
from tests.common.fixtures.vault_db import role_args_common
from tests.common.fixtures.vault_db import role_static_setup
from tests.common.fixtures.vault_db import roles_setup
from tests.common.fixtures.vault_db import testdb
from tests.common.fixtures.vault_db import testreissuerole
from tests.common.fixtures.vault_db import testrole
from tests.common.fixtures.vault_db import teststaticrole
from tests.functional.modules.test_vault_db import _cached_creds
from tests.functional.modules.test_vault_db import test_clear_cached
from tests.functional.modules.test_vault_db import test_delete_connection
from tests.functional.modules.test_vault_db import test_delete_role
from tests.functional.modules.test_vault_db import test_delete_role_static
from tests.functional.modules.test_vault_db import test_fetch_connection
from tests.functional.modules.test_vault_db import test_fetch_role
from tests.functional.modules.test_vault_db import test_fetch_role_static
from tests.functional.modules.test_vault_db import test_get_creds
from tests.functional.modules.test_vault_db import test_get_creds_cached
from tests.functional.modules.test_vault_db import test_get_creds_static
from tests.functional.modules.test_vault_db import test_list_cached
from tests.functional.modules.test_vault_db import test_list_connections
from tests.functional.modules.test_vault_db import test_list_roles
from tests.functional.modules.test_vault_db import test_list_roles_static
from tests.functional.modules.test_vault_db import test_renew_cached
from tests.functional.modules.test_vault_db import test_reset_connection
from tests.functional.modules.test_vault_db import test_rotate_static_role
from tests.functional.modules.test_vault_db import test_update_connection
from tests.functional.modules.test_vault_db import test_write_connection
from tests.functional.modules.test_vault_db import test_write_role
from tests.functional.modules.test_vault_db import test_write_static_role

# pylint: enable=unused-import

pytestmark = genmarks(internal_logic=True, mounts="database")


@pytest.fixture(scope="module")
def master_config_overrides():
    # ensure a persistent cache is available for get_creds
    return gen_master_opts(backend="disk")


@pytest.fixture
def vault_db(runners, clean_db_mount):  # pylint: disable=unused-argument
    return runners.vault_db
