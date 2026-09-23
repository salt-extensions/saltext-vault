from pathlib import Path

import pytest

from tests.common import CliFuncProxy
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
from tests.functional.modules.test_vault_db import test_clear_cached
from tests.functional.modules.test_vault_db import test_delete_connection
from tests.functional.modules.test_vault_db import test_delete_role
from tests.functional.modules.test_vault_db import test_delete_role_static
from tests.functional.modules.test_vault_db import test_fetch_connection
from tests.functional.modules.test_vault_db import test_fetch_role
from tests.functional.modules.test_vault_db import test_fetch_role_static
from tests.functional.modules.test_vault_db import test_get_creds
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

pytestmark = genmarks(internal_logic=True, mounts="database", policies=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk", policies="database_admin")


@pytest.fixture(autouse=True)
def vault_db(salt_ssh_cli, vault_policies, clean_db_mount):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault_db


@pytest.fixture(params=({},))
def _cached_creds(salt_ssh_cli, roles_setup, request):  # pylint: disable=unused-argument
    data = request.param.copy()
    role = data.pop("role", "testrole")
    ret = salt_ssh_cli.run("vault_db.get_creds", role, cache=True, **data)
    assert ret.returncode == 0
    assert "username" in ret.data
    assert "password" in ret.data
    yield ret.data
    # We need to get rid of the cached data since the lease is
    # revoked after each test and we don't run with check_server.
    ret = salt_ssh_cli.run("vault_db.clear_cached")
    assert ret.returncode == 0
    assert ret.data is True


def test_get_creds_cached(salt_ssh_cli, _cached_creds, master):
    ret_new = salt_ssh_cli.run("vault_db.get_creds", "testrole", cache=True)
    assert ret_new.returncode == 0
    assert "username" in ret_new.data
    assert "password" in ret_new.data
    assert ret_new.data["username"] == _cached_creds["username"]
    assert ret_new.data["password"] == _cached_creds["password"]
    # Ensure we're caching to the master per-minion cache,
    # not the Salt-SSH minion one. This allows master-side
    # renewals for Salt-SSH minions via an engine module.
    cachedir = Path(master.config["cachedir"])
    cache_file = (
        cachedir
        / "minions"
        / "localhost"
        / "vault"
        / "connection"
        / "session"
        / "leases"
        / "db.database.dynamic.testrole.default.p"
    )
    assert cache_file.exists()
