from pathlib import Path

import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_db import connection_setup
from tests.functional.modules.test_vault_db import mysql_image
from tests.functional.modules.test_vault_db import role_args_common
from tests.functional.modules.test_vault_db import role_static_setup
from tests.functional.modules.test_vault_db import roles_setup
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
from tests.functional.modules.test_vault_db import testdb
from tests.functional.modules.test_vault_db import testreissuerole
from tests.functional.modules.test_vault_db import testrole
from tests.functional.modules.test_vault_db import teststaticrole

# pylint: enable=unused-import
from tests.support.helpers import WrapperFuncProxy
from tests.support.mysql import create_mysql_combo  # pylint: disable=unused-import
from tests.support.mysql import mysql_combo  # pylint: disable=unused-import
from tests.support.mysql import mysql_container  # pylint: disable=unused-import
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_revoke

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies"),
    pytest.mark.parametrize("secret_mounts", ("database",), indirect=True),
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
                    "database_admin",
                ],
            },
        }
    }


@pytest.fixture(autouse=True)
def vault_db(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    try:
        yield WrapperFuncProxy("vault_db", salt_ssh_cli)
    finally:
        # prevent dangling leases, which prevent disabling the secret engine
        assert vault_revoke("database/creds", prefix=True)
        if "testdb" in vault_list("database/config"):
            vault_delete("database/config/testdb")
            assert "testdb" not in vault_list("database/config")
        if "testrole" in vault_list("database/roles"):
            vault_delete("database/roles/testrole")
            assert "testrole" not in vault_list("database/roles")
        if "teststaticrole" in vault_list("database/static-roles"):
            vault_delete("database/static-roles/teststaticrole")
            assert "teststaticrole" not in vault_list("database/static-roles")


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
