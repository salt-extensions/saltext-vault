import time
from datetime import datetime
from pathlib import Path

import pytest
from saltfactories.utils import random_string

from tests.support.mysql import MySQLImage
from tests.support.mysql import create_mysql_combo  # pylint: disable=unused-import
from tests.support.mysql import mysql_combo  # pylint: disable=unused-import
from tests.support.mysql import mysql_container  # pylint: disable=unused-import
from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_list
from tests.support.vault import vault_revoke
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.usefixtures("vault_container_version"),
    pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True),
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


@pytest.fixture(scope="module")
def mysql_image():
    version = "10.3"
    return MySQLImage(
        name="mariadb",
        tag=version,
        container_id=random_string(f"mariadb-{version}-"),
    )


@pytest.fixture
def role_args_common():
    return {
        "db_name": "testdb",
        "creation_statements": r"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';GRANT SELECT ON *.* TO '{{name}}'@'%';",
    }


@pytest.fixture
def testrole():
    return {
        "default_ttl": 3600,
        "max_ttl": 86400,
    }


@pytest.fixture
def testreissuerole():
    return {
        "default_ttl": 180,
        "max_ttl": 180,
    }


@pytest.fixture
def teststaticrole(mysql_container):
    return {
        "db_name": "testdb",
        "rotation_period": 86400,
        "username": mysql_container.mysql_user,
    }


@pytest.fixture
def testdb(mysql_container, container_host_ref):
    return {
        "plugin_name": "mysql-database-plugin",
        "connection_url": f"{{{{username}}}}:{{{{password}}}}@tcp({container_host_ref}:{mysql_container.mysql_port})/",
        "allowed_roles": "testrole,teststaticrole,testreissuerole",
        "username": "root",
        "password": mysql_container.mysql_passwd,
    }


@pytest.fixture(scope="module", autouse=True)
def db_engine(vault_container_version):  # pylint: disable=unused-argument
    assert vault_enable_secret_engine("database")
    yield
    assert vault_disable_secret_engine("database")


@pytest.fixture
def connection_setup(testdb):
    try:
        vault_write("database/config/testdb", **testdb)
        assert "testdb" in vault_list("database/config")
        yield
    finally:
        # prevent dangling leases, which prevent disabling the secret engine
        assert vault_revoke("database/creds", prefix=True)
        if "testdb" in vault_list("database/config"):
            vault_delete("database/config/testdb")
            assert "testdb" not in vault_list("database/config")


@pytest.fixture(params=[["testrole"]])
def roles_setup(connection_setup, request, role_args_common):  # pylint: disable=unused-argument
    try:
        for role_name in request.param:
            role_args = request.getfixturevalue(role_name)
            role_args.update(role_args_common)
            vault_write(f"database/roles/{role_name}", **role_args)
            assert role_name in vault_list("database/roles")
        yield
    finally:
        for role_name in request.param:
            if role_name in vault_list("database/roles"):
                vault_delete(f"database/roles/{role_name}")
                assert role_name not in vault_list("database/roles")


@pytest.fixture
def role_static_setup(connection_setup, teststaticrole):  # pylint: disable=unused-argument
    role_name = "teststaticrole"
    try:
        vault_write(f"database/static-roles/{role_name}", **teststaticrole)
        assert role_name in vault_list("database/static-roles")
        yield
    finally:
        if role_name in vault_list("database/static-roles"):
            vault_delete(f"database/static-roles/{role_name}")
            assert role_name not in vault_list("database/static-roles")


@pytest.fixture(autouse=True)
def _cleanup():
    try:
        yield
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


@pytest.mark.usefixtures("connection_setup")
def test_list_connections(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.list_connections")
    assert ret.returncode == 0
    assert ret.data == ["testdb"]


@pytest.mark.usefixtures("connection_setup")
def test_fetch_connection(salt_ssh_cli, testdb):
    ret = salt_ssh_cli.run("vault_db.fetch_connection", "testdb")
    assert ret.returncode == 0
    for var, val in testdb.items():
        if var == "password":
            continue
        if var in ["connection_url", "username"]:
            assert var in ret.data["connection_details"]
            assert ret.data["connection_details"][var] == val
        else:
            assert var in ret.data
            if var == "allowed_roles":
                assert ret.data[var] == list(val.split(","))
            else:
                assert ret.data[var] == val


@pytest.mark.usefixtures("testdb")
def test_write_connection(salt_ssh_cli, mysql_container, container_host_ref):
    args = {
        "plugin": "mysql",
        "connection_url": f"{{{{username}}}}:{{{{password}}}}@tcp({container_host_ref}:{mysql_container.mysql_port})/",
        "allowed_roles": ["testrole", "teststaticrole"],
        "username": "root",
        "password": mysql_container.mysql_passwd,
        # Can't rotate because we wouldn't know the new one for further tests
        "rotate": False,
    }
    ret = salt_ssh_cli.run("vault_db.write_connection", "testdb", **args)
    assert ret.returncode == 0
    assert "testdb" in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_update_connection(salt_ssh_cli):
    """
    Ensure missing kwargs are not enforced on updates.
    """
    ret = salt_ssh_cli.run(
        "vault_db.write_connection", "testdb", "mysql", allowed_roles=["*"], rotate=False
    )
    assert ret.returncode == 0
    assert ret.data is True


@pytest.mark.usefixtures("connection_setup")
def test_delete_connection(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.delete_connection", "testdb")
    assert ret.returncode == 0
    assert ret.data
    assert "testdb" not in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_reset_connection(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.reset_connection", "testdb")
    assert ret.returncode == 0
    assert ret.data


@pytest.mark.usefixtures("roles_setup")
def test_list_roles(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.list_roles")
    assert ret.returncode == 0
    assert ret.data == ["testrole"]


@pytest.mark.usefixtures("role_static_setup")
def test_list_roles_static(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.list_roles", static=True)
    assert ret.returncode == 0
    assert ret.data == ["teststaticrole"]


@pytest.mark.usefixtures("roles_setup")
def test_fetch_role(salt_ssh_cli, testrole):
    ret = salt_ssh_cli.run("vault_db.fetch_role", "testrole")
    assert ret.returncode == 0
    assert ret.data
    for var, val in testrole.items():
        assert var in ret.data
        if var == "creation_statements":
            assert ret.data[var] == [val]
        else:
            assert ret.data[var] == val


@pytest.mark.usefixtures("role_static_setup")
def test_fetch_role_static(salt_ssh_cli, teststaticrole):
    ret = salt_ssh_cli.run("vault_db.fetch_role", "teststaticrole", static=True)
    assert ret.returncode == 0
    assert ret.data
    for var, val in teststaticrole.items():
        assert var in ret.data
        assert ret.data[var] == val


@pytest.mark.usefixtures("connection_setup")
def test_write_role(salt_ssh_cli):
    args = {
        "connection": "testdb",
        "creation_statements": r"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';GRANT SELECT ON *.* TO '{{name}}'@'%';",
    }
    ret = salt_ssh_cli.run("vault_db.write_role", "testrole", **args)
    assert ret.returncode == 0
    assert ret.data
    assert "testrole" in vault_list("database/roles")


@pytest.mark.usefixtures("connection_setup")
def test_write_static_role(salt_ssh_cli, mysql_container):
    args = {
        "connection": "testdb",
        "username": mysql_container.mysql_user,
        "rotation_period": 86400,
    }
    ret = salt_ssh_cli.run("vault_db.write_static_role", "teststaticrole", **args)
    assert ret.returncode == 0
    assert ret.data
    assert "teststaticrole" in vault_list("database/static-roles")


@pytest.mark.usefixtures("roles_setup")
def test_delete_role(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.delete_role", "testrole")
    assert ret.returncode == 0
    assert ret.data
    assert "testrole" not in vault_list("database/roles")


@pytest.mark.usefixtures("role_static_setup")
def test_delete_role_static(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.delete_role", "teststaticrole", static=True)
    assert ret.returncode == 0
    assert ret.data
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


@pytest.mark.usefixtures("roles_setup")
def test_get_creds(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.get_creds", "testrole", cache=False)
    assert ret.returncode == 0
    assert "username" in ret.data
    assert "password" in ret.data


@pytest.mark.usefixtures("role_static_setup")
def test_get_creds_static(salt_ssh_cli, teststaticrole):
    ret = salt_ssh_cli.run("vault_db.get_creds", "teststaticrole", static=True, cache=False)
    assert ret.returncode == 0
    assert "username" in ret.data
    assert "password" in ret.data
    assert ret.data["username"] == teststaticrole["username"]


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


@pytest.mark.usefixtures("_cached_creds")
def test_clear_cached(salt_ssh_cli):
    list_cached = salt_ssh_cli.run("vault_db.list_cached")
    assert list_cached.returncode == 0
    assert list_cached.data
    clear_cached = salt_ssh_cli.run("vault_db.clear_cached")
    assert clear_cached.returncode == 0
    assert clear_cached.data is True
    list_cached_new = salt_ssh_cli.run("vault_db.list_cached")
    assert list_cached_new.returncode == 0
    assert not list_cached_new.data


@pytest.mark.usefixtures("_cached_creds")
def test_list_cached(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.list_cached")
    assert ret.returncode == 0
    ckey = "db.database.dynamic.testrole.default"
    assert ret.data
    assert ckey in ret.data
    assert not ret.data[ckey]["expired"]
    assert ret.data[ckey]["expires_in"] > 3590
    assert "data" not in ret.data[ckey]
    now = datetime.now().astimezone()
    # this might fail if this test runs juuust before midnight
    assert ret.data[ckey]["creation_time"].startswith(now.strftime("%Y-%m-%d"))
    # I hope you have something better to do during New Year's Eve
    assert ret.data[ckey]["expire_time"].startswith(now.strftime("%Y-"))
    for val in ("creation_time", "expire_time"):
        assert ret.data[ckey][val].endswith(now.strftime(" %Z"))


@pytest.mark.usefixtures("_cached_creds")
def test_renew_cached(salt_ssh_cli):
    curr = salt_ssh_cli.run("vault_db.list_cached")
    assert curr.returncode == 0
    curr = curr.data
    ckey = "db.database.dynamic.testrole.default"
    assert curr
    assert ckey in curr
    time.sleep(3)
    renew_cached = salt_ssh_cli.run("vault_db.renew_cached")
    assert renew_cached.returncode == 0
    assert renew_cached.data is True
    new = salt_ssh_cli.run("vault_db.list_cached")
    assert new.returncode == 0
    assert new.data[ckey]["expire_time"] != curr[ckey]["expire_time"]


@pytest.mark.usefixtures("role_static_setup")
def test_rotate_static_role(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_db.get_creds", "teststaticrole", static=True, cache=False)
    assert ret.returncode == 0
    assert ret.data
    old_pw = ret.data["password"]
    ret = salt_ssh_cli.run("vault_db.rotate_static_role", "teststaticrole")
    assert ret.returncode == 0
    assert ret.data
    ret = salt_ssh_cli.run("vault_db.get_creds", "teststaticrole", static=True, cache=False)
    assert ret.returncode == 0
    assert ret.data["password"] != old_pw
