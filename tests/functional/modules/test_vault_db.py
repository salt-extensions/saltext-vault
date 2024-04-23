import logging
import time
from datetime import datetime

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
    pytest.mark.slow_test,
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.usefixtures("vault_container_version"),
]


@pytest.fixture(scope="module")
def minion_config_overrides(vault_port):
    return {
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_creds
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
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


@pytest.fixture
def vault_db(modules):
    try:
        yield modules.vault_db
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
def test_list_connections(vault_db):
    ret = vault_db.list_connections()
    assert ret == ["testdb"]


def test_list_connections_empty(vault_db):
    ret = vault_db.list_connections()
    assert ret == []


@pytest.mark.usefixtures("connection_setup")
def test_fetch_connection(vault_db, testdb):
    ret = vault_db.fetch_connection("testdb")
    assert ret
    for var, val in testdb.items():
        if var == "password":
            continue
        if var in ["connection_url", "username"]:
            assert var in ret["connection_details"]
            assert ret["connection_details"][var] == val
        else:
            assert var in ret
            if var == "allowed_roles":
                assert ret[var] == list(val.split(","))
            else:
                assert ret[var] == val


@pytest.mark.usefixtures("testdb")
def test_fetch_connection_empty(vault_db):
    ret = vault_db.fetch_connection("foobar")
    assert ret is None


@pytest.mark.usefixtures("testdb")
def test_write_connection(vault_db, mysql_container, container_host_ref):
    args = {
        "plugin": "mysql",
        "connection_url": f"{{{{username}}}}:{{{{password}}}}@tcp({container_host_ref}:{mysql_container.mysql_port})/",
        "allowed_roles": ["testrole", "teststaticrole"],
        "username": "root",
        "password": mysql_container.mysql_passwd,
        # Can't rotate because we wouldn't know the new one for further tests
        "rotate": False,
    }
    ret = vault_db.write_connection("testdb", **args)
    assert ret
    assert "testdb" in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_update_connection(vault_db):
    """
    Ensure missing kwargs are not enforced on updates.
    """
    assert vault_db.write_connection("testdb", "mysql", allowed_roles=["*"], rotate=False) is True


@pytest.mark.usefixtures("connection_setup")
def test_delete_connection(vault_db):
    ret = vault_db.delete_connection("testdb")
    assert ret
    assert "testdb" not in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_reset_connection(vault_db):
    ret = vault_db.reset_connection("testdb")
    assert ret


@pytest.mark.usefixtures("roles_setup")
def test_list_roles(vault_db):
    ret = vault_db.list_roles()
    assert ret == ["testrole"]


def test_list_roles_empty(vault_db):
    ret = vault_db.list_roles()
    assert ret == []


@pytest.mark.usefixtures("role_static_setup")
def test_list_roles_static(vault_db):
    ret = vault_db.list_roles(static=True)
    assert ret == ["teststaticrole"]


@pytest.mark.usefixtures("roles_setup")
def test_fetch_role(vault_db, testrole):
    ret = vault_db.fetch_role("testrole")
    assert ret
    for var, val in testrole.items():
        assert var in ret
        if var == "creation_statements":
            assert ret[var] == [val]
        else:
            assert ret[var] == val


@pytest.mark.usefixtures("role_static_setup")
def test_fetch_role_static(vault_db, teststaticrole):
    ret = vault_db.fetch_role("teststaticrole", static=True)
    assert ret
    for var, val in teststaticrole.items():
        assert var in ret
        assert ret[var] == val


def test_fetch_role_empty(vault_db):
    ret = vault_db.fetch_role("foobar")
    assert ret is None


@pytest.mark.usefixtures("connection_setup")
def test_write_role(vault_db):
    args = {
        "connection": "testdb",
        "creation_statements": r"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';GRANT SELECT ON *.* TO '{{name}}'@'%';",
    }
    ret = vault_db.write_role("testrole", **args)
    assert ret
    assert "testrole" in vault_list("database/roles")


@pytest.mark.usefixtures("connection_setup")
def test_write_static_role(vault_db, mysql_container):
    args = {
        "connection": "testdb",
        "username": mysql_container.mysql_user,
        "rotation_period": 86400,
    }
    ret = vault_db.write_static_role("teststaticrole", **args)
    assert ret
    assert "teststaticrole" in vault_list("database/static-roles")


@pytest.mark.usefixtures("roles_setup")
def test_delete_role(vault_db):
    ret = vault_db.delete_role("testrole")
    assert ret
    assert "testrole" not in vault_list("database/roles")


@pytest.mark.usefixtures("role_static_setup")
def test_delete_role_static(vault_db):
    ret = vault_db.delete_role("teststaticrole", static=True)
    assert ret
    assert "teststaticrole" not in vault_list("database/static-roles")


@pytest.fixture(params=({},))
def _cached_creds(vault_db, roles_setup, request):  # pylint: disable=unused-argument
    data = request.param.copy()
    role = data.pop("role", "testrole")
    ret = vault_db.get_creds(role, cache=True, **data)
    assert ret
    assert "username" in ret
    assert "password" in ret
    return ret


@pytest.mark.usefixtures("roles_setup")
def test_get_creds(vault_db):
    ret = vault_db.get_creds("testrole", cache=False)
    assert ret
    assert "username" in ret
    assert "password" in ret


@pytest.mark.usefixtures("role_static_setup")
def test_get_creds_static(vault_db, teststaticrole):
    ret = vault_db.get_creds("teststaticrole", static=True, cache=False)
    assert ret
    assert "username" in ret
    assert "password" in ret
    assert ret["username"] == teststaticrole["username"]


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_get_creds_cached(vault_db, _cached_creds):
    ret_new = vault_db.get_creds("testrole", cache=True)
    assert ret_new
    assert "username" in ret_new
    assert "password" in ret_new
    assert ret_new["username"] == _cached_creds["username"]
    assert ret_new["password"] == _cached_creds["password"]


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
@pytest.mark.usefixtures("roles_setup")
def test_get_creds_cached__multiple(vault_db):
    ret = vault_db.get_creds("testrole", cache="one")
    assert ret
    assert "username" in ret
    assert "password" in ret
    ret_new = vault_db.get_creds("testrole", cache="two")
    assert ret_new
    assert "username" in ret_new
    assert "password" in ret_new
    assert ret_new["username"] != ret["username"]
    assert ret_new["password"] != ret["password"]
    assert vault_db.get_creds("testrole", cache="one") == ret
    assert vault_db.get_creds("testrole", cache="two") == ret_new


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("roles_setup", [["testreissuerole"]], indirect=True)
@pytest.mark.parametrize(
    "_cached_creds", ({"role": "testreissuerole", "valid_for": 180},), indirect=True
)
def test_get_creds_cached_valid_for_reissue(vault_db, testreissuerole, _cached_creds):
    """
    Test that valid cached credentials that do not fulfill valid_for
    and cannot be renewed as requested are reissued
    """
    # 3 seconds because of leeway in lease validity check after renewals
    time.sleep(3)
    ret_new = vault_db.get_creds(
        "testreissuerole", cache=True, valid_for=testreissuerole["default_ttl"]
    )
    assert ret_new
    assert "username" in ret_new
    assert "password" in ret_new
    assert ret_new["username"] != _cached_creds["username"]
    assert ret_new["password"] != _cached_creds["password"]


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("roles_setup", [["testreissuerole"]], indirect=True)
@pytest.mark.parametrize(
    "_cached_creds", ({"role": "testreissuerole", "valid_for": 180},), indirect=True
)
def test_get_creds_cached_with_cached_min_ttl(vault_db, _cached_creds):
    """
    Test that a cached ``min_ttl`` (``valid_for``) is respected at a minimum.
    """
    # 3 seconds because of leeway in lease validity check after renewals
    time.sleep(3)
    ret_new = vault_db.get_creds("testreissuerole", cache=True, valid_for=5)
    assert ret_new
    assert "username" in ret_new
    assert "password" in ret_new
    assert ret_new["username"] != _cached_creds["username"]
    assert ret_new["password"] != _cached_creds["password"]


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
@pytest.mark.parametrize(
    "_cached_creds,new",
    (
        ({"valid_for": 240}, {"valid_for": 360}),
        ({"revoke_delay": 240}, {"revoke_delay": 15}),
        ({"renew_increment": 240}, {"renew_increment": 15}),
        ({"meta": {"foo": "bar"}}, {"meta": {"bar": "baz"}}),
    ),
    indirect=("_cached_creds",),
)
@pytest.mark.parametrize("warn", (False, True))
def test_get_creds_cached_changed_lifecycle(vault_db, _cached_creds, new, warn, caplog):
    """
    Test that changed lifecycle attributes are warned about when
    _warn_about_attr_change is not set only.

    This is a precaution for the following situation:
    * A state manages the cached creds with wanted lifecycle attributes
    * During template rendering, the creds are requested with different
      lifecycle attributes.
    """
    with caplog.at_level(logging.WARNING):
        ret_new = vault_db.get_creds("testrole", cache=True, **new, _warn_about_attr_change=warn)
    assert ret_new
    assert "username" in ret_new
    assert "password" in ret_new
    assert ret_new["username"] == _cached_creds["username"]
    assert ret_new["password"] == _cached_creds["password"]
    assert ("changed lifecycle attributes" in caplog.text) is warn


@pytest.mark.usefixtures("_cached_creds")
@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_clear_cached(vault_db):
    assert vault_db.list_cached()
    assert vault_db.clear_cached() is True
    assert not vault_db.list_cached()


@pytest.mark.usefixtures("_cached_creds")
@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_list_cached(vault_db):
    ret = vault_db.list_cached()
    ckey = "db.database.dynamic.testrole.default"
    assert ret
    assert ckey in ret
    assert not ret[ckey]["expired"]
    assert ret[ckey]["expires_in"] > 3590
    assert "data" not in ret[ckey]
    now = datetime.now().astimezone()
    # this might fail if this test runs juuust before midnight
    assert ret[ckey]["creation_time"].startswith(now.strftime("%Y-%m-%d"))
    # I hope you have something better to do during New Year's Eve
    assert ret[ckey]["expire_time"].startswith(now.strftime("%Y-"))
    for val in ("creation_time", "expire_time"):
        assert ret[ckey][val].endswith(now.strftime(" %Z"))


@pytest.mark.usefixtures("_cached_creds")
@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_renew_cached(vault_db):
    curr = vault_db.list_cached()
    ckey = "db.database.dynamic.testrole.default"
    assert curr
    assert ckey in curr
    time.sleep(3)
    assert vault_db.renew_cached() is True
    new = vault_db.list_cached()
    assert new[ckey]["expire_time"] != curr[ckey]["expire_time"]


@pytest.mark.usefixtures("role_static_setup")
def test_rotate_static_role(vault_db):
    ret = vault_db.get_creds("teststaticrole", static=True, cache=False)
    assert ret
    old_pw = ret["password"]
    ret = vault_db.rotate_static_role("teststaticrole")
    assert ret
    ret = vault_db.get_creds("teststaticrole", static=True, cache=False)
    assert ret
    assert ret["password"] != old_pw
