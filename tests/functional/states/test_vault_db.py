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
from tests.support.vault import vault_read
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
                "backend": "disk",
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        }
    }


@pytest.fixture(scope="module")
def mysql_image():
    version = "10.5"
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
def teststaticrole(mysql_container):
    return {
        "db_name": "testdb",
        "rotation_period": 86400,
        "username": mysql_container.mysql_user,
    }


@pytest.fixture
def testreissuerole():
    return {
        "default_ttl": 180,
        "max_ttl": 180,
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
def vault_db(states):
    try:
        yield states.vault_db
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


@pytest.fixture
def connargs(mysql_container, container_host_ref):
    return {
        "plugin": "mysql",
        "connection_url": f"{{{{username}}}}:{{{{password}}}}@tcp({container_host_ref}:{mysql_container.mysql_port})/",
        "allowed_roles": ["testrole", "teststaticrole", "testreissuerole"],
        "username": "root",
        "password": mysql_container.mysql_passwd,
        "rotate": False,
    }


@pytest.fixture
def roleargs():
    return {
        "connection": "testdb",
        "creation_statements": r"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';GRANT SELECT ON *.* TO '{{name}}'@'%';",
    }


@pytest.fixture
def roleargs_static(mysql_container):
    return {
        "connection": "testdb",
        "username": mysql_container.mysql_user,
        "rotation_period": 86400,
    }


def test_connection_present(vault_db, connargs):
    ret = vault_db.connection_present("testdb", **connargs)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "testdb"
    assert "testdb" in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_connection_present_no_changes(vault_db, connargs):
    ret = vault_db.connection_present("testdb", **connargs)
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("connection_setup")
def test_connection_present_allowed_roles_change(vault_db, connargs):
    connargs["allowed_roles"] = ["testrole", "teststaticrole", "newrole"]
    ret = vault_db.connection_present("testdb", **connargs)
    assert ret.result
    assert ret.changes
    assert "allowed_roles" in ret.changes
    assert (
        vault_read("database/config/testdb")["data"]["allowed_roles"] == connargs["allowed_roles"]
    )


@pytest.mark.usefixtures("connection_setup")
def test_connection_present_new_param(vault_db, connargs):
    connargs["username_template"] = r"{{random 20}}"
    ret = vault_db.connection_present("testdb", **connargs)
    assert ret.result
    assert ret.changes
    assert "username_template" in ret.changes
    assert (
        vault_read("database/config/testdb")["data"]["connection_details"]["username_template"]
        == connargs["username_template"]
    )


def test_connection_present_test_mode(vault_db, connargs):
    ret = vault_db.connection_present("testdb", test=True, **connargs)
    assert ret.result is None
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "testdb"
    assert "testdb" not in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_connection_absent(vault_db):
    ret = vault_db.connection_absent("testdb")
    assert ret.result
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == "testdb"
    assert "testdb" not in vault_list("database/config")


def test_connection_absent_no_changes(vault_db):
    ret = vault_db.connection_absent("testdb")
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("connection_setup")
def test_connection_absent_test_mode(vault_db):
    ret = vault_db.connection_absent("testdb", test=True)
    assert ret.result is None
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == "testdb"
    assert "testdb" in vault_list("database/config")


@pytest.mark.usefixtures("connection_setup")
def test_role_present(vault_db, roleargs):
    ret = vault_db.role_present("testrole", **roleargs)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "testrole"
    assert "testrole" in vault_list("database/roles")


@pytest.mark.usefixtures("roles_setup")
def test_role_present_no_changes(vault_db, roleargs):
    ret = vault_db.role_present("testrole", **roleargs)
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_role_present_no_changes_with_time_string(vault_db, roleargs):
    roleargs["default_ttl"] = "1h"
    ret = vault_db.role_present("testrole", **roleargs)
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_role_present_param_change(vault_db, roleargs):
    roleargs["default_ttl"] = 1337
    ret = vault_db.role_present("testrole", **roleargs)
    assert ret.result
    assert ret.changes
    assert "default_ttl" in ret.changes
    assert vault_read("database/roles/testrole")["data"]["default_ttl"] == 1337


@pytest.mark.usefixtures("connection_setup")
def test_role_present_test_mode(vault_db, roleargs):
    ret = vault_db.role_present("testrole", test=True, **roleargs)
    assert ret.result is None
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "testrole"
    assert "testrole" not in vault_list("database/roles")


@pytest.mark.usefixtures("connection_setup")
def test_static_role_present(vault_db, roleargs_static):
    ret = vault_db.static_role_present("teststaticrole", **roleargs_static)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "teststaticrole"
    assert "teststaticrole" in vault_list("database/static-roles")


@pytest.mark.usefixtures("role_static_setup")
def test_static_role_present_no_changes(vault_db, roleargs_static):
    ret = vault_db.static_role_present("teststaticrole", **roleargs_static)
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("role_static_setup")
def test_static_role_present_param_change(vault_db, roleargs_static):
    roleargs_static["rotation_period"] = 1337
    ret = vault_db.static_role_present("teststaticrole", **roleargs_static)
    assert ret.result
    assert ret.changes
    assert "rotation_period" in ret.changes
    assert vault_read("database/static-roles/teststaticrole")["data"]["rotation_period"] == 1337


@pytest.mark.usefixtures("connection_setup")
def test_static_role_present_test_mode(vault_db, roleargs_static):
    ret = vault_db.static_role_present("teststaticrole", test=True, **roleargs_static)
    assert ret.result is None
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "teststaticrole"
    assert "teststaticrole" not in vault_list("database/static-roles")


@pytest.mark.usefixtures("roles_setup")
def test_role_absent(vault_db):
    ret = vault_db.role_absent("testrole")
    assert ret.result
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == "testrole"
    assert "testrole" not in vault_list("database/roles")


@pytest.mark.usefixtures("role_static_setup")
def test_role_absent_static(vault_db):
    ret = vault_db.role_absent("teststaticrole", static=True)
    assert ret.result
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == "teststaticrole"
    assert "teststaticrole" not in vault_list("database/static-roles")


def test_role_absent_no_changes(vault_db):
    ret = vault_db.role_absent("testrole")
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_role_absent_test_mode(vault_db):
    ret = vault_db.role_absent("testrole", test=True)
    assert ret.result is None
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == "testrole"
    assert "testrole" in vault_list("database/roles")


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


@pytest.fixture(params=({},))
def _cached_creds(request, loaders, roles_setup):  # pylint: disable=unused-argument
    kwargs = {"name": "testrole", "cache": True}
    kwargs.update(request.param)
    ret = loaders.modules.vault_db.get_creds(**kwargs)
    assert ret
    assert "username" in ret
    assert "password" in ret
    assert loaders.modules.vault_db.list_cached()
    # We need to clear the context because in the test suite, the state modules
    # are running in a different one than the execution modules and the lease
    # has already been cached in the context of the execution module.
    # This means it does not pick up changes to the cached files, but we need
    # it to check changes in the tests.
    loaders.context.clear()
    return ret


@pytest.mark.usefixtures("roles_setup")
def test_creds_cached(testmode, vault_db, modules):
    ret = vault_db.creds_cached("testrole", test=testmode)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "new" in ret.changes
    assert "issued" in ret.comment
    assert ("would have" in ret.comment) is testmode
    assert bool(modules.vault_db.list_cached()) is not testmode


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_creds_cached_already_cached(testmode, vault_db, modules, _cached_creds):
    ret = vault_db.creds_cached("testrole", test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "already cached and valid" in ret.comment
    assert modules.vault_db.get_creds("testrole") == _cached_creds


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_creds_cached_already_cached_but_different_params(
    testmode, vault_db, modules, _cached_creds
):
    """
    Ensure changed parameters are reported without reissuing the
    lease, if possible.
    """
    ret = vault_db.creds_cached(
        "testrole",
        valid_for=800,
        renew_increment=120,
        revoke_delay=240,
        meta={"foo": "bar"},
        test=testmode,
    )
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "new" not in ret.changes
    assert "expiry" not in ret.changes
    assert ret.changes == {
        "min_ttl": {"old": None, "new": 800},
        "renew_increment": {"old": None, "new": 120},
        "revoke_delay": {"old": None, "new": 240},
        "meta": {"old": None, "new": {"foo": "bar"}},
    }
    assert "edited" in ret.comment
    assert ("would have" in ret.comment) is testmode
    assert modules.vault_db.get_creds("testrole") == _cached_creds
    new = modules.vault_db.list_cached()
    new = new[next(iter(new))]
    assert (new["min_ttl"] == 800) is not testmode
    assert (new["renew_increment"] == 120) is not testmode
    assert (new["revoke_delay"] == 240) is not testmode
    assert (new["meta"] == {"foo": "bar"}) is not testmode


def test_creds_cached_renew(testmode, vault_db, modules, _cached_creds):
    """
    Ensure renewed credentials are reported as such.
    """
    ret = vault_db.creds_cached("testrole", valid_for="2h", test=testmode)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "expiry" in ret.changes
    assert ret["changes"] == {"expiry": True, "min_ttl": {"old": None, "new": "2h"}}
    assert "renewed" in ret.comment
    assert ("would have" in ret.comment) is testmode
    if not testmode:
        assert modules.vault_db.get_creds("testrole") == _cached_creds
    # can't check the changes because requesting it would
    # apply the changes and listing the cache does not include the data


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("roles_setup", [["testreissuerole"]], indirect=True)
@pytest.mark.parametrize(
    "_cached_creds", ({"name": "testreissuerole", "valid_for": 185},), indirect=True
)
def test_creds_cached_reissue(testmode, vault_db, modules, _cached_creds):
    """
    Ensure reissued credentials are reported as such.
    """
    ret = vault_db.creds_cached("testreissuerole", valid_for=160, test=testmode)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "expiry" in ret.changes
    if testmode:
        # this is hard to detect in test mode TODO?
        assert "renewed/reissued" in ret.comment
        assert ret["changes"] == {"expiry": True, "min_ttl": {"old": 185, "new": 160}}
    else:
        assert "reissued" in ret.comment
        assert ret["changes"] == {
            "expiry": True,
            "min_ttl": {"old": 185, "new": 160},
            "reissued": True,
        }
    assert ("would have" in ret.comment) is testmode
    new = modules.vault_db.list_cached()
    new = new[next(iter(new))]
    assert (new["min_ttl"] == 160) is not testmode


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("roles_setup", [["testreissuerole"]], indirect=True)
@pytest.mark.parametrize(
    "_cached_creds", ({"name": "testreissuerole", "valid_for": 185},), indirect=True
)
def test_creds_cached_reissue_only(testmode, vault_db, loaders, _cached_creds):
    """
    Ensure that expired leases are recognized, even if valid_for has not been set.
    """
    old = loaders.modules.vault_db.list_cached()
    old = old[next(iter(old))]
    old.pop("expires_in")
    loaders.context.clear()  # to get updated information because of differing ctx
    ret = vault_db.creds_cached("testreissuerole", test=testmode)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "expiry" in ret.changes
    if testmode:
        # this is hard to detect in test mode TODO?
        assert "renewed/reissued" in ret.comment
        assert ret["changes"] == {"expiry": True}
    else:
        assert "reissued" in ret.comment
        assert ret["changes"] == {"expiry": True, "reissued": True}
    assert ("would have" in ret.comment) is testmode
    new = loaders.modules.vault_db.list_cached()
    new = new[next(iter(new))]
    new.pop("expires_in")
    assert (new == old) is testmode


def test_creds_uncached(testmode, vault_db, modules, _cached_creds):
    ret = vault_db.creds_uncached("testrole", test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "revoked" in ret.changes
    assert ("would have" in ret.comment) is testmode
    assert "revoked" in ret.comment
    after = modules.vault_db.list_cached()
    assert bool(after) is testmode


@pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True)
def test_creds_uncached_no_changes(testmode, vault_db):
    ret = vault_db.creds_uncached("testrole", test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "No matching credentials" in ret.comment
