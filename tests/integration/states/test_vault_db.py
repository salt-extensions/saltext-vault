from textwrap import dedent

import pytest
import salt.utils.beacons
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
    pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True),
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",
            },
        },
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


@pytest.fixture(params=[["testrole"]], autouse=True)
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


@pytest.fixture
def _lease_beacon(master, salt_call_cli):
    state_contents = dedent(
        """
        Vault lease is cached:
          vault_db.creds_cached:
            - name: testrole
            # When the lease is requested, it is valid for
            # at least this amount of time
            - valid_for: 900
            - beacon: true
            - beacon_interval: 300
            - check_server: true
            # The beacon ensures this min_ttl, must be >= valid_for if set
            - min_ttl: 1200
            - meta: other.state.or.something.else
    """
    )
    states = master.state_tree.base.temp_file("vault_lease.sls", state_contents)
    try:
        with states:
            yield "vault_lease"
    finally:
        beacon = "vault_lease_db.database.dynamic.testrole.default"
        salt_call_cli.run("beacons.delete", beacon)
        res = salt_call_cli.run("beacons.list", return_yaml=False)
        assert res.returncode == 0
        assert beacon not in res.data


@pytest.fixture
def _lease_beacon_absent(master, salt_call_cli):
    state_contents = dedent(
        """
        Vault lease is not cached:
          vault_db.creds_uncached:
            - name: testrole
            - beacon: true
    """
    )
    states = master.state_tree.base.temp_file("vault_lease_absent.sls", state_contents)
    try:
        with states:
            yield "vault_lease_absent"
    finally:
        beacon = "vault_lease_db.database.dynamic.testrole.default"
        salt_call_cli.run("beacons.delete", beacon)
        res = salt_call_cli.run("beacons.list", return_yaml=False)
        assert res.returncode == 0
        assert beacon not in res.data


def test_creds_cached_mod_beacon(salt_call_cli, _lease_beacon, _lease_beacon_absent):
    """
    Ensure beacons can be added as part of caching a lease.
    """
    ret = salt_call_cli.run("state.apply", _lease_beacon)
    assert ret.returncode == 0

    # Ensure the lease is actually cached
    ckey = "db.database.dynamic.testrole.default"
    ret = salt_call_cli.run("vault_db.list_cached")
    assert ret.returncode == 0
    assert ret.data
    assert ckey in ret.data

    # Ensure the beacon has been created with the correct config
    # The beacon modules have a really weird API.
    # Dynamic beacons are added as an "opts" item.
    # We need to explicitly disable YAML output to get the Python object.
    # Each beacon config param is its own single-item (dict) list.
    # Also, most beacon functions are prone to crash on even the most basic
    # unexpected circumstances. Oh well. They are nice when they work.
    ret = salt_call_cli.run(
        "beacons.list", return_yaml=False, include_pillar=False, include_opts=True
    )
    assert ret.returncode == 0
    assert ret.data
    beacons_config = {}
    for beacon, conf in ret.data.items():
        beacons_config[beacon] = salt.utils.beacons.list_to_dict(conf)
    beacon = "vault_lease_db.database.dynamic.testrole.default"
    assert beacon in beacons_config
    assert beacons_config[beacon] == {
        "beacon_module": "vault_lease",
        "interval": 300,
        "leases": ckey,
        "min_ttl": 1200,
        "meta": "other.state.or.something.else",
        "check_server": True,
    }
    # I wanted to test if the beacon is executed with a high min_ttl
    # and low interval, but it seems beacons are not scheduled at all here.
    ret = salt_call_cli.run("state.apply", _lease_beacon_absent)
    assert ret.returncode == 0

    # Now remove the lease and its beacon again
    ret = salt_call_cli.run("vault_db.list_cached")
    assert ret.returncode == 0
    assert ckey not in ret.data

    ret = salt_call_cli.run(
        "beacons.list", return_yaml=False, include_pillar=False, include_opts=True
    )
    assert ret.returncode == 0
    assert beacon not in ret.data
