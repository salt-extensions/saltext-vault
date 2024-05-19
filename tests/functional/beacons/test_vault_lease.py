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
    pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True),
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
        "max_ttl": 7200,
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


@pytest.fixture(params=({},))
def lease_creation_params(request):
    defaults = {"name": "testrole"}
    defaults.update(request.param)
    return defaults


@pytest.fixture(params=(False,))
def _multi_lease(request):
    return request.param


@pytest.fixture(params=({},))
def beacon_config(request, _multi_lease, existing_lease):
    req = request.param.copy()
    datatype = req.pop("leases_type", str if not _multi_lease else list)
    if _multi_lease:
        alt_lease = request.getfixturevalue("existing_alt_lease")
    data = {}
    if datatype is str:
        data["leases"] = existing_lease
    elif datatype is list:
        data["leases"] = [existing_lease]
        if _multi_lease:
            data["leases"].append(alt_lease)
    else:
        data["leases"] = {existing_lease: req.pop("per_lease_params", {})}
        if _multi_lease:
            data["leases"][alt_lease] = req.pop("per_lease_alt_params", {})
    data.update(req)
    return [{k: v} for k, v in data.items()]


@pytest.fixture
def existing_lease(
    roles_setup, lease_creation_params, vault_db, loaders
):  # pylint: disable=unused-argument
    ckey = ".".join(
        [
            "db",
            lease_creation_params.get("mount", "database"),
            "dynamic",
            lease_creation_params["name"],
            lease_creation_params.get("cache", "default"),
        ]
    )
    lease = vault_db.get_creds(**lease_creation_params)
    assert lease
    # We need to clear the context because in the test suite, the beacon modules
    # are running in a different one than the execution modules and the lease
    # has already been cached in the context of the execution module.
    # This means it does not pick up changes to the cached files, but we need
    # it to check changes in the tests.
    loaders.context.clear()
    return ckey  # revocation is handled in vault_db


@pytest.fixture(params=({"cache": "alt"},))
def existing_alt_lease(
    request, roles_setup, lease_creation_params, vault_db, loaders
):  # pylint: disable=unused-argument
    params = request.param
    ckey = ".".join(
        [
            "db",
            params.get("mount", lease_creation_params.get("mount", "database")),
            "dynamic",
            params.get("name", lease_creation_params["name"]),
            params.get("cache", lease_creation_params.get("cache", "default")),
        ]
    )
    lease = vault_db.get_creds(**lease_creation_params, **params)
    assert lease
    # We need to clear the context because in the test suite, the beacon modules
    # are running in a different one than the execution modules and the lease
    # has already been cached in the context of the execution module.
    # This means it does not pick up changes to the cached files, but we need
    # it to check changes in the tests.
    loaders.context.clear()
    return ckey  # revocation is handled in vault_db


@pytest.fixture
def revoked_lease(existing_lease, vault_db):
    lease_id = vault_db.list_cached()[existing_lease]["lease_id"]
    assert vault_revoke(lease_id)
    return existing_lease


@pytest.fixture
def beacon(beacons):
    yield beacons.vault_lease.beacon


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (False, True), indirect=True)
@pytest.mark.parametrize(
    "beacon_config", ({"check_server": False}, {"check_server": True}), indirect=True
)
def test_beacon_valid(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == []


@pytest.mark.parametrize("beacon_config", ({"leases": "foo.bar.baz"},), indirect=True)
def test_beacon_missing(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == [
        {
            "check_server": None,
            "ckey": "foo.bar.baz",
            "expired": True,
            "expires_in": -1,
            "meta": None,
            "min_ttl": 300,
            "tag": "expire",
        }
    ]


@pytest.mark.parametrize("beacon_config", ({"leases": ["foo.bar", "foo.baz"]},), indirect=True)
def test_beacon_missing_multi(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == [
        {
            "check_server": None,
            "ckey": "foo.bar",
            "expired": True,
            "expires_in": -1,
            "meta": None,
            "min_ttl": 300,
            "tag": "expire",
        },
        {
            "check_server": None,
            "ckey": "foo.baz",
            "expired": True,
            "expires_in": -1,
            "meta": None,
            "min_ttl": 300,
            "tag": "expire",
        },
    ]


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (True,), indirect=True)
@pytest.mark.usefixtures("revoked_lease")
def test_beacon_revoked_not_check_server(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == []


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (True,), indirect=True)
@pytest.mark.usefixtures("revoked_lease", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params",
    (
        ({"check_server": True}, {}),
        ({"leases_type": dict, "per_lease_params": {"check_server": True}}, {}),
    ),
    indirect=True,
)
def test_beacon_revoked_check_server(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, check_server=True, expired=True, expires_in=-1)


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params",
    (
        ({"min_ttl": 7000}, {}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 7000}}, {}),
        ({}, {"valid_for": 7000}),
        ({"min_ttl": 300}, {"valid_for": 7000}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 300}}, {"valid_for": 7000}),
    ),
    indirect=True,
)
def test_beacon_min_ttl(beacon, beacon_config, vault_db, existing_lease):
    ret = beacon(beacon_config)
    assert ret == []
    info = vault_db.list_cached()[existing_lease]
    assert info["duration"] == 7000


@pytest.mark.usefixtures("beacon_config", "existing_lease")
@pytest.mark.parametrize(
    "beacon_config",
    ({"renew": False, "min_ttl": 7000},),
    indirect=True,
)
def test_beacon_not_renew(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, min_ttl=7000)


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params",
    (
        ({"min_ttl": 8000}, {}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 8000}}, {}),
        ({}, {"valid_for": 8000}),
        ({"min_ttl": 300}, {"valid_for": 8000}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 300}}, {"valid_for": 8000}),
    ),
    indirect=True,
)
def test_beacon_min_ttl_unattainable(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, min_ttl=8000)
    assert ret["expires_in"] > 3590


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params,expected_meta",
    (
        ({"meta": "foo.bar"}, {}, "foo.bar"),
        ({"leases_type": dict, "per_lease_params": {"meta": "foo.bar"}}, {}, "foo.bar"),
        ({}, {"meta": "foo.bar"}, "foo.bar"),
        ({"meta": "foo.bar"}, {"meta": "foo.baz"}, "foo.baz"),
        (
            {"leases_type": dict, "per_lease_params": {"meta": "foo.bar"}},
            {"meta": "foo.baz"},
            "foo.baz",
        ),
        ({"meta": "foo.bar"}, {"meta": ["foo.baz"]}, ["foo.baz"]),
        ({"meta": ["foo.bar"]}, {"meta": "foo.baz"}, "foo.baz"),
        ({"meta": ["foo.bar"]}, {"meta": {"foo": "baz"}}, {"foo": "baz"}),
        ({"meta": ["foo.bar"]}, {"meta": ["foo.baz"]}, ["foo.bar", "foo.baz"]),
        (
            {"meta": {"foo": {"bar": True}}},
            {"meta": {"foo": {"bar": False}}},
            {"foo": {"bar": False}},
        ),
        (
            {"meta": {"foo": {"bar": True}}},
            {"meta": {"foo": {"baz": False}}},
            {"foo": {"bar": True, "baz": False}},
        ),
        (
            {"meta": {"foo": {"bar": [True]}}},
            {"meta": {"foo": {"bar": [False]}}},
            {"foo": {"bar": [True, False]}},
        ),
        ({"meta": "foo"}, {"meta": {"foo": {"bar": False}}}, {"foo": {"bar": False}}),
    ),
    indirect=("beacon_config", "lease_creation_params"),
)
def test_beacon_meta(beacon, beacon_config, expected_meta):
    beacon_config.append({"min_ttl": 10000})
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, min_ttl=10000, meta=expected_meta)


def _assert_evt(evt, *remove, **expected):
    assert set(evt) == {
        "meta",
        "creation_time",
        "duration",
        "expired",
        "revoke_delay",
        "tag",
        "renew_increment",
        "renewable",
        "min_ttl",
        "check_server",
        "lease_id",
        "ckey",
        "expire_time",
        "expires_in",
    }
    expected = {
        "check_server": None,
        "ckey": "db.database.dynamic.testrole.default",
        # For renewals, we can't know what the max_ttl is, so this will be the default
        # duration.
        "duration": 3600,
        "expired": False,
        "meta": None,
        "min_ttl": 300,
        "renew_increment": None,
        "renewable": True,
        "revoke_delay": None,
        "tag": "expire",
        **expected,
    }
    expected.update(expected)
    for unwanted in remove:
        expected.pop(unwanted, None)
    for param, val in expected.items():
        assert evt[param] == val
