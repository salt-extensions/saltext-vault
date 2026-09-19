import pytest

# pylint: disable=unused-import
from tests.fixtures.mysql import create_mysql_combo
from tests.fixtures.mysql import mysql_combo
from tests.fixtures.mysql import mysql_container
from tests.fixtures.vault_db import connection_setup
from tests.fixtures.vault_db import mysql_image
from tests.fixtures.vault_db import role_args_common
from tests.fixtures.vault_db import roles_setup
from tests.fixtures.vault_db import testdb
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_revoke
from tests.support.vault import vault_write

# pylint: enable=unused-import


@pytest.fixture
def beacons(loaders):
    return loaders.beacons


@pytest.fixture
def testrole():
    return {
        "default_ttl": 3600,
        "max_ttl": 7200,
    }


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
    alt_lease = None
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
