from datetime import datetime

import pytest
from saltfactories.utils import random_string

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_secret_id
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "approle_admin",
                ],
            },
        }
    }


@pytest.fixture
def testrole():
    return {
        "secret_id_ttl": 86400,
        "secret_id_num_uses": 3,
    }


@pytest.fixture(scope="module", autouse=True)
def approle_auth(container):  # pylint: disable=unused-argument
    name = random_string("approle-test", uppercase=False)
    assert vault_enable_auth_method("approle", [f"-path={name}"])
    try:
        yield name
    finally:
        assert vault_disable_auth_method(name)


@pytest.fixture(params=[["testrole"]])
def roles_setup(approle_auth, request):  # pylint: disable=unused-argument
    try:
        for role_name in request.param:
            role_args = request.getfixturevalue(role_name)
            vault_write(f"auth/{approle_auth}/role/{role_name}", **role_args)
            assert role_name in vault_list(f"auth/{approle_auth}/role")
        yield
    finally:
        for role_name in request.param:
            if role_name in vault_list(f"auth/{approle_auth}/role"):
                vault_delete(f"auth/{approle_auth}/role/{role_name}")
                assert role_name not in vault_list(f"auth/{approle_auth}/role")


@pytest.mark.usefixtures("roles_setup")
def test_list(salt_ssh_cli, approle_auth):
    ret = salt_ssh_cli.run("vault_approle.list", mount=approle_auth)
    assert ret.returncode == 0
    assert ret.data == ["testrole"]


@pytest.mark.usefixtures("roles_setup")
def test_read(salt_ssh_cli, testrole, approle_auth):
    ret = salt_ssh_cli.run("vault_approle.read", "testrole", mount=approle_auth)
    assert ret.returncode == 0
    assert ret.data
    for var, val in testrole.items():
        assert var in ret.data
        assert ret.data[var] == val


def test_write(salt_ssh_cli, approle_auth, container):
    args = {
        "bind_secret_id": True,
        "secret_id_bound_cidrs": ["172.16.1.0/24"],
        "secret_id_num_uses": 42,
        "secret_id_ttl": 1337,
        "local_secret_ids": False,
        "token_ttl": "1337m",
        "token_max_ttl": "1345m",
        "token_policies": ["approle_admin"],
        "token_bound_cidrs": ["172.16.1.0/24"],
        "token_explicit_max_ttl": 98765,
        "token_no_default_policy": True,
        "token_num_uses": 37,
        "token_period": 6969,
        "token_type": "service",
    }
    expected = args.copy()
    if "vault" in container and "latest" in container:
        args["alias_metadata"] = {"foo": "bar"}
        expected["alias_metadata"] = {"foo": "bar"}
    elif "openbao" in container:
        expected["token_strictly_bind_ip"] = args["token_strictly_bind_ip"] = True
        expected["token_bound_cidrs"] = []
        args["token_bound_cidrs"] = None
    expected["token_ttl"] = 80220
    expected["token_max_ttl"] = 80700
    ret = salt_ssh_cli.run("vault_approle.write", "testrole", **args, mount=approle_auth)
    assert ret.returncode == 0
    assert "testrole" in vault_list(f"auth/{approle_auth}/role")
    role = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    assert role == expected

    # Test partial updates
    update_args = {"token_num_uses": 42, "token_policies": []}
    ret = salt_ssh_cli.run("vault_approle.write", "testrole", **update_args, mount=approle_auth)
    assert ret.returncode == 0
    assert "testrole" in vault_list(f"auth/{approle_auth}/role")
    role = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    for key, oldval in expected.items():
        if key == "alias_metadata":
            # somehow, this is reset when updating
            oldval = {}
        assert role[key] == update_args.get(key, oldval)


@pytest.mark.usefixtures("roles_setup")
def test_delete(salt_ssh_cli, approle_auth):
    ret = salt_ssh_cli.run("vault_approle.delete", "testrole", mount=approle_auth)
    assert ret.returncode == 0
    assert ret.data
    assert "testrole" not in vault_list(f"auth/{approle_auth}/role")


@pytest.fixture(params=({},))
def _cached_approle(
    salt_ssh_cli, approle_auth, roles_setup, request
):  # pylint: disable=unused-argument
    data = request.param.copy()
    role = data.pop("role", "testrole")
    ret = salt_ssh_cli.run(
        "vault_approle.get_secret_id", role, cache=True, **data, all_data=True, mount=approle_auth
    )
    assert ret.returncode == 0
    assert isinstance(ret.data["id"], str)
    return ret.data


@pytest.mark.usefixtures("roles_setup")
def test_get_role_id(salt_ssh_cli, approle_auth):
    expected = vault_read(f"auth/{approle_auth}/role/testrole/role-id")["data"]["role_id"]
    ret = salt_ssh_cli.run("vault_approle.get_role_id", "testrole", mount=approle_auth)
    assert ret.returncode == 0
    assert isinstance(ret.data, str)
    assert ret.data == expected


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id(salt_ssh_cli, approle_auth):
    ret = salt_ssh_cli.run(
        "vault_approle.get_secret_id", "testrole", cache=False, mount=approle_auth
    )
    assert ret.returncode == 0
    assert ret.data
    assert isinstance(ret.data, str)
    assert not ret.data.strip("abcdef0123456789-")


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_wrapped(salt_ssh_cli, approle_auth):
    ret = salt_ssh_cli.run("vault_approle.get_secret_id", "testrole", wrap=30, mount=approle_auth)
    assert ret.returncode == 0
    assert ret.data
    assert isinstance(ret.data, str)
    assert ret.data.strip("abcdef0123456789-")


def test_get_secret_id_cached(salt_ssh_cli, _cached_approle, approle_auth):
    ret_new = salt_ssh_cli.run(
        "vault_approle.get_secret_id", "testrole", cache=True, all_data=True, mount=approle_auth
    )
    assert ret_new.returncode == 0
    assert ret_new.data
    assert isinstance(ret_new.data, dict)
    assert ret_new.data == _cached_approle


def test_get_secret_id_cached_destroyed(salt_ssh_cli, _cached_approle, approle_auth):
    vault_write(
        f"auth/{approle_auth}/role/testrole/secret-id-accessor/destroy",
        secret_id_accessor=_cached_approle["accessor"],
    )
    ret_new = salt_ssh_cli.run(
        "vault_approle.get_secret_id", "testrole", cache=True, mount=approle_auth
    )
    assert ret_new.returncode == 0
    assert ret_new.data
    assert isinstance(ret_new.data, str)
    assert ret_new.data != _cached_approle["id"]


@pytest.fixture
def testreissuerole():
    return {
        "secret_id_ttl": 180,
    }


@pytest.mark.usefixtures("_cached_approle")
def test_clear_cached(salt_ssh_cli, approle_auth):
    ret = salt_ssh_cli.run("vault_approle.list_cached", mount=approle_auth)
    assert ret.returncode == 0
    assert f"secid.{approle_auth}.testrole.default" in ret.data
    ret = salt_ssh_cli.run("vault_approle.clear_cached", mount=approle_auth)
    assert ret.returncode == 0
    ret = salt_ssh_cli.run("vault_approle.list_cached", mount=approle_auth)
    assert ret.returncode == 0
    assert f"secid.{approle_auth}.testrole.default" not in ret.data


@pytest.mark.usefixtures("_cached_approle")
def test_list_cached(salt_ssh_cli, approle_auth):
    ret = salt_ssh_cli.run("vault_approle.list_cached")
    assert ret.returncode == 0
    assert ret.data
    ckey = f"secid.{approle_auth}.testrole.default"
    assert ckey in ret.data
    assert not ret.data[ckey]["expired"]
    assert ret.data[ckey]["expires_in"] > 3590
    assert "id" not in ret.data[ckey]
    assert "secret_id" not in ret.data[ckey]
    now = datetime.now().astimezone()
    # this might fail if this test runs juuust before midnight
    assert ret.data[ckey]["creation_time"].startswith(now.strftime("%Y-%m-%d"))
    # I hope you have something better to do during New Year's Eve
    assert ret.data[ckey]["expire_time"].startswith(now.strftime("%Y-"))
    for val in ("creation_time", "expire_time"):
        assert ret.data[ckey][val].endswith(now.strftime(" %Z"))


@pytest.mark.parametrize("accessor", (False, True))
def test_lookup_secret_id(salt_ssh_cli, _cached_approle, approle_auth, accessor):
    params = {"mount": approle_auth}
    if accessor:
        params["accessor"] = _cached_approle["accessor"]
    else:
        params["secret_id"] = _cached_approle["id"]
    ret = salt_ssh_cli.run("vault_approle.lookup_secret_id", "testrole", **params)
    assert ret.returncode == 0
    assert isinstance(ret.data, dict)
    assert ret.data["secret_id_num_uses"] == 3
    assert ret.data["secret_id_ttl"] == 86400
    assert ret.data["secret_id_accessor"] == _cached_approle["accessor"]
    assert "cidr_list" in ret.data
    assert "creation_time" in ret.data
    assert "expiration_time" in ret.data
    assert "metadata" in ret.data
    assert "token_bound_cidrs" in ret.data


@pytest.mark.parametrize("accessor", (False, True))
def test_destroy_secret_id(salt_ssh_cli, _cached_approle, approle_auth, accessor):
    params = {}
    if accessor:
        params["accessor"] = _cached_approle["accessor"]
    else:
        params["secret_id"] = _cached_approle["id"]
    ret = salt_ssh_cli.run(
        "vault_approle.destroy_secret_id", "testrole", **params, mount=approle_auth
    )
    assert ret.returncode == 0
    assert ret.data
    _existing_data, exists = vault_write(
        f"auth/{approle_auth}/role/testrole/secret-id-accessor/lookup",
        secret_id_accessor=_cached_approle["accessor"],
        _nofail=True,
    )
    assert exists is False
