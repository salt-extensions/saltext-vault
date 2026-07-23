import time
from datetime import datetime

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from saltfactories.utils import random_string

from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
]


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_secret_id
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
    assert vault_enable_auth_method("approle", name)
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


@pytest.fixture
def vault_approle(modules, approle_auth):
    try:
        yield modules.vault_approle
    finally:
        vault_delete(f"auth/{approle_auth}/role/testrole")


@pytest.mark.usefixtures("roles_setup")
def test_list(vault_approle, approle_auth):
    ret = vault_approle.list(mount=approle_auth)
    assert ret == ["testrole"]


def test_list_empty(vault_approle, approle_auth):
    ret = vault_approle.list(mount=approle_auth)
    assert ret == []


@pytest.mark.usefixtures("roles_setup")
def test_read(vault_approle, testrole, approle_auth):
    ret = vault_approle.read("testrole", mount=approle_auth)
    assert ret
    for var, val in testrole.items():
        assert var in ret
        assert ret[var] == val


def test_read_empty(vault_approle, approle_auth):
    with pytest.raises(CommandExecutionError, match="VaultNotFoundError.*"):
        vault_approle.read("foobar", mount=approle_auth)


def test_write(vault_approle, approle_auth, container):
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
    ret = vault_approle.write("testrole", **args, mount=approle_auth)
    assert ret
    assert "testrole" in vault_list(f"auth/{approle_auth}/role")
    role = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    assert role == expected

    # Test partial updates
    update_args = {"token_num_uses": 42, "token_policies": []}
    ret = vault_approle.write("testrole", **update_args, mount=approle_auth)
    assert ret
    assert "testrole" in vault_list(f"auth/{approle_auth}/role")
    role = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    for key, oldval in expected.items():
        if key == "alias_metadata":
            # somehow, this is reset when updating
            oldval = {}
        assert role[key] == update_args.get(key, oldval)


@pytest.mark.usefixtures("roles_setup")
def test_delete(vault_approle, approle_auth):
    ret = vault_approle.delete("testrole", mount=approle_auth)
    assert ret
    assert "testrole" not in vault_list(f"auth/{approle_auth}/role")


@pytest.fixture(params=({},))
def _cached_approle(
    vault_approle, approle_auth, roles_setup, request
):  # pylint: disable=unused-argument
    data = request.param.copy()
    role = data.pop("role", "testrole")
    ret = vault_approle.get_secret_id(role, cache=True, **data, all_data=True, mount=approle_auth)
    assert ret
    assert isinstance(ret["id"], str)
    return ret


@pytest.mark.usefixtures("roles_setup")
def test_get_role_id(vault_approle, approle_auth):
    expected = vault_read(f"auth/{approle_auth}/role/testrole/role-id")["data"]["role_id"]
    ret = vault_approle.get_role_id("testrole", mount=approle_auth)
    assert ret
    assert isinstance(ret, str)
    assert ret == expected


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id(vault_approle, approle_auth):
    ret = vault_approle.get_secret_id("testrole", cache=False, mount=approle_auth)
    assert ret
    assert isinstance(ret, str)
    assert not ret.strip("abcdef0123456789-")


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_wrapped(vault_approle, approle_auth):
    ret = vault_approle.get_secret_id("testrole", wrap=30, mount=approle_auth)
    assert ret
    assert isinstance(ret, str)
    assert ret.strip("abcdef0123456789-")


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_wrapped_cache_fail(vault_approle, approle_auth):
    with pytest.raises(SaltInvocationError, match="Cannot cache wrapped responses.*"):
        vault_approle.get_secret_id("testrole", wrap=30, cache=True, mount=approle_auth)


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_all_data(vault_approle, approle_auth):
    ret = vault_approle.get_secret_id("testrole", cache=False, all_data=True, mount=approle_auth)
    assert isinstance(ret, dict)
    assert ret
    assert "id" in ret
    assert "lease_id" in ret
    assert ret["lease_id"] == ret["id"]
    assert "accessor" in ret
    assert ret["num_uses"] == 3
    assert ret["duration"] == 86400
    assert isinstance(ret["creation_time"], int)
    assert isinstance(ret["expire_time"], int)
    assert ret["wrapping_accessor"] is None


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_wrapped_all_data(vault_approle, approle_auth):
    ret = vault_approle.get_secret_id(
        "testrole", cache=False, wrap=30, all_data=True, mount=approle_auth
    )
    assert isinstance(ret, dict)
    assert ret
    assert "id" in ret
    assert "lease_id" in ret
    assert "accessor" in ret
    assert "num_uses" not in ret
    assert ret["duration"] == 30
    assert isinstance(ret["creation_time"], int)
    assert isinstance(ret["expire_time"], int)
    assert ret["wrapping_accessor"]


@pytest.mark.parametrize("all_data", (False, True))
def test_get_secret_id_cached(vault_approle, _cached_approle, approle_auth, all_data):
    ret_new = vault_approle.get_secret_id(
        "testrole", cache=True, all_data=all_data, mount=approle_auth
    )
    assert ret_new
    if all_data:
        assert isinstance(ret_new, dict)
        assert ret_new == _cached_approle
    else:
        assert isinstance(ret_new, str)
        assert ret_new == _cached_approle["id"]


def test_get_secret_id_cached_destroyed(vault_approle, _cached_approle, approle_auth):
    vault_approle.destroy_secret_id(
        "testrole", accessor=_cached_approle["accessor"], mount=approle_auth
    )
    ret_new = vault_approle.get_secret_id("testrole", cache=True, mount=approle_auth)
    assert ret_new
    assert isinstance(ret_new, str)
    assert ret_new != _cached_approle["id"]


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_cached_multiple(vault_approle, _cached_approle, approle_auth):
    ret = vault_approle.get_secret_id("testrole", cache="one", mount=approle_auth)
    assert ret
    assert isinstance(ret, str)
    ret_new = vault_approle.get_secret_id("testrole", cache="two", mount=approle_auth)
    assert ret_new
    assert isinstance(ret_new, str)
    assert ret_new != ret
    assert vault_approle.get_secret_id("testrole", cache="one", mount=approle_auth) == ret
    assert vault_approle.get_secret_id("testrole", cache="two", mount=approle_auth) == ret_new
    assert (
        vault_approle.get_secret_id("testrole", cache=True, mount=approle_auth)
        == _cached_approle["id"]
    )


@pytest.fixture
def testreissuerole():
    return {
        "secret_id_ttl": 180,
    }


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("roles_setup", [["testreissuerole"]], indirect=True)
@pytest.mark.parametrize(
    "_cached_approle", ({"role": "testreissuerole", "min_ttl": 180},), indirect=True
)
def test_get_secret_id_cached_valid_for_reissue(
    vault_approle, testreissuerole, _cached_approle, approle_auth
):
    """
    Test that valid cached SecretIDs that do not fulfill min_ttl are reissued
    """
    # 3 seconds because of leeway in lease validity check after renewals
    time.sleep(3)
    ret_new = vault_approle.get_secret_id(
        "testreissuerole", cache=True, min_ttl=testreissuerole["secret_id_ttl"], mount=approle_auth
    )
    assert ret_new
    assert ret_new != _cached_approle["id"]


@pytest.mark.usefixtures("roles_setup")
def test_get_secret_id_cached_name_with_dots(vault_approle, approle_auth):
    """
    Custom cache names are documented as arbitrary strings, so they
    can contain dots. Ensure such entries can be retrieved from cache
    and cleared again.
    """
    ret = vault_approle.get_secret_id("testrole", cache="with.dots", mount=approle_auth)
    assert ret
    assert isinstance(ret, str)
    ret_new = vault_approle.get_secret_id("testrole", cache="with.dots", mount=approle_auth)
    assert ret_new == ret
    vault_approle.clear_cached(cache="with.dots", mount=approle_auth)
    assert not vault_approle.list_cached(mount=approle_auth)


@pytest.mark.usefixtures("_cached_approle")
def test_clear_cached(vault_approle, approle_auth):
    assert f"secid.{approle_auth}.testrole.default" in vault_approle.list_cached(mount=approle_auth)
    assert vault_approle.clear_cached(mount=approle_auth) is True
    assert f"secid.{approle_auth}.testrole.default" not in vault_approle.list_cached(
        mount=approle_auth
    )


@pytest.mark.usefixtures("_cached_approle")
def test_clear_cached_specific(vault_approle, approle_auth):
    vault_approle.get_secret_id("testrole", cache="alt", mount=approle_auth)
    assert len(vault_approle.list_cached(mount=approle_auth)) == 2
    vault_approle.clear_cached(mount="foobar")
    assert len(vault_approle.list_cached(mount=approle_auth)) == 2
    vault_approle.clear_cached(cache="alt")
    assert len(vault_approle.list_cached(mount=approle_auth)) == 1
    vault_approle.get_secret_id("testrole", cache="alt", mount=approle_auth)
    assert len(vault_approle.list_cached(mount=approle_auth)) == 2
    vault_approle.clear_cached(cache=True)
    assert len(vault_approle.list_cached(mount=approle_auth)) == 1
    vault_approle.clear_cached(name="foobar")
    assert len(vault_approle.list_cached(mount=approle_auth)) == 1
    vault_approle.clear_cached(name="testrole")
    assert len(vault_approle.list_cached(mount=approle_auth)) == 0


@pytest.mark.usefixtures("_cached_approle")
def test_list_cached(vault_approle, approle_auth):
    ret = vault_approle.list_cached()
    ckey = f"secid.{approle_auth}.testrole.default"
    assert ret
    assert ckey in ret
    assert not ret[ckey]["expired"]
    assert ret[ckey]["expires_in"] > 3590
    assert "id" not in ret[ckey]
    assert "secret_id" not in ret[ckey]
    now = datetime.now().astimezone()
    # this might fail if this test runs juuust before midnight
    assert ret[ckey]["creation_time"].startswith(now.strftime("%Y-%m-%d"))
    # I hope you have something better to do during New Year's Eve
    assert ret[ckey]["expire_time"].startswith(now.strftime("%Y-"))
    for val in ("creation_time", "expire_time"):
        assert ret[ckey][val].endswith(now.strftime(" %Z"))


@pytest.mark.parametrize("accessor", (False, True))
def test_lookup_secret_id(vault_approle, _cached_approle, approle_auth, accessor):
    params = {"mount": approle_auth}
    if accessor:
        params["accessor"] = _cached_approle["accessor"]
    else:
        params["secret_id"] = _cached_approle["id"]
    ret = vault_approle.lookup_secret_id("testrole", **params)
    assert isinstance(ret, dict)
    assert ret["secret_id_num_uses"] == 3
    assert ret["secret_id_ttl"] == 86400
    assert ret["secret_id_accessor"] == _cached_approle["accessor"]
    assert "cidr_list" in ret
    assert "creation_time" in ret
    assert "expiration_time" in ret
    assert "metadata" in ret
    assert "token_bound_cidrs" in ret


@pytest.mark.parametrize("accessor", (False, True))
def test_destroy_secret_id(vault_approle, _cached_approle, approle_auth, accessor):
    params = {"mount": approle_auth}
    if accessor:
        params["accessor"] = _cached_approle["accessor"]
    else:
        params["secret_id"] = _cached_approle["id"]
    vault_approle.destroy_secret_id("testrole", **params)
    with pytest.raises(CommandExecutionError, match="VaultNotFoundError.*"):
        vault_approle.lookup_secret_id("testrole", **params)
