import pytest
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
                "backend": "disk",
            },
        }
    }


@pytest.fixture
def testrole(request):
    defaults = {
        "secret_id_ttl": 86400,
        "secret_id_num_uses": 3,
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


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


@pytest.fixture
def vault_approle(states, approle_auth):
    try:
        yield states.vault_approle
    finally:
        vault_delete(f"auth/{approle_auth}/role/testrole")


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


@pytest.fixture
def roleargs(approle_auth):
    return {
        "secret_id_ttl": 86400,
        "mount": approle_auth,
    }


def test_present(vault_approle, roleargs, approle_auth, testmode):
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "created" in ret.changes
    assert ret.changes["created"] == "testrole"
    assert ("testrole" not in vault_list(f"auth/{approle_auth}/role")) is testmode


@pytest.mark.usefixtures("roles_setup")
def test_present_no_changes(vault_approle, roleargs, testmode):
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_present_no_changes_with_time_string(vault_approle, roleargs, testmode):
    roleargs["secret_id_ttl"] = "1d"
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_present_generic_param_change(vault_approle, roleargs, approle_auth, testmode):
    roleargs["token_num_uses"] = 1337
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "token_num_uses" in ret.changes
    assert (
        vault_read(f"auth/{approle_auth}/role/testrole")["data"]["token_num_uses"] != 1337
    ) is testmode


@pytest.mark.usefixtures("roles_setup", "testrole")
@pytest.mark.parametrize("testrole", ({"token_policies": ["foo", "bar"]},), indirect=True)
def test_present_list_param_change(vault_approle, roleargs, approle_auth, testmode):
    roleargs["token_policies"] = ["foo", "baz"]
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "token_policies" in ret.changes
    assert ret["changes"]["token_policies"] == {"added": ["baz"], "removed": ["bar"]}
    assert (
        set(vault_read(f"auth/{approle_auth}/role/testrole")["data"]["token_policies"])
        != {
            "foo",
            "baz",
        }
    ) is testmode


@pytest.mark.usefixtures("roles_setup", "testrole")
def test_present_time_param_change(vault_approle, roleargs, approle_auth, testmode):
    roleargs["secret_id_ttl"] = "1h"
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "secret_id_ttl" in ret.changes
    assert ret["changes"]["secret_id_ttl"] == {"old": 86400, "new": "1h"}
    assert (
        vault_read(f"auth/{approle_auth}/role/testrole")["data"]["secret_id_ttl"] != 3600
    ) is testmode


@pytest.mark.usefixtures("roles_setup", "testrole")
def test_present_alias_metadata_change(vault_approle, roleargs, approle_auth, container, modules):
    if "vault" not in container or "latest" not in container:
        pytest.skip("Only supported on recent Vault releases")
    prev_metadata = {"foo": "bar", "bar": "baz"}
    modules.vault_approle.write("testrole", mount=approle_auth, alias_metadata=prev_metadata)
    roleargs["alias_metadata"] = {"foo": "baz", "baz": "quux"}
    ret = vault_approle.present("testrole", **roleargs)
    assert ret.result is True
    assert ret.changes
    assert "alias_metadata" in ret.changes
    assert ret["changes"]["alias_metadata"] == {
        "added": ["baz"],
        "changed": ["foo"],
        "removed": ["bar"],
    }
    data = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    assert data["alias_metadata"] == roleargs["alias_metadata"]


@pytest.mark.usefixtures("roles_setup", "testrole")
def test_present_token_strictly_bind_ip_change(vault_approle, roleargs, approle_auth, container):
    if "openbao" not in container:
        pytest.skip("Only supported on OpenBao")
    roleargs["token_strictly_bind_ip"] = True
    ret = vault_approle.present("testrole", **roleargs)
    assert ret.result is True
    assert ret.changes
    assert "token_strictly_bind_ip" in ret.changes
    assert ret["changes"]["token_strictly_bind_ip"] == {"old": False, "new": True}
    assert (
        vault_read(f"auth/{approle_auth}/role/testrole")["data"]["token_strictly_bind_ip"] is True
    )


@pytest.mark.usefixtures("roles_setup", "testrole")
@pytest.mark.parametrize(
    "testrole", ({"token_num_uses": 42, "token_period": "1h"},), indirect=True
)  # These must not be set when setting batch token type
def test_present_token_type_batch_change(vault_approle, roleargs, approle_auth, testmode):
    roleargs["token_type"] = "batch"
    roleargs["token_policies"] = ["foo", "bar"]
    roleargs.pop("secret_id_ttl")
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "token_type" in ret.changes
    assert "token_num_uses" in ret.changes
    assert "token_period" in ret.changes
    assert "token_policies" in ret.changes
    data = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    assert (data["token_type"] != "batch") is testmode
    if not testmode:
        assert set(data["token_policies"]) == {"foo", "bar"}
        assert data["secret_id_ttl"] == 86400
        assert data["secret_id_num_uses"] == 3


@pytest.mark.usefixtures("roles_setup", "testrole")
@pytest.mark.parametrize(
    "testrole", ({"token_type": "batch"},), indirect=True
)  # These must not be set when setting batch token type
def test_present_token_type_service_change(vault_approle, roleargs, approle_auth, testmode):
    roleargs["token_type"] = "service"
    roleargs["token_num_uses"] = 42
    roleargs["token_period"] = "1h"
    roleargs["token_policies"] = ["foo", "bar"]
    roleargs.pop("secret_id_ttl")
    ret = vault_approle.present("testrole", **roleargs, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert ret.changes["token_type"] == {"old": "batch", "new": "service"}
    assert ret.changes["token_num_uses"] == {"old": 0, "new": 42}
    assert ret.changes["token_period"] == {"old": 0, "new": "1h"}
    assert ret.changes["token_policies"] == {"added": ["bar", "foo"], "removed": []}
    data = vault_read(f"auth/{approle_auth}/role/testrole")["data"]
    assert (data["token_type"] != "service") is testmode
    if not testmode:
        assert set(data["token_policies"]) == {"foo", "bar"}
        assert data["secret_id_ttl"] == 86400
        assert data["secret_id_num_uses"] == 3
        assert data["token_num_uses"] == 42
        assert data["token_period"] == 3600


@pytest.mark.usefixtures("roles_setup")
def test_absent(vault_approle, approle_auth, testmode):
    ret = vault_approle.absent("testrole", mount=approle_auth, test=testmode)
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == "testrole"
    assert ("testrole" in vault_list(f"auth/{approle_auth}/role")) is testmode


def test_absent_no_changes(vault_approle, approle_auth, testmode):
    ret = vault_approle.absent("testrole", mount=approle_auth, test=testmode)
    assert ret.result is True
    assert not ret.changes
