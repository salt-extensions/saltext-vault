import logging
import os

import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks
from tests.common.helpers.vault import outdated_cached_config

pytestmark = genmarks(
    "master_approle_mount",
    internal_logic=True,
    mounts=[[("kv", "salt", "-version=2"), ("kv", "secret", "-version=2")]],
    policies=True,
    secrets=True,
    pillar=True,
)

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_overrides(master_approle_mount):  # pylint: disable=unused-argument
    return gen_master_opts(
        backend="file",
        issue="approle",
        allow_override=True,
        params={
            "secret_id_num_uses": 0,
            "secret_id_ttl": 1800,
            "token_explicit_max_ttl": 1800,
            "token_num_uses": 0,
        },
        policies=["salt_minion_{minion}", "salt_role_{pillar[roles]}"],
        entity_metadata={
            "minion-id": "{minion}",
            "role": "{pillar[role]}",
            "roles": "{pillar[roles]}",
        },
        # ensure approles/entities are generated during pillar rendering
        pillars=[
            "salt/minions/{minion}",
            "salt/roles/{pillar[role]}",
            "salt/roles/{pillar[roles]}",
        ],
    )


@pytest.fixture(scope="module")
def pillar_defaults():
    return {"roles": {"roles": ["dev", "web"], "role": "foo"}}


@pytest.fixture(scope="module")
def vault_pillar_defaults(minion):
    return {
        f"salt/minions/{minion.id.lower()}": {"minion_id_acl_template": "worked"},
        "salt/roles/foo": {"pillar_role_acl_template": "worked"},
        "salt/roles/dev": {"pillar_roles_0_acl_template": "worked"},
        "salt/roles/web": {"pillar_roles_1_acl_template": "worked"},
    }


@pytest.fixture
def approles_synced(
    salt_run_cli,
    minion,
):
    ret = salt_run_cli.run("vault.sync_approles", minion.id)
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_run_cli.run("vault.list_approles")
    assert ret.returncode == 0
    assert minion.id.lower() in ret.data
    return ret.data


@pytest.mark.usefixtures("conn_cache_absent")
def test_minion_can_authenticate(salt_call_cli):
    """
    Test that the minion can run queries against Vault.
    The master impersonating the minion is already tested in the fixture setup
    (ext_pillar).
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"


@pytest.fixture
def entities_synced(
    salt_run_cli,
    salt_call_cli,
    minion,
):
    ret = salt_run_cli.run("vault.sync_entities", minion.id)
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_run_cli.run("vault.list_approles")
    assert ret.returncode == 0
    assert minion.id.lower() in ret.data
    ret = salt_run_cli.run("vault.list_entities")
    assert ret.returncode == 0
    assert f"salt_minion_{minion.id}" in ret.data
    ret = salt_run_cli.run("vault.show_entity", minion.id)
    assert ret.returncode == 0
    assert ret.data == {
        "minion-id": minion.id,
        "role": "foo",
        "roles": "dev,web",
        "roles__0": "dev",
        "roles__1": "web",
    }
    # Entity metadata grants access to the pillar paths. Ensure the pillar reflects that.
    ret = salt_call_cli.run("saltutil.refresh_pillar", wait=True)
    assert ret.returncode == 0
    assert ret.data is True
    yield


@pytest.mark.usefixtures("entities_synced")
def test_minion_pillar_is_populated_as_expected(salt_call_cli, salt_version):
    """
    Test that ext_pillar pillar-templated paths are resolved as expectd
    (and that the ACL policy templates work on the Vault side).
    """
    if salt_version[0] >= 3008:
        ret = salt_call_cli.run("pillar.items", unmask=True)
    else:
        ret = salt_call_cli.run("pillar.items")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("minion_id_acl_template") == "worked"
    assert ret.data.get("pillar_role_acl_template") == "worked"
    assert ret.data.get("pillar_roles_0_acl_template") == "worked"
    assert ret.data.get("pillar_roles_1_acl_template") == "worked"


@pytest.mark.usefixtures("approles_synced")
@pytest.mark.usefixtures("conn_cache_absent")
def test_minion_token_policies_are_assigned_as_expected(salt_call_cli, minion):
    """
    Test that issued tokens have the expected policies.
    """
    ret = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    assert set(ret.data["data"]["policies"]) == {
        "default",
        "salt_minion",
        f"salt_minion_{minion.id.lower()}",
        "salt_role_dev",
        "salt_role_web",
    }


@pytest.fixture
def _cache_auth_outdated(minion_conn_cachedir, salt_call_cli):
    def _mutate(cached_config):
        # reset approle config to defaults, make method token
        cached_config["auth"]["method"] = "token"
        cached_config["auth"]["approle_mount"] = "approle"
        cached_config["auth"]["approle_name"] = "salt-master"
        cached_config["auth"]["secret_id"] = None
        cached_config["auth"].pop("role_id")

    with outdated_cached_config(minion_conn_cachedir, salt_call_cli, _mutate):
        yield


@pytest.mark.usefixtures("_cache_auth_outdated")
def test_auth_method_switch_does_not_break_minion_auth(salt_call_cli, caplog):
    """
    Test that after a master configuration switch from another authentication method,
    minions with cached configuration flush it and request a new one.
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
    assert "Master returned error and requested cache expiration" in caplog.text


@pytest.mark.usefixtures("_cache_server_outdated")
def test_server_switch_does_not_break_minion_auth(salt_call_cli, caplog):
    """
    Test that after a master configuration switch to another server URL,
    minions with cached configuration detect the mismatch and request a
    new configuration.
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
    assert "Mismatch of cached and reported server data detected" in caplog.text


@pytest.mark.parametrize("ckey", ["config", "__token", "secret_id"])
def test_cache_is_used_on_the_minion(ckey, salt_call_cli, minion_conn_cachedir):
    """
    Test that remote configuration, tokens acquired by authenticating with an AppRole
    and issued secret IDs are written to cache.
    """
    cache = minion_conn_cachedir
    if ckey == "__token":
        cache = cache / "session"
        if not cache.exists():
            cache.mkdir()
    if f"{ckey}.p" not in os.listdir(cache):
        ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
        assert ret.returncode == 0
    assert f"{ckey}.p" in os.listdir(cache)


@pytest.mark.parametrize(
    "suffix,ckeys",
    (
        ("/session", ("__token",)),
        ("", ("config", "secret_id")),
    ),
)
def test_cache_is_used_on_the_impersonating_master(suffix, ckeys, salt_run_cli, minion):
    """
    Test that remote configuration, tokens acquired by authenticating with an AppRole
    and issued secret IDs are written to cache when a master is impersonating
    a minion during pillar rendering.
    """
    cbank = f"minions/{minion.id}/vault/connection{suffix}"
    ret = salt_run_cli.run("cache.list", cbank)
    assert ret.returncode == 0
    assert ret.data
    for ckey in ckeys:
        assert ckey in ret.data


def test_cache_is_used_for_master_token_information(salt_run_cli):
    """
    Test that a locally configured token is cached, including meta information.
    """
    ret = salt_run_cli.run("cache.list", "vault/connection/session")
    assert ret.returncode == 0
    assert ret.data
    assert "__token" in ret.data


@pytest.fixture(scope="module")
def issue_overrides():
    return {
        "token_explicit_max_ttl": 1337,
        "token_num_uses": 42,
        "secret_id_num_uses": 3,
        "secret_id_ttl": 1338,
    }


@pytest.mark.usefixtures("approles_synced")
def test_issue_param_overrides_work(overriding_minion, issue_overrides, salt_run_cli):
    """
    Test that minion overrides of issue params work for AppRoles.
    """
    ret = overriding_minion.salt_call_cli().run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    ret = salt_run_cli.run("vault.show_approle", overriding_minion.id)
    assert ret.returncode == 0
    assert ret.data
    for val in (
        "token_explicit_max_ttl",
        "token_num_uses",
        "secret_id_num_uses",
        "secret_id_ttl",
    ):
        assert ret.data[val] == issue_overrides[val]


def test_impersonating_master_does_not_override_issue_param_overrides(
    overriding_minion, salt_run_cli, issue_overrides
):
    """
    Test that rendering the pillar does not remove issue param overrides
    requested by a minion
    """
    # ensure the minion requests a new configuration
    ret = overriding_minion.salt_call_cli().run("vault.clear_token_cache")
    assert ret.returncode == 0
    # check that the overrides are applied
    ret = overriding_minion.salt_call_cli().run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data["data"]["explicit_max_ttl"] == issue_overrides["token_explicit_max_ttl"]
    # ensure the master does not have cached authentication
    ret = salt_run_cli.run("vault.clear_cache")
    assert ret.returncode == 0
    # Render the pillar from the master
    ret = salt_run_cli.run("pillar.show_pillar", overriding_minion.id)
    assert ret.returncode == 0
    # check that issue overrides are still present
    ret = salt_run_cli.run("vault.show_approle", overriding_minion.id)
    assert ret.returncode == 0
    assert ret.data
    assert ret.data["token_explicit_max_ttl"] == issue_overrides["token_explicit_max_ttl"]
    # request pillar refresh from minion
    ret = overriding_minion.salt_call_cli().run("saltutil.refresh_pillar", wait=True)
    assert ret.returncode == 0
    # check that issue overrides are still present
    ret = salt_run_cli.run("vault.show_approle", overriding_minion.id)
    assert ret.returncode == 0
    assert ret.data
    assert ret.data["token_explicit_max_ttl"] == issue_overrides["token_explicit_max_ttl"]
