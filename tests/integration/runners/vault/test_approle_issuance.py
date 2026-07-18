import logging
import os

import pytest
import salt.utils.data
import salt.utils.files
import salt.utils.msgpack
from saltfactories.utils import random_string

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "pillar_base", "vault_secrets"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        # ensure approles/entities are generated during pillar rendering
        "ext_pillar": [
            {"vault": "salt/minions/{minion}"},
            {"vault": "salt/roles/{pillar[role]}"},
            {"vault": "salt/roles/{pillar[roles]}"},
        ],
        "vault": {
            "cache": {
                "backend": "file",
            },
            "issue": {
                "allow_minion_override_params": True,
                "type": "approle",
                "approle": {
                    "params": {
                        "secret_id_num_uses": 0,
                        "secret_id_ttl": 1800,
                        "token_explicit_max_ttl": 1800,
                        "token_num_uses": 0,
                    }
                },
            },
            "metadata": {
                "entity": {
                    "minion-id": "{minion}",
                    "role": "{pillar[role]}",
                    "roles": "{pillar[roles]}",
                },
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "salt_minion_{minion}",
                    "salt_role_{pillar[roles]}",
                ],
            },
        },
    }


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
    # minion_data_cache_present,  # pylint: disable=unused-argument
    minion,
):
    ret = salt_run_cli.run("vault.sync_approles", minion.id)
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_run_cli.run("vault.list_approles")
    assert ret.returncode == 0
    assert minion.id.lower() in ret.data
    yield


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
def _missing_auth_cache(minion_conn_cachedir):
    token_cachefile = minion_conn_cachedir / "session" / "__token.p"
    secret_id_cachefile = minion_conn_cachedir / "secret_id.p"
    for file in (secret_id_cachefile, token_cachefile):
        if file.exists():
            file.unlink()
    yield


@pytest.fixture
def _cache_auth_outdated(
    _missing_auth_cache, minion_conn_cachedir, vault_port
):  # pylint: disable=unused-argument
    vault_url = f"http://127.0.0.1:{vault_port}"
    config_data = b"\x84\xa4auth\x84\xadapprole_mount\xa7approle\xacapprole_name\xbavault-approle-int-minion-1\xa6method\xa5token\xa9secret_id\xc0\xa5cache\x83\xa7backend\xa4disk\xa6config\xcd\x0e\x10\xa6secret\xa3ttl\xa6client\x86\xabmax_retries\x05\xaebackoff_factor\xcb?\xd3333333\xabbackoff_max\x08\xaebackoff_jitter\xcb?\xf0\x00\x00\x00\x00\x00\x00\xaaretry_post\xc3\xb3respect_retry_after\xc3\xa6server\x83\xa9namespace\xc0\xa6verify\xc0\xa3url"
    config_data += (len(vault_url) + 160).to_bytes(1, "big") + vault_url.encode()
    config_cachefile = minion_conn_cachedir / "config.p"
    with salt.utils.files.fopen(config_cachefile, "wb") as f:
        f.write(config_data)
    try:
        yield
    finally:
        if config_cachefile.exists():
            config_cachefile.unlink()


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


@pytest.fixture
def _cache_server_outdated(
    _missing_auth_cache, minion_conn_cachedir
):  # pylint: disable=unused-argument
    config_data = b"\x84\xa4auth\x85\xadapprole_mount\xa7approle\xacapprole_name\xbavault-approle-int-minion-1\xa6method\xa7approle\xa7role_id\xactest-role-id\xa9secret_id\xc3\xa5cache\x83\xa7backend\xa4disk\xa6config\xcd\x0e\x10\xa6secret\xa3ttl\xa6client\x86\xabmax_retries\x05\xaebackoff_factor\xcb?\xd3333333\xabbackoff_max\x08\xaebackoff_jitter\xcb?\xf0\x00\x00\x00\x00\x00\x00\xaaretry_post\xc3\xb3respect_retry_after\xc3\xa6server\x83\xa9namespace\xc0\xa6verify\xc0\xa3url\xb2http://127.0.0.1:8"
    config_cachefile = minion_conn_cachedir / "config.p"
    with salt.utils.files.fopen(config_cachefile, "wb") as f:
        f.write(config_data)
    try:
        yield
    finally:
        if config_cachefile.exists():
            config_cachefile.unlink()


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
def overriding_minion(master, issue_overrides):
    assert master.is_running()
    factory = master.salt_minion_daemon(
        random_string("overriding-minion", uppercase=False),
        defaults={"open_mode": True, "grains": {}},
        overrides={"vault": {"issue_params": issue_overrides}},
    )
    with factory.started():
        # Sync All
        salt_call_cli = factory.salt_call_cli()
        ret = salt_call_cli.run("saltutil.sync_all", _timeout=120)
        assert ret.returncode == 0, ret
        yield factory


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
