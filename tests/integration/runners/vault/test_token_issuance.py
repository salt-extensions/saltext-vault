import copy
import logging
import os

import pytest
import salt.utils.data
import salt.utils.msgpack

from tests.common import gen_master_opts
from tests.common.containers import genmarks
from tests.common.helpers.vault import outdated_cached_config

pytestmark = genmarks(
    internal_logic_only=True, mounts=True, policies=True, secrets=True, pillar=True
)

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(
        backend="file",
        params={"num_uses": 0},
        policies=["salt_minion_{minion}", "salt_role_{pillar[roles]}"],
        policy_cache_time=0,
        # ensure approles/entities are generated during pillar rendering
        pillars="secret/path/foo",
    )


@pytest.fixture(scope="module")
def pillar_defaults():
    return {"roles": {"roles": ["dev", "web"]}}


@pytest.fixture(scope="module")
def vault_pillar_defaults():
    return {"secret/path/foo": {"success": "yeehaaw"}}


@pytest.fixture
def _cache_auth_outdated(minion_conn_cachedir, salt_call_cli, minion):
    def _mutate(cached_config):
        # insert some dummy approle data, we expect this to get deleted
        cached_config["auth"]["method"] = "approle"
        cached_config["auth"]["role_id"] = "test-role-id"
        cached_config["auth"]["approle_name"] = minion.id
        cached_config["auth"]["secret_id"] = True

    with outdated_cached_config(minion_conn_cachedir, salt_call_cli, _mutate):
        yield


@pytest.fixture(params=((1, 0), (1, 7)))
def cache_from_old_version(salt_call_cli, minion_conn_cachedir, request):
    """
    Removes any top-level keys from cached config except
    for auth, cache and server. Also removes server:url_alts.
    Added when ``client`` was introduced to the config to
    simulate upgrades from old versions.
    """

    def _mutate(cached_config):
        old_params = copy.deepcopy(cached_config)
        if request.param < (1, 1):  # vault:client introduced in 1.1
            old_params.pop("client")
        if request.param < (1, 8):  # vault:server:url_alts introduced in 1.8
            old_params["server"].pop("url_alts")
        return old_params

    with outdated_cached_config(
        minion_conn_cachedir, salt_call_cli, _mutate, clear_auth=False
    ) as cached_config:
        yield cached_config


@pytest.fixture(scope="module")
def issue_overrides():
    return {
        "explicit_max_ttl": 1337,
        "num_uses": 42,
        "secret_id_num_uses": 3,
        "secret_id_ttl": 1338,
        "irrelevant_setting": "abc",
    }


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
        f"salt_minion_{minion.id}",
        "salt_role_dev",
        "salt_role_web",
    }


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


def test_upgrade_does_not_break_auth(salt_call_cli, minion_conn_cachedir, cache_from_old_version):
    """
    Test that after this saltext has been upgraded, an old cached configuration
    is updated without breaking anything.
    """
    token_cachefile = minion_conn_cachedir / "session" / "__token.p"
    token_data = token_cachefile.read_bytes()
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
    config_cachefile = minion_conn_cachedir / "config.p"
    cached_config = salt.utils.data.decode(salt.utils.msgpack.loads(config_cachefile.read_bytes()))
    # cache_from_old_version gives us the expected config, a bit misleading
    # It should be updated to the new format.
    assert cached_config == cache_from_old_version
    # The token should be the same.
    assert token_cachefile.read_bytes() == token_data


@pytest.mark.parametrize("ckey", ["config", "__token"])
def test_cache_is_used_on_the_minion(ckey, salt_call_cli, minion_conn_cachedir):
    """
    Test that remote configuration and tokens are written to cache.
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


@pytest.mark.parametrize("ckey", ["config", "__token"])
def test_cache_is_used_on_the_impersonating_master(ckey, salt_run_cli, minion):
    """
    Test that remote configuration and tokens are written to cache when a
    master is impersonating a minion during pillar rendering.
    """
    cbank = f"minions/{minion.id}/vault/connection"
    if ckey == "__token":
        cbank += "/session"
    ret = salt_run_cli.run("cache.list", cbank)
    assert ret.returncode == 0
    assert ret.data
    assert ckey in ret.data


@pytest.mark.usefixtures("conn_cache_absent")
def test_issue_param_overrides_require_setting(overriding_minion):
    """
    Test that minion overrides of issue params are not set by default
    and require setting ``issue:allow_minion_override_params``.
    """
    ret = overriding_minion.salt_call_cli().run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data["data"]["explicit_max_ttl"] != 1337
    assert ret.data["data"]["num_uses"] != 41  # one use is consumed by the lookup
