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
    pytest.mark.usefixtures(
        "container", "pillar_base", "secret_mounts", "vault_policies", "vault_secrets"
    ),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        # ensure approles/entities are generated during pillar rendering
        "ext_pillar": [{"vault": "secret/path/foo"}],
        "vault": {
            "cache": {
                "backend": "file",
            },
            "issue": {
                "type": "token",
                "token": {
                    "params": {
                        "num_uses": 0,
                    }
                },
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "salt_minion_{minion}",
                    "salt_role_{pillar[roles]}",
                ],
                "cache_time": 0,
            },
        },
    }


@pytest.fixture(scope="module")
def pillar_defaults():
    return {"roles": {"roles": ["dev", "web"]}}


@pytest.fixture(scope="module")
def vault_pillar_defaults():
    return {"secret/path/foo": {"success": "yeehaaw"}}


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
    config_data = b"\x84\xa4auth\x85\xadapprole_mount\xa7approle\xacapprole_name\xbavault-approle-int-minion-1\xa6method\xa7approle\xa7role_id\xactest-role-id\xa9secret_id\xc3\xa5cache\x83\xa7backend\xa4disk\xa6config\xcd\x0e\x10\xa6secret\xa3ttl\xa6client\x86\xabmax_retries\x05\xaebackoff_factor\xcb?\xd3333333\xabbackoff_max\x08\xaebackoff_jitter\xcb?\xf0\x00\x00\x00\x00\x00\x00\xaaretry_post\xc3\xb3respect_retry_after\xc3\xa6server\x83\xa9namespace\xc0\xa6verify\xc0\xa3url"
    config_data += (len(vault_url) + 160).to_bytes(1, "big") + vault_url.encode()
    config_cachefile = minion_conn_cachedir / "config.p"
    with salt.utils.files.fopen(config_cachefile, "wb") as f:
        f.write(config_data)
    try:
        yield
    finally:
        if config_cachefile.exists():
            config_cachefile.unlink()


@pytest.fixture
def cache_from_old_version(salt_call_cli, minion_conn_cachedir):
    """
    Removes any top-level keys from cached config except
    for auth, cache and server.
    Added when ``client`` was introduced to the config to
    simulate upgrades from old versions.
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    config_cachefile = minion_conn_cachedir / "config.p"
    assert config_cachefile.exists()
    cached_config = salt.utils.data.decode(salt.utils.msgpack.loads(config_cachefile.read_bytes()))
    old_params = {}
    for param in ("auth", "cache", "server"):
        old_params[param] = cached_config.pop(param)
    config_cachefile.write_bytes(salt.utils.msgpack.dumps(old_params))
    cached_config.update(old_params)
    try:
        yield cached_config
    finally:
        if config_cachefile.exists():
            config_cachefile.unlink()


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


@pytest.mark.usefixtures("cache_from_old_version")
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
