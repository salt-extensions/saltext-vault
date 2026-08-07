import pytest
import salt.cache

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]

CBANK = "vault/connection"
CKEY = "config"


@pytest.fixture(scope="module")
def master_config_overrides():
    # Ensure the minion caches the connection configuration on disk,
    # otherwise it does not persist between salt-call invocations.
    return {"vault": {"cache": {"backend": "disk"}}}


@pytest.fixture
def minion_conn_cache(minion, salt_call_cli):
    # Ensure the connection configuration is cached
    ret = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    cache = salt.cache.factory(minion.config)
    config = cache.fetch(CBANK, CKEY)
    assert config
    assert config["server"]["namespace"] is None
    return cache


def test_update_config_unchanged(salt_call_cli, minion_conn_cache):
    """
    When the master's configuration is compatible with the cached one,
    it should be updated in place.
    """
    ret = salt_call_cli.run("vault.update_config")
    assert ret.returncode == 0
    assert ret.data is True
    assert minion_conn_cache.fetch(CBANK, CKEY)


def test_update_config_compatible_change(salt_call_cli, minion_conn_cache):
    """
    Changed settings that do not require reauthentication, e.g.
    ``auth:token_lifecycle``, should be updated in place without
    invalidating the current session.
    """
    config = minion_conn_cache.fetch(CBANK, CKEY)
    # Simulate the master having changed a non-significant setting by
    # writing an outdated value into the minion's cache.
    current_ttl = config["auth"]["token_lifecycle"]["minimum_ttl"]
    assert current_ttl != 1337
    config["auth"]["token_lifecycle"]["minimum_ttl"] = 1337
    minion_conn_cache.store(CBANK, CKEY, config)
    token_before = minion_conn_cache.fetch(f"{CBANK}/session", "__token")
    assert token_before
    ret = salt_call_cli.run("vault.update_config")
    assert ret.returncode == 0
    assert ret.data is True
    updated = minion_conn_cache.fetch(CBANK, CKEY)
    assert updated["auth"]["token_lifecycle"]["minimum_ttl"] == current_ttl
    # The session should have been kept
    assert minion_conn_cache.fetch(f"{CBANK}/session", "__token") == token_before


@pytest.mark.parametrize("keep_session", (False, True))
def test_update_config_significant_change(salt_call_cli, minion_conn_cache, keep_session):
    """
    When the master's configuration differs significantly from the cached one,
    the caches should be flushed and new authentication credentials requested,
    unless ``keep_session`` is set.
    """
    config = minion_conn_cache.fetch(CBANK, CKEY)
    config["server"]["namespace"] = "tampered"
    minion_conn_cache.store(CBANK, CKEY, config)
    ret = salt_call_cli.run("vault.update_config", keep_session=keep_session)
    assert ret.returncode == 0
    if keep_session:
        assert ret.data is False
        # The cached configuration should not have been touched
        assert minion_conn_cache.fetch(CBANK, CKEY)["server"]["namespace"] == "tampered"
        # Restore the cached configuration for subsequent tests
        config["server"]["namespace"] = None
        minion_conn_cache.store(CBANK, CKEY, config)
    else:
        assert ret.data is True
        # The caches should have been flushed and a new configuration requested
        assert minion_conn_cache.fetch(CBANK, CKEY)["server"]["namespace"] is None
