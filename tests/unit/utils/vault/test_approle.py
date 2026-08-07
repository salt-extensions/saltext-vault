from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.vault.utils import vault
from saltext.vault.utils.vault import api as vapi
from saltext.vault.utils.vault import approle as vapprole
from saltext.vault.utils.vault import cache as vcache
from saltext.vault.utils.vault import leases as vleases

pytestmark = [pytest.mark.usefixtures("time_stopped")]

CKEY = "secid.salt-minions.myrole.default"


@pytest.fixture
def secid():
    return vleases.VaultSecretId(
        secret_id="test-secret-id",
        secret_id_ttl=1337,
        secret_id_num_uses=3,
        secret_id_accessor="test-accessor",
        creation_time=0,
        expiration_time=1337,
    )


@pytest.fixture
def secret_id_meta():
    return {
        "cidr_list": [],
        "creation_time": 0,
        "expiration_time": 1337,
        "last_updated_time": 0,
        "metadata": {},
        "secret_id_accessor": "test-accessor",
        "secret_id_num_uses": 3,
        "secret_id_ttl": 1337,
        "token_bound_cidrs": [],
    }


@pytest.fixture
def api(secret_id_meta):
    _api = Mock(spec=vapi.AppRoleApi)
    _api.read_secret_id.return_value = secret_id_meta
    return _api


@pytest.fixture
def cache(secid):
    _cache = Mock(spec=vcache.VaultLeaseCache)
    _cache.get.return_value = secid
    _cache.list.return_value = {CKEY}
    return _cache


@pytest.fixture
def store(api, cache):
    return vapprole.SecretIdStore(api, cache)


def test_get_store_converts_errors():
    """
    Ensure exceptions during API initialization (e.g. authentication
    failures) are converted into CommandExecutionError
    """
    with patch(
        "saltext.vault.utils.vault.approle.get_approle_api",
        autospec=True,
        side_effect=vault.VaultAuthExpired("token expired"),
    ):
        with pytest.raises(CommandExecutionError, match="VaultAuthExpired: token expired"):
            vapprole.get_store({}, {})


@pytest.mark.parametrize("destroy", (False, True))
def test_get_valid(store, cache, api, secid, destroy):
    res = store.get(CKEY, destroy=destroy)
    assert res is secid
    cache.get.assert_called_once_with(CKEY, flush=destroy)
    api.read_secret_id.assert_called_once_with(
        "myrole", accessor="test-accessor", mount="salt-minions"
    )
    api.destroy_secret_id.assert_not_called()
    # The lookup meta matched the cached data, no update should have happened
    cache.store.assert_not_called()


@pytest.mark.parametrize("destroy", (False, True))
def test_get_insufficient_validity(store, cache, api, destroy):
    """
    When the cached SecretID is not valid for the requested amount of time,
    it should only be destroyed and flushed if ``destroy`` is set.
    """
    res = store.get(CKEY, valid_for=99999, destroy=destroy)
    assert res is None
    if destroy:
        api.destroy_secret_id.assert_called_once_with(
            "myrole", accessor="test-accessor", mount="salt-minions"
        )
        cache.flush.assert_called_once_with(CKEY)
    else:
        api.destroy_secret_id.assert_not_called()
        cache.flush.assert_not_called()


@pytest.mark.parametrize("destroy", (False, True))
def test_get_missing_upstream(store, cache, api, destroy):
    """
    When the cached SecretID does not exist on the server anymore,
    the cache should only be flushed if ``destroy`` is set.
    """
    api.read_secret_id.side_effect = vault.VaultNotFoundError
    res = store.get(CKEY, destroy=destroy)
    assert res is None
    api.destroy_secret_id.assert_not_called()
    if destroy:
        cache.flush.assert_called_once_with(CKEY)
    else:
        cache.flush.assert_not_called()


def test_get_uncached(store, cache, api):
    cache.get.return_value = None
    assert store.get(CKEY) is None
    api.read_secret_id.assert_not_called()


def test_get_invalid_ckey(store, api):
    with pytest.raises(vault.VaultInvocationError, match="Invalid cache key"):
        store.get("invalid_ckey")
    api.read_secret_id.assert_not_called()


def test_get_updates_cache_on_changed_meta(store, cache, secid, secret_id_meta):
    """
    When the server-side lookup reports changed metadata, the cached
    SecretID should be updated accordingly, keeping its authentication
    data and accessor.
    """
    secret_id_meta["expiration_time"] = 2000
    secret_id_meta["secret_id_num_uses"] = 2
    res = store.get(CKEY)
    assert res is secid
    cache.store.assert_called_once()
    ckey, stored = cache.store.call_args[0]
    assert ckey == CKEY
    assert str(stored) == "test-secret-id"
    assert stored.accessor == "test-accessor"
    assert stored.expire_time == 2000
    assert stored.num_uses == 2
    assert stored.duration == secid.duration


def test_list_cached_info_skips_vanished(store, cache, secid):
    """
    Cached SecretIDs that vanish between listing and retrieval
    (e.g. because they expired) should be skipped.
    """
    vanished_ckey = "secid.salt-minions.otherrole.default"
    cache.list.return_value = {CKEY, vanished_ckey}
    cache.get.side_effect = lambda ckey, **_: secid if ckey == CKEY else None
    res = store.list_cached_info()
    assert list(res) == [CKEY]
    assert res[CKEY]["expires_in"] == 1337
    assert res[CKEY]["expired"] is False
    assert "id" not in res[CKEY]
    assert "lease_id" not in res[CKEY]


def test_list_cached_info_respects_match(store, cache):
    """
    Cache keys that do not match the requested pattern should be
    skipped without accessing the cache.
    """
    other_ckey = "secid.other-mount.myrole.default"
    cache.list.return_value = {CKEY, other_ckey}
    res = store.list_cached_info(match="secid.salt-minions.*")
    assert list(res) == [CKEY]
    cache.get.assert_called_once_with(CKEY, flush=False)


def test_destroy_ignores_missing(store, api, secid):
    api.destroy_secret_id.side_effect = vault.VaultNotFoundError
    store.destroy("myrole", secid, mount="salt-minions")
    api.destroy_secret_id.assert_called_once_with(
        "myrole", accessor="test-accessor", mount="salt-minions"
    )


@pytest.mark.parametrize("flush_on_failure", (False, True))
def test_destroy_cached_permission_denied(store, cache, api, flush_on_failure):
    """
    When the token lacks permissions to destroy a SecretID, an exception
    should be raised at the end and the cache only flushed if
    ``flush_on_failure`` is set.
    """
    api.destroy_secret_id.side_effect = vault.VaultPermissionDeniedError("denied")
    with pytest.raises(vault.VaultException, match="Failed deleting some SecretIDs"):
        store.destroy_cached(flush_on_failure=flush_on_failure)
    if flush_on_failure:
        cache.flush.assert_called_once_with(CKEY)
    else:
        cache.flush.assert_not_called()
