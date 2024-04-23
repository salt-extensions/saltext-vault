import logging
from unittest.mock import Mock
from unittest.mock import call
from unittest.mock import patch

import pytest

from saltext.vault.utils import vault
from saltext.vault.utils.vault import cache as vcache
from saltext.vault.utils.vault import client as vclient
from saltext.vault.utils.vault import leases as vleases

pytestmark = [pytest.mark.usefixtures("time_stopped")]


@pytest.fixture
def lease_renewed_response():
    return {
        "lease_id": "database/creds/testrole/abcd",
        "renewable": True,
        "lease_duration": 2000,
    }


@pytest.fixture
def lease_renewed_extended_response():
    return {
        "lease_id": "database/creds/testrole/abcd",
        "renewable": True,
        "lease_duration": 3000,
    }


@pytest.fixture
def store(events):
    client = Mock(spec=vclient.AuthenticatedVaultClient)
    cache = Mock(spec=vcache.VaultLeaseCache)
    cache.exists.return_value = False
    cache.get.return_value = None
    return vleases.LeaseStore(client, cache, expire_events=events)


@pytest.fixture
def store_valid(store, lease, lease_renewed_response):
    store.cache.exists.return_value = True
    store.cache.get.return_value = vleases.VaultLease(**lease)
    store.client.post.return_value = lease_renewed_response
    return store


@pytest.fixture
def store_multi(store, lease, lease_renewed_response):
    lease = vleases.VaultLease(**lease)
    lease_2 = lease.with_renewed(id="foobar", lease_id="foobar")
    lease_3 = lease.with_renewed(id="barbaz", lease_id="barbaz")
    leases = {"test_1": lease, "test_12": lease_2, "test_3": lease_3}
    store.cache.exists.side_effect = lambda x, **y: x in leases
    store.cache.get.side_effect = lambda x, **y: leases[x]
    store.cache.list.return_value = list(leases)
    store.client.post.return_value = lease_renewed_response
    return store


@pytest.mark.parametrize(
    "creation_time",
    [
        1661188581,
        "1661188581",
        "2022-08-22T17:16:21.473219641+00:00",
        "2022-08-22T17:16:21.47321964+00:00",
        "2022-08-22T17:16:21.4732196+00:00",
        "2022-08-22T17:16:21.473219+00:00",
        "2022-08-22T17:16:21.47321+00:00",
        "2022-08-22T17:16:21.4732+00:00",
        "2022-08-22T17:16:21.473+00:00",
        "2022-08-22T17:16:21.47+00:00",
        "2022-08-22T17:16:21.4+00:00",
    ],
)
def test_vault_lease_creation_time_normalization(creation_time):
    """
    Ensure the normalization of different creation_time formats works as expected -
    many token endpoints report a timestamp, while other endpoints report RFC3339-formatted
    strings that may have a variable number of digits for sub-second precision (0 omitted)
    while datetime.fromisoformat expects exactly 6 digits
    """
    data = {
        "lease_id": "id",
        "renewable": False,
        "lease_duration": 1337,
        "creation_time": creation_time,
        "data": None,
    }
    res = vleases.VaultLease(**data)
    assert res.creation_time == 1661188581


@pytest.mark.parametrize(
    "time_stopped,duration,offset,expected",
    [
        (0, 50, 0, True),
        (50, 10, 0, False),
        (0, 60, 10, True),
        (0, 60, 600, False),
    ],
    indirect=["time_stopped"],
)
def test_vault_lease_is_valid_accounts_for_time(duration, offset, expected):
    """
    Ensure lease validity is checked correctly and can look into the future
    """
    data = {
        "lease_id": "id",
        "renewable": False,
        "lease_duration": duration,
        "creation_time": 0,
        "expire_time": duration,
        "data": None,
    }
    res = vleases.VaultLease(**data)
    assert res.is_valid_for(offset) is expected


@pytest.mark.parametrize(
    "time_stopped,duration,offset,expected",
    [
        (0, 50, 0, True),
        (50, 10, 0, False),
        (0, 60, 10, True),
        (0, 60, 600, False),
    ],
    indirect=["time_stopped"],
)
def test_vault_token_is_valid_accounts_for_time(duration, offset, expected):
    """
    Ensure token time validity is checked correctly and can look into the future
    """
    data = {
        "client_token": "id",
        "renewable": False,
        "lease_duration": duration,
        "num_uses": 0,
        "creation_time": 0,
        "expire_time": duration,
    }
    res = vault.VaultToken(**data)
    assert res.is_valid_for(offset) is expected


@pytest.mark.parametrize(
    "num_uses,uses,expected",
    [(0, 999999, True), (1, 0, True), (1, 1, False), (1, 2, False)],
)
def test_vault_token_is_valid_accounts_for_num_uses(num_uses, uses, expected):
    """
    Ensure token uses validity is checked correctly
    """
    data = {
        "client_token": "id",
        "renewable": False,
        "lease_duration": 0,
        "num_uses": num_uses,
        "creation_time": 0,
        "use_count": uses,
    }
    with patch(
        "saltext.vault.utils.vault.leases.BaseLease.is_valid_for",
        autospec=True,
        return_value=True,
    ):
        res = vault.VaultToken(**data)
        assert res.is_valid() is expected


@pytest.mark.parametrize(
    "time_stopped,duration,offset,expected",
    [
        (0, 50, 0, True),
        (50, 10, 0, False),
        (0, 60, 10, True),
        (0, 60, 600, False),
    ],
    indirect=["time_stopped"],
)
def test_vault_approle_secret_id_is_valid_accounts_for_time(duration, offset, expected):
    """
    Ensure secret ID time validity is checked correctly and can look into the future
    """
    data = {
        "secret_id": "test-secret-id",
        "renewable": False,
        "creation_time": 0,
        "expiration_time": duration,
        "secret_id_num_uses": 0,
        "secret_id_ttl": duration,
    }
    res = vault.VaultSecretId(**data)
    assert res.is_valid(offset) is expected


@pytest.mark.parametrize(
    "num_uses,uses,expected",
    [(0, 999999, True), (1, 0, True), (1, 1, False), (1, 2, False)],
)
def test_vault_approle_secret_id_is_valid_accounts_for_num_uses(num_uses, uses, expected):
    """
    Ensure secret ID uses validity is checked correctly
    """
    data = {
        "secret_id": "test-secret-id",
        "renewable": False,
        "creation_time": 0,
        "secret_id_ttl": 0,
        "secret_id_num_uses": num_uses,
        "use_count": uses,
    }
    with patch(
        "saltext.vault.utils.vault.leases.BaseLease.is_valid_for",
        autospec=True,
        return_value=True,
    ):
        res = vault.VaultSecretId(**data)
        assert res.is_valid() is expected


class TestLeaseStore:
    """
    Vault Lease Tests
    """

    def test_get_uncached_or_invalid(self, store):
        """
        Ensure uncached or invalid leases are reported as None.
        """
        ret = store.get("test")
        assert ret is None
        store.client.post.assert_not_called()
        store.cache.flush.assert_not_called()
        store.cache.store.assert_not_called()

    def test_get_cached_valid(self, store_valid, lease):
        """
        Ensure valid leases are returned without extra behavior.
        """
        ret = store_valid.get("test")
        assert ret == lease
        store_valid.client.post.assert_not_called()
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_not_called()

    @pytest.mark.parametrize("valid_for", [2000, pytest.param(2002, id="2002_renewal_leeway")])
    def test_get_valid_renew_default_period(self, store_valid, lease, valid_for):
        """
        Ensure renewals are attempted by default, the cache is updated accordingly
        and validity checks after renewal allow for a little leeway to account
        for latency.
        """
        ret = store_valid.get("test", valid_for=valid_for)
        lease["duration"] = lease["expire_time"] = 2000
        assert ret == lease
        store_valid.client.post.assert_called_once_with(
            "sys/leases/renew", payload={"lease_id": lease["id"]}
        )
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_called_once_with("test", ret)
        store_valid.expire_events.assert_not_called()

    @pytest.mark.parametrize("lease", ({"min_ttl": 3000},), indirect=True)
    def test_get_valid_renew_min_ttl_on_lease(
        self, store_valid, lease, lease_renewed_extended_response
    ):
        """
        Ensure that even if the cached lease fulfills the requested valid_for,
        that a renewal is attempted if min_ttl is higher.
        """
        store_valid.client.post.return_value = lease_renewed_extended_response
        ret = store_valid.get("test", valid_for=1200)
        lease["duration"] = lease["expire_time"] = 3000
        assert ret == lease
        store_valid.client.post.assert_called_once_with(
            "sys/leases/renew", payload={"lease_id": lease["id"]}
        )
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_called_once_with("test", ret)
        store_valid.expire_events.assert_not_called()

    @pytest.mark.parametrize("lease", ({"min_ttl": 3000},), indirect=True)
    def test_get_valid_renew_min_ttl_on_lease_undercut(
        self, store_valid, lease, lease_renewed_response
    ):
        """
        Ensure that even if the cached lease fulfills the requested valid_for
        and a renewal still undercuts it, nothing is returned
        """
        store_valid.client.post.return_value = lease_renewed_response
        ret = store_valid.get("test", valid_for=1200)
        assert ret is None
        store_valid.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"]},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": 3000},
                ),
            )
        )
        store_valid.cache.flush.assert_called_once_with("test")
        store_valid.expire_events.assert_called_once_with(
            tag="vault/lease/test/expire",
            data={"valid_for_less": 3000, "ttl": 2000, "meta": lease["meta"]},
        )

    @pytest.mark.parametrize("lease", ({"renew_increment": 2005},), indirect=True)
    def test_get_valid_renew_lease_default_period(self, store_valid, lease):
        """
        Ensure that renewals without increment override respect the value
        set on the lease during creation.
        """
        ret = store_valid.get("test", valid_for=2000)
        lease["duration"] = lease["expire_time"] = 2000
        assert ret == lease
        store_valid.client.post.assert_called_once_with(
            "sys/leases/renew",
            payload={"lease_id": lease["id"], "increment": lease["renew_increment"]},
        )
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_called_once_with("test", ret)
        store_valid.expire_events.assert_not_called()

    @pytest.mark.parametrize(
        "lease", ({}, {"renew_increment": 1999}, {"renew_increment": 2001}), indirect=True
    )
    def test_get_valid_renew_increment(self, store_valid, lease):
        """
        Ensure renew_increment is honored when renewing and overrides the one
        set on the lease only if it does not undercut it.
        """
        ret = store_valid.get("test", valid_for=1400, renew_increment=2000)
        lease["duration"] = lease["expire_time"] = 2000
        assert ret == lease
        store_valid.client.post.assert_called_once_with(
            "sys/leases/renew",
            payload={
                "lease_id": lease["id"],
                "increment": max(lease["renew_increment"] or 0, 2000),
            },
        )
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_called_once_with("test", ret)
        store_valid.expire_events.assert_not_called()

    def test_get_valid_renew_increment_insufficient(self, store_valid, lease):
        """
        Ensure that when renew_increment is set, valid_for is respected and that
        a second renewal using valid_for as increment is not attempted when the
        Vault server does not allow renewals for at least valid_for.
        If an event factory was passed, an event should be sent.
        """
        ret = store_valid.get("test", valid_for=2100, renew_increment=3000)
        assert ret is None
        store_valid.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": 3000},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": 60},
                ),
            )
        )
        store_valid.cache.flush.assert_called_once_with("test")
        store_valid.expire_events.assert_called_once_with(
            tag="vault/lease/test/expire", data={"valid_for_less": 2100, "ttl": 2000, "meta": None}
        )

    @pytest.mark.parametrize("lease", ({"min_ttl": 2100},), indirect=True)
    def test_get_valid_renew_increment_undercuts_min_ttl(
        self, store_valid, lease, caplog, lease_renewed_response, lease_renewed_extended_response
    ):
        """
        Ensure that when a renew_increment undercuts the lease's default
        min_ttl, the renewal is first attempted without a renew_increment
        and if it still undercuts the min_ttl, a second one is attempted
        with the min_ttl as the increment.
        The user should be warned about the invalid request.
        """
        store_valid.client.post.side_effect = (
            lease_renewed_response,
            lease_renewed_extended_response,
        )
        with caplog.at_level(logging.WARNING):
            ret = store_valid.get("test", valid_for=1500, renew_increment=1600)
            assert "Dropping requested renew_increment" in caplog.text
        lease["duration"] = lease["expire_time"] = 3000
        assert ret == lease

        store_valid.client.post.assert_has_calls(
            (
                call("sys/leases/renew", payload={"lease_id": lease["id"]}),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": lease["min_ttl"]},
                ),
            )
        )
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_called_with("test", ret)
        store_valid.expire_events.assert_not_called()

    @pytest.mark.parametrize("valid_for", [3000, pytest.param(3002, id="3002_renewal_leeway")])
    def test_get_valid_renew_valid_for(
        self,
        store_valid,
        lease,
        valid_for,
        lease_renewed_response,
        lease_renewed_extended_response,
    ):  # pylint: disable-msg=too-many-arguments
        """
        Ensure that, if renew_increment was not set and the default period
        does not yield valid_for, a second renewal is attempted by valid_for.
        There should be some leeway by default to account for latency.
        """
        store_valid.client.post.side_effect = (
            lease_renewed_response,
            lease_renewed_extended_response,
        )
        ret = store_valid.get("test", valid_for=valid_for)
        lease["duration"] = lease["expire_time"] = 3000
        assert ret == lease
        store_valid.client.post.assert_has_calls(
            (
                call("sys/leases/renew", payload={"lease_id": lease["id"]}),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": valid_for},
                ),
            )
        )
        store_valid.cache.flush.assert_not_called()
        store_valid.cache.store.assert_called_with("test", ret)
        store_valid.expire_events.assert_not_called()

    @pytest.mark.parametrize("lease", ({}, {"meta": {"foo": "bar"}}), indirect=True)
    def test_get_valid_not_renew(self, store_valid, lease):
        """
        Currently valid leases should not be returned if they undercut
        valid_for. By default, revocation should be attempted and the cache
        should be flushed. If an event factory was passed, an event should be sent
        which includes the per-lease metadata.
        """
        ret = store_valid.get("test", valid_for=2000, renew=False)
        assert ret is None
        store_valid.cache.store.assert_not_called()
        store_valid.client.post.assert_called_once_with(
            "sys/leases/renew", payload={"lease_id": lease["id"], "increment": 60}
        )
        store_valid.cache.flush.assert_called_once_with("test")
        store_valid.expire_events.assert_called_once_with(
            tag="vault/lease/test/expire",
            data={"valid_for_less": 2000, "ttl": 1337, "meta": lease["meta"]},
        )

    @pytest.mark.parametrize(
        "lease", ({}, {"revoke_delay": 1200}, {"revoke_delay": 1400}), indirect=True
    )
    @pytest.mark.parametrize("revoke", (None, 1100, 1500))
    def test_get_valid_revoke(self, store_valid, lease, revoke):
        """
        Ensure revoke is honored when revoking and overrides the revoke_delay
        set on the lease. Also ensure the revoke_delay on the lease is
        the default.
        """
        ret = store_valid.get("test", valid_for=3500, revoke=revoke)
        assert ret is None
        store_valid.client.post.assert_called_with(
            "sys/leases/renew",
            payload={"lease_id": lease["id"], "increment": revoke or lease["revoke_delay"] or 60},
        )
        store_valid.cache.flush.assert_called_once_with("test")
        store_valid.expire_events.assert_called_once_with(
            tag="vault/lease/test/expire",
            data={"valid_for_less": 3500, "ttl": 2000, "meta": lease["meta"]},
        )

    def test_get_valid_not_flush(self, store_valid):
        """
        Currently valid leases should not be returned if they undercut
        valid_for and should not be revoked if requested so.
        If an event factory was passed, an event should be sent.
        """
        ret = store_valid.get("test", valid_for=2000, revoke=False, renew=False)
        assert ret is None
        store_valid.cache.flush.assert_not_called()
        store_valid.client.post.assert_not_called()
        store_valid.cache.store.assert_not_called()
        store_valid.expire_events.assert_called_once_with(
            tag="vault/lease/test/expire", data={"valid_for_less": 2000, "ttl": 1337, "meta": None}
        )

    @pytest.mark.parametrize("check_server", (False, True))
    @pytest.mark.parametrize("expected", (False, True))
    def test_get_check_server(
        self,
        store_valid,
        lease,
        expected,
        check_server,
        lease_lookup_response,
        lease_renewed_response,
    ):
        """
        Ensure that "valid" leases are validated with the server only if requested.
        """
        if expected:
            store_valid.client.post.return_value = lease_lookup_response
        else:
            store_valid.client.post.side_effect = (
                vault.VaultInvocationError("invalid lease"),
                lease_renewed_response,
            )
        ret = store_valid.get("test", valid_for=1300, check_server=check_server)
        assert (ret == lease) is (expected or not check_server)
        if check_server:
            if expected:
                store_valid.client.post.assert_called_once_with(
                    "sys/leases/lookup", payload={"lease_id": lease["id"]}
                )
                store_valid.cache.flush.assert_not_called()
                store_valid.expire_events.assert_not_called()
            else:
                store_valid.client.post.assert_has_calls(
                    (
                        call("sys/leases/lookup", payload={"lease_id": lease["id"]}),
                        call(
                            "sys/leases/renew",
                            payload={"lease_id": lease["id"], "increment": 60},
                        ),
                    )
                )
                store_valid.cache.flush.assert_called_once_with("test")
                store_valid.expire_events.assert_called_once_with(
                    tag="vault/lease/test/expire",
                    data={"valid_for_less": 1300, "ttl": 0, "meta": lease["meta"]},
                )
        else:
            store_valid.client.post.assert_not_called()
            store_valid.expire_events.assert_not_called()
        store_valid.cache.store.assert_not_called()

    @pytest.mark.parametrize("on_call", (1, 2))
    def test_get_renew_already_revoked(self, store_valid, on_call, lease_renewed_response):
        """
        Ensure there's no crash when a renewal is attempted on a revoked lease
        and that the cache is flushed.
        """
        store_valid.client.post.side_effect = (
            (on_call - 1) * [lease_renewed_response]
            + [vault.VaultInvocationError("lease not found")]
            + [lease_renewed_response]
        )
        ret = store_valid.get("test", valid_for=3000)
        assert ret is None
        store_valid.cache.flush.assert_called_once_with("test")
        store_valid.expire_events.assert_called_once_with(
            tag="vault/lease/test/expire", data={"valid_for_less": 3000, "ttl": 0, "meta": None}
        )

    @pytest.mark.parametrize("as_str", (False, True))
    def test_revoke_already_revoked(self, store_valid, lease, as_str):
        """
        A notfound exception should not matter for revoking.
        """
        store_valid.client.post.side_effect = vault.VaultInvocationError("lease not found")
        lease = vault.VaultLease(**lease)
        if as_str:
            lease = str(lease)
        assert store_valid.revoke(lease) is True

    def test_revoke_delay_should_have_a_minimum_of_1(self, store_valid, lease):
        """
        Since revocation internally uses renewals by setting the lease
        validity to a low value, a minimum value of 1 must be enforced,
        otherwise the lease is renewed by its default TTL.
        """
        assert store_valid.revoke(lease["id"], delta=0) is True
        store_valid.client.post.assert_called_once_with(
            "sys/leases/renew", payload={"lease_id": lease["id"], "increment": 1}
        )

    def test_list_info(self, store_multi, lease):
        """
        Test listing cached leases.
        """
        ret = store_multi.list_info()
        assert set(ret) == {"test_1", "test_12", "test_3"}
        lease.pop("data")
        lease["expires_in"] = 1337
        lease["expired"] = False
        assert ret["test_1"] == lease
        assert ret["test_12"]["lease_id"] == "foobar"
        assert ret["test_3"]["lease_id"] == "barbaz"

    def test_list_info_match(self, store_multi, lease):
        """
        Test listing cached leases with a glob.
        """
        ret = store_multi.list_info(match="test_1*")
        assert set(ret) == {"test_1", "test_12"}
        lease.pop("data")
        lease["expires_in"] = 1337
        lease["expired"] = False
        assert ret["test_1"] == lease
        assert ret["test_12"]["lease_id"] == "foobar"

    def test_list_info_expired(self, store_multi, lease):
        """
        The list should not contain expired leases, but they should
        not be flushed from cache during the call.
        """
        prev = store_multi.cache.get.side_effect
        store_multi.cache.get.side_effect = lambda x, **y: prev(x, **y) if x != "test_12" else None
        ret = store_multi.list_info(match="test_1*")
        assert set(ret) == {"test_1"}
        lease.pop("data")
        lease["expires_in"] = 1337
        lease["expired"] = False
        assert ret["test_1"] == lease
        store_multi.cache.get.assert_called_with("test_12", flush=False)

    def test_renew_cached(self, store_multi, lease):
        """
        Test renewing all cached leases.
        """
        assert store_multi.renew_cached() is True
        store_multi.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"]},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "foobar"},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "barbaz"},
                ),
            )
        )

    def test_renew_cached_match(self, store_multi, lease):
        """
        Test renewing all cached leases that match a glob.
        """
        assert store_multi.renew_cached(match="test_1*") is True
        store_multi.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"]},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "foobar"},
                ),
            )
        )

    def test_renew_cached_expired(self, store_multi, lease):
        """
        Expired leases should be skipped and they should be flushed
        from cache during the call.
        """
        prev = store_multi.cache.get.side_effect
        store_multi.cache.get.side_effect = lambda x, **y: prev(x, **y) if x != "test_12" else None
        assert store_multi.renew_cached(match="test_1*") is True
        store_multi.client.post.assert_called_once_with(
            "sys/leases/renew", payload={"lease_id": lease["id"]}
        )
        store_multi.cache.get.assert_called_with("test_12", flush=True)

    @pytest.mark.parametrize("exc", (vault.VaultNotFoundError, vault.VaultPermissionDeniedError))
    def test_renew_cached_exception(self, store_multi, exc, lease_renewed_response, lease):
        """
        Ensure that exceptions are reraised after everything has been processed.
        """
        store_multi.client.post.side_effect = [lease_renewed_response, exc, lease_renewed_response]
        with pytest.raises(
            vault.VaultException, match=r"Failed renewing some leases: \['test_12'\]"
        ):
            store_multi.renew_cached()
        store_multi.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"]},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "foobar"},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "barbaz"},
                ),
            )
        )

    def test_revoke_cached(self, store_multi, lease):
        """
        Test revoking all cached leases.
        """
        assert store_multi.revoke_cached() is True
        store_multi.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": 60},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "foobar", "increment": 60},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "barbaz", "increment": 60},
                ),
            )
        )

    def test_revoke_cached_match(self, store_multi, lease):
        """
        Test revoking all cached leases that match a glob.
        """
        assert store_multi.revoke_cached(match="test_1*", delta=120) is True
        store_multi.client.post.assert_has_calls(
            (
                call(
                    "sys/leases/renew",
                    payload={"lease_id": lease["id"], "increment": 120},
                ),
                call(
                    "sys/leases/renew",
                    payload={"lease_id": "foobar", "increment": 120},
                ),
            )
        )

    def test_revoke_cached_expired(self, store_multi, lease):
        """
        Expired leases should be skipped and they should be flushed
        from cache during the call.
        """
        prev = store_multi.cache.get.side_effect
        store_multi.cache.get.side_effect = lambda x, **y: prev(x, **y) if x != "test_12" else None
        assert store_multi.revoke_cached(match="test_1*") is True
        store_multi.client.post.assert_called_once_with(
            "sys/leases/renew", payload={"lease_id": lease["id"], "increment": 60}
        )
        store_multi.cache.get.assert_called_with("test_12", flush=True)

    @pytest.mark.parametrize("flush_on_failure", (False, True))
    def test_revoke_cached_exception(self, store_multi, lease_renewed_response, flush_on_failure):
        """
        Ensure that exceptions are reraised after everything has been processed.
        The cached leases should only be flushed from cache if it was requested.
        """
        store_multi.client.post.side_effect = [
            lease_renewed_response,
            vault.VaultPermissionDeniedError,
            lease_renewed_response,
        ]
        with pytest.raises(
            vault.VaultException, match=r"Failed revoking some leases: \['test_12'\]"
        ):
            store_multi.revoke_cached(flush_on_failure=flush_on_failure)
        if flush_on_failure:
            store_multi.cache.flush.assert_has_calls(
                (call("test_1"), call("test_12"), call("test_3"))
            )
        else:
            store_multi.cache.flush.assert_has_calls((call("test_1"), call("test_3")))
