import time
from unittest.mock import patch

import pytest

from saltext.vault.utils import vault
from saltext.vault.utils.vault import leases as vleases
from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # Backend is the same, regardless of Vault vs OpenBao
]


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "vault": {
            "cache": {
                "expire_events": True,
            },
        },
    }


@pytest.fixture
def _event():
    with patch("saltext.vault.utils.vault.factory._get_event", autospec=True) as evt:
        yield evt


@pytest.fixture(params=[({}, False)])
def lease(request):
    overrides, valid = request.param
    defaults = {
        "lease_id": "database/creds/testrole/deadbeef",
        "data": {"username": "u", "password": "p"},
        "lease_duration": 3600,
        "expire_time": round(time.time()) + (600 if valid else -600),
        "renewable": True,
    }
    defaults.update(overrides)
    return vleases.VaultLease(**defaults)  # type: ignore


@pytest.fixture
def store(minion_opts, context, lease, ckey, _event):  # pylint: disable=unused-argument
    store = vault.get_lease_store(minion_opts, context)
    store.store(ckey, lease)
    assert "vault/connection/session/leases" in context
    assert ckey in context["vault/connection/session/leases"]
    assert ckey in store.list()
    return store


@pytest.fixture
def context():
    return {}


@pytest.fixture
def ckey():
    return "test.foo.lease"


def test_lease_store_get_hard_expired_lease_is_flushed(store, ckey, context, _event):
    """
    A cached lease that has already expired must be removed from the cache when
    it is requested.
    """
    assert store.get(ckey) is None
    assert ckey not in context["vault/connection/session/leases"]
    assert ckey not in store.cache.list()
    assert ckey not in store.list()
    assert store.get(ckey) is None
    _event.return_value.assert_called_once_with(
        tag=f"vault/lease/{ckey}/expire",
        data={"valid_for_less": 0, "ttl": 0, "meta": None},
    )


@pytest.mark.usefixtures("lease")
@pytest.mark.parametrize(
    "lease", [({"min_ttl": 99999, "meta": {"foo": "bar"}}, True)], indirect=True
)
def test_lease_store_get_valid_for_less_flushes_lease_from_cache(store, ckey, context, _event):
    """
    When a lease undercuts its valid_for, it should be flushed.
    """
    assert store.get(ckey, renew=False) is None
    assert ckey not in context["vault/connection/session/leases"]
    assert ckey not in store.cache.list()
    assert ckey not in store.list()
    assert store.get(ckey) is None
    assert _event.return_value.call_args[1]["tag"] == f"vault/lease/{ckey}/expire"
    data = _event.return_value.call_args[1]["data"]
    assert data["valid_for_less"] == 99999
    assert 550 < data["ttl"] <= 600
    assert data["meta"] == {"foo": "bar"}


@pytest.mark.usefixtures("lease")
@pytest.mark.parametrize("lease", [({"check_server": True}, True)], indirect=True)
def test_lease_store_server_check_fail_flushes_lease_from_cache(store, ckey, context, _event):
    """
    When a lease does not exist on the server, it should be flushed.
    """
    assert store.get(ckey, check_server=True) is None
    assert ckey not in context["vault/connection/session/leases"]
    assert ckey not in store.cache.list()
    assert ckey not in store.list()
    assert store.get(ckey) is None
    _event.return_value.assert_called_once_with(
        tag=f"vault/lease/{ckey}/expire",
        data={"valid_for_less": 0, "ttl": 0, "meta": None},
    )
    assert store.get(ckey) is None


@pytest.mark.usefixtures("lease")
@pytest.mark.parametrize("lease", [({"check_server": True}, True)], indirect=True)
def test_lease_store_renew_fail_flushes_lease_from_cache(store, ckey, context, _event):
    """
    When a lease does not exist on the server, it should be flushed.
    """
    assert store.get(ckey, valid_for=999) is None
    assert ckey not in context["vault/connection/session/leases"]
    assert ckey not in store.cache.list()
    assert ckey not in store.list()
    assert store.get(ckey) is None
    _event.return_value.assert_called_once_with(
        tag=f"vault/lease/{ckey}/expire",
        data={"valid_for_less": 999, "ttl": 0, "meta": None},
    )
