"""
Ensure the beacon does not cause duplicate expiry events when
`cache:expire_events` is enabled.

The beacon reports expiring leases via its own return channel
(``salt/beacon/.../vault_lease_.../expire``). When the lease store it
employs internally is wired to fire ``vault/lease/<ckey>/expire`` events
as well, a single failed renewal results in two events for the same fact.
"""

from unittest.mock import patch

import pytest

from tests.common import gen_minion_opts
from tests.common.containers import genmarks

pytestmark = genmarks(mounts="database")


@pytest.fixture(scope="module")
def minion_config_overrides():
    # ensure a persistent cache is available for get_creds
    return gen_minion_opts(backend="disk", expire_events=True)


@pytest.fixture
def fired_events():
    events = []

    def _get_event(opts):  # pylint: disable=unused-argument
        def _fire(*, tag, data):
            events.append({"tag": tag, "data": data})
            return True

        return _fire

    with patch("saltext.vault.utils.vault.factory._get_event", _get_event):
        yield events


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize("beacon_config", ({"min_ttl": 8000},), indirect=True)
def test_beacon_does_not_fire_duplicate_expire_events(beacon, beacon_config, fired_events):
    """
    A failed renewal is reported via the beacon's return value already.
    The lease store employed by the beacon must not fire a separate
    expiry event for the same lease.
    """
    fired_events.clear()
    ret = beacon(beacon_config)
    assert len(ret) == 1
    expire_events = [evt for evt in fired_events if "expire" in (evt["tag"] or "")]
    assert not expire_events
