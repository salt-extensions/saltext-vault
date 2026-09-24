import pytest

from tests.common import gen_minion_opts
from tests.common.containers import genmarks

pytestmark = genmarks(mounts="database")


@pytest.fixture(scope="module")
def minion_config_overrides():
    return gen_minion_opts(backend="disk")


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (False, True), indirect=True)
@pytest.mark.parametrize(
    "beacon_config",
    (
        pytest.param({"check_server": False}, id="no_check_server"),
        pytest.param({"check_server": True}, id="check_server"),
    ),
    indirect=True,
)
def test_beacon_valid(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == []


@pytest.mark.parametrize("beacon_config", ({"leases": "foo.bar.baz"},), indirect=True)
def test_beacon_missing(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == [
        {
            "check_server": None,
            "ckey": "foo.bar.baz",
            "expired": True,
            "expires_in": -1,
            "meta": None,
            "min_ttl": 300,
            "tag": "expire",
        }
    ]


@pytest.mark.parametrize("beacon_config", ({"leases": ["foo.bar", "foo.baz"]},), indirect=True)
def test_beacon_missing_multi(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == [
        {
            "check_server": None,
            "ckey": "foo.bar",
            "expired": True,
            "expires_in": -1,
            "meta": None,
            "min_ttl": 300,
            "tag": "expire",
        },
        {
            "check_server": None,
            "ckey": "foo.baz",
            "expired": True,
            "expires_in": -1,
            "meta": None,
            "min_ttl": 300,
            "tag": "expire",
        },
    ]


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (True,), indirect=True)
@pytest.mark.usefixtures("revoked_lease")
def test_beacon_revoked_not_check_server(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert ret == []


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (True,), indirect=True)
@pytest.mark.usefixtures("revoked_lease", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params",
    (
        pytest.param({"check_server": True}, {}, id="global_param"),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"check_server": True}},
            {},
            id="per_lease_param",
        ),
    ),
    indirect=True,
)
def test_beacon_revoked_check_server(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, check_server=True, expired=True, expires_in=-1)


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params",
    (
        pytest.param({"min_ttl": 7000}, {}, id="global_min_ttl"),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"min_ttl": 7000}},
            {},
            id="per_lease_min_ttl",
        ),
        pytest.param({}, {"valid_for": 7000}, id="cached_valid_for"),
        pytest.param({"min_ttl": 300}, {"valid_for": 7000}, id="cached_overrides_global"),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"min_ttl": 300}},
            {"valid_for": 7000},
            id="cached_overrides_per_lease",
        ),
    ),
    indirect=True,
)
def test_beacon_min_ttl(beacon, beacon_config, vault_db, existing_lease):
    ret = beacon(beacon_config)
    assert ret == []
    info = vault_db.list_cached()[existing_lease]
    assert info["duration"] == 7000


@pytest.mark.usefixtures("beacon_config", "existing_lease")
@pytest.mark.parametrize(
    "beacon_config",
    ({"renew": False, "min_ttl": 7000},),
    indirect=True,
)
def test_beacon_not_renew(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, min_ttl=7000)


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params",
    (
        pytest.param({"min_ttl": 8000}, {}, id="global_min_ttl"),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"min_ttl": 8000}},
            {},
            id="per_lease_min_ttl",
        ),
        pytest.param({}, {"valid_for": 8000}, id="cached_valid_for"),
        pytest.param({"min_ttl": 300}, {"valid_for": 8000}, id="cached_overrides_global"),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"min_ttl": 300}},
            {"valid_for": 8000},
            id="cached_overrides_per_lease",
        ),
    ),
    indirect=True,
)
def test_beacon_min_ttl_unattainable(beacon, beacon_config):
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(
        ret,
        min_ttl=8000,
        duration=pytest.approx(7200, abs=60),
        expires_in=pytest.approx(7200, abs=60),
    )


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize(
    "beacon_config,lease_creation_params,expected_meta",
    (
        pytest.param({"meta": "foo.bar"}, {}, "foo.bar", id="global_str"),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"meta": "foo.bar"}},
            {},
            "foo.bar",
            id="per_lease_str",
        ),
        pytest.param({}, {"meta": "foo.bar"}, "foo.bar", id="cached_str"),
        pytest.param(
            {"meta": "foo.bar"}, {"meta": "foo.baz"}, "foo.baz", id="cached_overrides_global"
        ),
        pytest.param(
            {"leases_type": dict, "per_lease_params": {"meta": "foo.bar"}},
            {"meta": "foo.baz"},
            "foo.baz",
            id="cached_overrides_per_lease",
        ),
        pytest.param(
            {"meta": "foo.bar"}, {"meta": ["foo.baz"]}, ["foo.baz"], id="list_overrides_str"
        ),
        pytest.param(
            {"meta": ["foo.bar"]}, {"meta": "foo.baz"}, "foo.baz", id="str_overrides_list"
        ),
        pytest.param(
            {"meta": ["foo.bar"]},
            {"meta": {"foo": "baz"}},
            {"foo": "baz"},
            id="dict_overrides_list",
        ),
        pytest.param(
            {"meta": ["foo.bar"]},
            {"meta": ["foo.baz"]},
            ["foo.bar", "foo.baz"],
            id="lists_merge",
        ),
        pytest.param(
            {"meta": {"foo": {"bar": True}}},
            {"meta": {"foo": {"bar": False}}},
            {"foo": {"bar": False}},
            id="dicts_merge_overlapping",
        ),
        pytest.param(
            {"meta": {"foo": {"bar": True}}},
            {"meta": {"foo": {"baz": False}}},
            {"foo": {"bar": True, "baz": False}},
            id="dicts_merge_distinct",
        ),
        pytest.param(
            {"meta": {"foo": {"bar": [True]}}},
            {"meta": {"foo": {"bar": [False]}}},
            {"foo": {"bar": [True, False]}},
            id="nested_lists_merge",
        ),
        pytest.param(
            {"meta": "foo"},
            {"meta": {"foo": {"bar": False}}},
            {"foo": {"bar": False}},
            id="dict_overrides_str",
        ),
    ),
    indirect=("beacon_config", "lease_creation_params"),
)
def test_beacon_meta(beacon, beacon_config, expected_meta):
    beacon_config.append({"min_ttl": 10000})
    ret = beacon(beacon_config)
    assert len(ret) == 1
    ret = ret[0]
    _assert_evt(ret, min_ttl=10000, meta=expected_meta, duration=pytest.approx(7200, abs=60))


@pytest.mark.usefixtures("beacon_config", "lease_creation_params")
@pytest.mark.parametrize("beacon_config", ({"min_ttl": 8000},), indirect=True)
def test_beacon_failed_renewal_reports_fresh_info(beacon, beacon_config, vault_db, existing_lease):
    """
    When a renewal attempt does not manage to reach ``min_ttl``, the emitted
    event must reflect the lease state after the renewal attempt, not the
    stale snapshot from before it.
    """
    ret = beacon(beacon_config)
    assert len(ret) == 1
    evt = ret[0]
    info = vault_db.list_cached()[existing_lease]
    # Sanity check: the renewal attempt extended the cached lease close to max_ttl
    assert info["expires_in"] == pytest.approx(7200, abs=60)
    assert evt["expires_in"] == pytest.approx(info["expires_in"], abs=60)
    assert evt["duration"] == info["duration"]


def _assert_evt(evt, *remove, **expected):
    assert set(evt) == {
        "meta",
        "creation_time",
        "duration",
        "expired",
        "revoke_delay",
        "tag",
        "renew_increment",
        "renewable",
        "min_ttl",
        "check_server",
        "lease_id",
        "ckey",
        "expire_time",
        "expires_in",
    }
    expected = {
        "check_server": None,
        "ckey": "db.database.dynamic.testrole.default",
        # For renewals, we can't know what the max_ttl is, so this will be the default
        # duration.
        "duration": pytest.approx(3600, abs=60),
        "expired": False,
        "meta": None,
        "min_ttl": 300,
        "renew_increment": None,
        "renewable": True,
        "revoke_delay": None,
        "tag": "expire",
        **expected,
    }
    expected.update(expected)
    for unwanted in remove:
        expected.pop(unwanted, None)
    for param, val in expected.items():
        assert evt[param] == val
