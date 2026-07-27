import pytest

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts"),
    pytest.mark.parametrize("secret_mounts", ("database",), indirect=True),
]


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_creds
            },
        }
    }


@pytest.mark.usefixtures("existing_alt_lease")
@pytest.mark.usefixtures("_multi_lease")
@pytest.mark.parametrize("_multi_lease", (False, True), indirect=True)
@pytest.mark.parametrize(
    "beacon_config", ({"check_server": False}, {"check_server": True}), indirect=True
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
        ({"check_server": True}, {}),
        ({"leases_type": dict, "per_lease_params": {"check_server": True}}, {}),
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
        ({"min_ttl": 7000}, {}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 7000}}, {}),
        ({}, {"valid_for": 7000}),
        ({"min_ttl": 300}, {"valid_for": 7000}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 300}}, {"valid_for": 7000}),
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
        ({"min_ttl": 8000}, {}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 8000}}, {}),
        ({}, {"valid_for": 8000}),
        ({"min_ttl": 300}, {"valid_for": 8000}),
        ({"leases_type": dict, "per_lease_params": {"min_ttl": 300}}, {"valid_for": 8000}),
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
        ({"meta": "foo.bar"}, {}, "foo.bar"),
        ({"leases_type": dict, "per_lease_params": {"meta": "foo.bar"}}, {}, "foo.bar"),
        ({}, {"meta": "foo.bar"}, "foo.bar"),
        ({"meta": "foo.bar"}, {"meta": "foo.baz"}, "foo.baz"),
        (
            {"leases_type": dict, "per_lease_params": {"meta": "foo.bar"}},
            {"meta": "foo.baz"},
            "foo.baz",
        ),
        ({"meta": "foo.bar"}, {"meta": ["foo.baz"]}, ["foo.baz"]),
        ({"meta": ["foo.bar"]}, {"meta": "foo.baz"}, "foo.baz"),
        ({"meta": ["foo.bar"]}, {"meta": {"foo": "baz"}}, {"foo": "baz"}),
        ({"meta": ["foo.bar"]}, {"meta": ["foo.baz"]}, ["foo.bar", "foo.baz"]),
        (
            {"meta": {"foo": {"bar": True}}},
            {"meta": {"foo": {"bar": False}}},
            {"foo": {"bar": False}},
        ),
        (
            {"meta": {"foo": {"bar": True}}},
            {"meta": {"foo": {"baz": False}}},
            {"foo": {"bar": True, "baz": False}},
        ),
        (
            {"meta": {"foo": {"bar": [True]}}},
            {"meta": {"foo": {"bar": [False]}}},
            {"foo": {"bar": [True, False]}},
        ),
        ({"meta": "foo"}, {"meta": {"foo": {"bar": False}}}, {"foo": {"bar": False}}),
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
