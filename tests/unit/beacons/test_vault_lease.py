import pytest

import saltext.vault.beacons.vault_lease as lease


@pytest.fixture
def configure_loader_modules():
    return {
        lease: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.mark.parametrize(
    "config,exp",
    (
        ({}, "Configuration for vault_lease must be a list"),
        ([], "Requires monitored lease(s) cache key(s) in `leases`"),
        ([{"leases": 123}], "`leases` must be a dict, list or str"),
        ([{"leases": "foo"}], True),
        ([{"leases": "foo.*"}], "`leases` does not support globs"),
        ([{"leases": ["foo", "bar"]}], True),
        ([{"leases": ["foo", "bar.*"]}], "`leases` does not support globs"),
        ([{"leases": {"foo": "foo", "bar": "bar"}}], "`leases` mapping values must be dicts"),
        ([{"leases": {"foo": {}, "bar": {}}}], True),
        ([{"leases": {"foo": {"min_ttl": "1d"}, "bar": {}}}], True),
        ([{"leases": {"foo": {"min_ttl": "1d"}, "bar.*": {}}}], "`leases` does not support globs"),
    ),
)
def test_validate(config, exp):
    res, msg = lease.validate(config)
    if exp is True:
        assert res is True
    else:
        assert msg == exp


@pytest.mark.parametrize(
    "config,exp",
    (
        ([{"leases": "foo"}], {"leases": {"foo": {}}}),
        (
            [{"leases": "foo"}, {"min_ttl": 42}, {"check_server": True}, {"meta": "foo"}],
            {"leases": {"foo": {"min_ttl": 42, "check_server": True, "meta": "foo"}}},
        ),
        ([{"leases": ["foo", "bar"]}], {"leases": {"foo": {}, "bar": {}}}),
        (
            [{"leases": ["foo", "bar"]}, {"min_ttl": 42}, {"check_server": True}, {"meta": "foo"}],
            {
                "leases": {
                    "foo": {"min_ttl": 42, "check_server": True, "meta": "foo"},
                    "bar": {"min_ttl": 42, "check_server": True, "meta": "foo"},
                }
            },
        ),
        ([{"leases": {"foo": {}, "bar": {}}}], {"leases": {"foo": {}, "bar": {}}}),
        (
            [
                {"leases": {"foo": {}, "bar": {}}},
                {"min_ttl": 42},
                {"check_server": True},
                {"meta": "foo"},
            ],
            {
                "leases": {
                    "foo": {"min_ttl": 42, "check_server": True, "meta": "foo"},
                    "bar": {"min_ttl": 42, "check_server": True, "meta": "foo"},
                }
            },
        ),
        (
            [
                {"leases": {"foo": {"min_ttl": 1337}, "bar": {"check_server": False}}},
                {"min_ttl": 42},
                {"check_server": True},
                {"meta": "foo"},
            ],
            {
                "leases": {
                    "foo": {"min_ttl": 1337, "check_server": True, "meta": "foo"},
                    "bar": {"min_ttl": 42, "check_server": False, "meta": "foo"},
                }
            },
        ),
        (
            [
                {"leases": {"foo": {"min_ttl": None}, "bar": {"meta": "bar"}}},
                {"min_ttl": 42},
                {"check_server": True},
                {"meta": "foo"},
            ],
            {
                "leases": {
                    "foo": {"min_ttl": None, "check_server": True, "meta": "foo"},
                    "bar": {"min_ttl": 42, "check_server": True, "meta": "bar"},
                }
            },
        ),
        (
            [
                {"leases": {"foo": {"meta": ["foo"]}, "bar": {"meta": {"bar": True}}}},
                {"meta": "foo"},
            ],
            {"leases": {"foo": {"meta": ["foo"]}, "bar": {"meta": {"bar": True}}}},
        ),
        (
            [
                {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
                {"meta": ["foo"]},
            ],
            {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
        ),
        (
            [
                {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
                {"meta": {"foo": True}},
            ],
            {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
        ),
        (
            [{"leases": ["foo", "bar"]}, {"renew": False}],
            {"leases": {"foo": {"renew": False}, "bar": {"renew": False}}},
        ),
        (
            [{"leases": {"foo": {"renew": True}, "bar": {}}}, {"renew": False}],
            {"leases": {"foo": {"renew": True}, "bar": {"renew": False}}},
        ),
    ),
)
def test_render_config(config, exp):
    res = lease._render_config(config)
    assert res == exp


@pytest.mark.parametrize(
    "cfg,info,exp",
    (
        ({}, {"min_ttl": 1234, "meta": None}, {"min_ttl": 1234, "meta": None}),
        ({}, {"min_ttl": "1h", "meta": None}, {"min_ttl": "1h", "meta": None}),
        ({"min_ttl": "1h"}, {"min_ttl": None, "meta": None}, {"min_ttl": "1h", "meta": None}),
        (
            {"check_server": True},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": None, "check_server": True},
        ),
        (
            {"check_server": False},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": None, "check_server": False},
        ),
        ({"min_ttl": "2h"}, {"min_ttl": 3600, "meta": None}, {"min_ttl": "2h", "meta": None}),
        ({"min_ttl": "1h"}, {"min_ttl": "2h", "meta": None}, {"min_ttl": "2h", "meta": None}),
        ({}, {"min_ttl": None, "meta": "foo"}, {"min_ttl": 300, "meta": "foo"}),
        ({"min_ttl": 42}, {"min_ttl": None, "meta": None}, {"min_ttl": 42, "meta": None}),
        ({"meta": 123}, {"min_ttl": None, "meta": None}, {"min_ttl": 300, "meta": 123}),
        ({"meta": ["foo"]}, {"min_ttl": None, "meta": None}, {"min_ttl": 300, "meta": ["foo"]}),
        (
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": {"foo": True}},
        ),
        ({"meta": "foo"}, {"min_ttl": None, "meta": "bar"}, {"min_ttl": 300, "meta": "bar"}),
        ({"meta": ["foo"]}, {"min_ttl": None, "meta": "bar"}, {"min_ttl": 300, "meta": "bar"}),
        (
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": "bar"},
            {"min_ttl": 300, "meta": "bar"},
        ),
        (
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": ["bar"]},
            {"min_ttl": 300, "meta": ["bar"]},
        ),
        (
            {"meta": ["foo"]},
            {"min_ttl": None, "meta": {"bar": True}},
            {"min_ttl": 300, "meta": {"bar": True}},
        ),
        (
            {"meta": ["foo"]},
            {"min_ttl": None, "meta": ["bar"]},
            {"min_ttl": 300, "meta": ["foo", "bar"]},
        ),
        (
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": {"bar": True}},
            {"min_ttl": 300, "meta": {"foo": True, "bar": True}},
        ),
        (
            {"meta": {"foo": ["a"]}},
            {"min_ttl": None, "meta": {"foo": ["b"]}},
            {"min_ttl": 300, "meta": {"foo": ["a", "b"]}},
        ),
        (
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": {"foo": False}},
            {"min_ttl": 300, "meta": {"foo": False}},
        ),
    ),
)
def test_merge_lease_config(cfg, info, exp):
    res = lease._merge_lease_config(cfg, info)
    assert res == exp


@pytest.mark.parametrize(
    "cfg,info,exp",
    (
        (
            {"min_ttl": 1234},
            {"min_ttl": 42, "meta": None},
            {"ckey": "test.lease", "min_ttl": 1234, "meta": None, "check_server": None},
        ),
        (
            {"min_ttl": 300, "meta": "foo"},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": "foo", "check_server": None},
        ),
        (
            {"min_ttl": 300, "meta": ["foo"]},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": ["foo"], "check_server": None},
        ),
        (
            {"min_ttl": 300, "meta": {"foo": True}},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": {"foo": True}, "check_server": None},
        ),
        (
            {"min_ttl": 300, "check_server": False},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": None, "check_server": False},
        ),
        (
            {"min_ttl": 300, "check_server": True},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": None, "check_server": True},
        ),
        (
            {"min_ttl": 300, "check_server": True, "meta": "foo.bar"},
            {"expires_in": -1, "expired": True},
            {
                "ckey": "test.lease",
                "min_ttl": 300,
                "meta": "foo.bar",
                "check_server": True,
                "expires_in": -1,
                "expired": True,
            },
        ),
    ),
)
def test_enrich_info(cfg, info, exp):
    exp["tag"] = "expire"
    res = lease._enrich_info("test.lease", cfg, info)
    assert res == exp
