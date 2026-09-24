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
        pytest.param({}, "Configuration for vault_lease must be a list", id="not_a_list"),
        pytest.param(
            [], "Requires monitored lease(s) cache key(s) in `leases`", id="missing_leases"
        ),
        pytest.param(
            [{"leases": 123}], "`leases` must be a dict, list or str", id="invalid_leases_type"
        ),
        pytest.param([{"leases": "foo"}], True, id="str_valid"),
        pytest.param([{"leases": "foo.*"}], "`leases` does not support globs", id="str_glob"),
        pytest.param([{"leases": ["foo", "bar"]}], True, id="list_valid"),
        pytest.param(
            [{"leases": ["foo", "bar.*"]}], "`leases` does not support globs", id="list_glob"
        ),
        pytest.param(
            [{"leases": {"foo": "foo", "bar": "bar"}}],
            "`leases` mapping values must be dicts",
            id="dict_nondict_values",
        ),
        pytest.param([{"leases": {"foo": {}, "bar": {}}}], True, id="dict_valid"),
        pytest.param(
            [{"leases": {"foo": {"min_ttl": "1d"}, "bar": {}}}], True, id="dict_with_overrides"
        ),
        pytest.param(
            [{"leases": {"foo": {"min_ttl": "1d"}, "bar.*": {}}}],
            "`leases` does not support globs",
            id="dict_glob",
        ),
    ),
)
def test_validate(config, exp):
    res, msg = lease.validate(config)
    if exp is True:
        assert res is True
    else:
        assert msg == exp


@pytest.mark.parametrize(
    "config",
    (
        pytest.param([{"leases": [123]}], id="int_in_list"),
        pytest.param([{"leases": [None]}], id="none_in_list"),
        pytest.param([{"leases": {123: {}}}], id="int_mapping_key"),
    ),
)
def test_validate_invalid_lease_key_types(config):
    """
    Validation must return a failure result instead of raising
    when lease cache keys are not strings.
    """
    res, _ = lease.validate(config)
    assert res is False


@pytest.mark.parametrize(
    "config,exp",
    (
        pytest.param([{"leases": "foo"}], {"leases": {"foo": {}}}, id="str"),
        pytest.param(
            [{"leases": "foo"}, {"min_ttl": 42}, {"check_server": True}, {"meta": "foo"}],
            {"leases": {"foo": {"min_ttl": 42, "check_server": True, "meta": "foo"}}},
            id="str_with_defaults",
        ),
        pytest.param([{"leases": ["foo", "bar"]}], {"leases": {"foo": {}, "bar": {}}}, id="list"),
        pytest.param(
            [{"leases": ["foo", "bar"]}, {"min_ttl": 42}, {"check_server": True}, {"meta": "foo"}],
            {
                "leases": {
                    "foo": {"min_ttl": 42, "check_server": True, "meta": "foo"},
                    "bar": {"min_ttl": 42, "check_server": True, "meta": "foo"},
                }
            },
            id="list_with_defaults",
        ),
        pytest.param(
            [{"leases": {"foo": {}, "bar": {}}}], {"leases": {"foo": {}, "bar": {}}}, id="dict"
        ),
        pytest.param(
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
            id="dict_with_defaults",
        ),
        pytest.param(
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
            id="per_lease_overrides",
        ),
        pytest.param(
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
            id="explicit_none_preserved",
        ),
        pytest.param(
            [
                {"leases": {"foo": {"meta": ["foo"]}, "bar": {"meta": {"bar": True}}}},
                {"meta": "foo"},
            ],
            {"leases": {"foo": {"meta": ["foo"]}, "bar": {"meta": {"bar": True}}}},
            id="meta_default_str_ignored",
        ),
        pytest.param(
            [
                {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
                {"meta": ["foo"]},
            ],
            {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
            id="meta_default_list_ignored",
        ),
        pytest.param(
            [
                {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
                {"meta": {"foo": True}},
            ],
            {"leases": {"foo": {"meta": ["baz"]}, "bar": {"meta": {"bar": True}}}},
            id="meta_default_dict_ignored",
        ),
        pytest.param(
            [{"leases": ["foo", "bar"]}, {"renew": False}],
            {"leases": {"foo": {"renew": False}, "bar": {"renew": False}}},
            id="renew_default",
        ),
        pytest.param(
            [{"leases": {"foo": {"renew": True}, "bar": {}}}, {"renew": False}],
            {"leases": {"foo": {"renew": True}, "bar": {"renew": False}}},
            id="renew_override",
        ),
    ),
)
def test_render_config(config, exp):
    res = lease._render_config(config)
    assert res == exp


@pytest.mark.parametrize(
    "cfg,info,exp",
    (
        pytest.param(
            {},
            {"min_ttl": 1234, "meta": None},
            {"min_ttl": 1234, "meta": None},
            id="info_min_ttl_int",
        ),
        pytest.param(
            {},
            {"min_ttl": "1h", "meta": None},
            {"min_ttl": "1h", "meta": None},
            id="info_min_ttl_str",
        ),
        pytest.param(
            {"min_ttl": "1h"},
            {"min_ttl": None, "meta": None},
            {"min_ttl": "1h", "meta": None},
            id="cfg_min_ttl_str",
        ),
        pytest.param(
            {"check_server": True},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": None, "check_server": True},
            id="check_server_true",
        ),
        pytest.param(
            {"check_server": False},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": None, "check_server": False},
            id="check_server_false",
        ),
        pytest.param(
            {"min_ttl": "2h"},
            {"min_ttl": 3600, "meta": None},
            {"min_ttl": "2h", "meta": None},
            id="cfg_min_ttl_larger",
        ),
        pytest.param(
            {"min_ttl": "1h"},
            {"min_ttl": "2h", "meta": None},
            {"min_ttl": "2h", "meta": None},
            id="info_min_ttl_larger",
        ),
        pytest.param(
            {},
            {"min_ttl": None, "meta": "foo"},
            {"min_ttl": 300, "meta": "foo"},
            id="info_meta",
        ),
        pytest.param(
            {"min_ttl": 42},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 42, "meta": None},
            id="cfg_min_ttl_int",
        ),
        pytest.param(
            {"meta": 123},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": 123},
            id="cfg_meta_int",
        ),
        pytest.param(
            {"meta": ["foo"]},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": ["foo"]},
            id="cfg_meta_list",
        ),
        pytest.param(
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": None},
            {"min_ttl": 300, "meta": {"foo": True}},
            id="cfg_meta_dict",
        ),
        pytest.param(
            {"meta": "foo"},
            {"min_ttl": None, "meta": "bar"},
            {"min_ttl": 300, "meta": "bar"},
            id="info_meta_str_wins",
        ),
        pytest.param(
            {"meta": ["foo"]},
            {"min_ttl": None, "meta": "bar"},
            {"min_ttl": 300, "meta": "bar"},
            id="info_str_over_cfg_list",
        ),
        pytest.param(
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": "bar"},
            {"min_ttl": 300, "meta": "bar"},
            id="info_str_over_cfg_dict",
        ),
        pytest.param(
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": ["bar"]},
            {"min_ttl": 300, "meta": ["bar"]},
            id="info_list_over_cfg_dict",
        ),
        pytest.param(
            {"meta": ["foo"]},
            {"min_ttl": None, "meta": {"bar": True}},
            {"min_ttl": 300, "meta": {"bar": True}},
            id="info_dict_over_cfg_list",
        ),
        pytest.param(
            {"meta": ["foo"]},
            {"min_ttl": None, "meta": ["bar"]},
            {"min_ttl": 300, "meta": ["foo", "bar"]},
            id="meta_lists_merge",
        ),
        pytest.param(
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": {"bar": True}},
            {"min_ttl": 300, "meta": {"foo": True, "bar": True}},
            id="meta_dicts_merge",
        ),
        pytest.param(
            {"meta": {"foo": ["a"]}},
            {"min_ttl": None, "meta": {"foo": ["b"]}},
            {"min_ttl": 300, "meta": {"foo": ["a", "b"]}},
            id="meta_nested_lists_merge",
        ),
        pytest.param(
            {"meta": {"foo": True}},
            {"min_ttl": None, "meta": {"foo": False}},
            {"min_ttl": 300, "meta": {"foo": False}},
            id="meta_dict_value_override",
        ),
    ),
)
def test_merge_lease_config(cfg, info, exp):
    res = lease._merge_lease_config(cfg, info)
    assert res == exp


@pytest.mark.parametrize(
    "cfg,info,exp_min_ttl",
    (
        pytest.param({"min_ttl": None}, {"min_ttl": None, "meta": None}, 300, id="default_min_ttl"),
        pytest.param({"min_ttl": None}, {"min_ttl": 60, "meta": None}, 60, id="info_min_ttl"),
    ),
)
def test_merge_lease_config_min_ttl_explicit_none(cfg, info, exp_min_ttl):
    """
    An explicit ``min_ttl: null`` in the beacon configuration must behave
    as if it was unset instead of crashing the beacon later
    (``timestring_map(None)`` returns ``None``, which cannot be compared).
    """
    res = lease._merge_lease_config(cfg, info)
    assert res["min_ttl"] == exp_min_ttl


@pytest.mark.parametrize(
    "cfg,info,exp",
    (
        pytest.param(
            {"min_ttl": 1234},
            {"min_ttl": 42, "meta": None},
            {"ckey": "test.lease", "min_ttl": 1234, "meta": None, "check_server": None},
            id="cfg_min_ttl_wins",
        ),
        pytest.param(
            {"min_ttl": 300, "meta": "foo"},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": "foo", "check_server": None},
            id="meta_str",
        ),
        pytest.param(
            {"min_ttl": 300, "meta": ["foo"]},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": ["foo"], "check_server": None},
            id="meta_list",
        ),
        pytest.param(
            {"min_ttl": 300, "meta": {"foo": True}},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": {"foo": True}, "check_server": None},
            id="meta_dict",
        ),
        pytest.param(
            {"min_ttl": 300, "check_server": False},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": None, "check_server": False},
            id="check_server_false",
        ),
        pytest.param(
            {"min_ttl": 300, "check_server": True},
            {"min_ttl": None, "meta": None},
            {"ckey": "test.lease", "min_ttl": 300, "meta": None, "check_server": True},
            id="check_server_true",
        ),
        pytest.param(
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
            id="expired",
        ),
    ),
)
def test_enrich_info(cfg, info, exp):
    exp["tag"] = "expire"
    res = lease._enrich_info("test.lease", cfg, info)
    assert res == exp
