# this needs to be from! see test_iso_to_timestamp_polyfill
from datetime import datetime
from unittest.mock import patch

import pytest
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault import helpers as hlp


@pytest.mark.parametrize(
    "opts_runtype,expected",
    [
        ("master", hlp.SALT_RUNTYPE_MASTER),
        ("master_peer_run", hlp.SALT_RUNTYPE_MASTER_PEER_RUN),
        ("master_impersonating", hlp.SALT_RUNTYPE_MASTER_IMPERSONATING),
        ("minion_local_1", hlp.SALT_RUNTYPE_MINION_LOCAL),
        ("minion_local_2", hlp.SALT_RUNTYPE_MINION_LOCAL),
        ("minion_local_3", hlp.SALT_RUNTYPE_MINION_LOCAL),
        ("minion_remote", hlp.SALT_RUNTYPE_MINION_REMOTE),
    ],
    indirect=["opts_runtype"],
)
def test_get_salt_run_type(opts_runtype, expected):
    """
    Ensure run types are detected as expected
    """
    assert hlp.get_salt_run_type(opts_runtype) == expected


@pytest.mark.parametrize(
    "opts",
    [
        {"id": "test-minion", "vault": {"config_location": "local"}},
        {
            "id": "test-minion",
            "vault": {"config_location": "master"},
            "__master_opts__": {"vault": {"server": {"url": "http://vault:8200"}}},
        },
    ],
)
def test_check_salt_ssh_opts_unchanged(opts):
    """
    Ensure opts are returned unchanged when they do not originate
    from an SSH wrapper (no ``__master_opts__``) or when a ``vault``
    configuration is present already
    """
    res = hlp.check_salt_ssh_opts(opts)
    assert res is opts


@pytest.mark.parametrize("caller_cachedir", [False, True])
def test_check_salt_ssh_opts_merges_master_opts(caller_cachedir):
    """
    Ensure that for SSH wrapper opts without a vault configuration,
    the master opts are merged in the same way as during pillar compilation,
    with the minion's ID set and the master's cachedir restored from
    ``_caller_cachedir`` if present (Salt 3008 OptsDict workaround)
    """
    opts = {
        "id": "test-minion",
        "cachedir": "/var/tmp/sshcache",
        "__master_opts__": {
            "vault": {"server": {"url": "http://vault:8200"}},
            "cachedir": "/var/cache/salt/master",
        },
    }
    if caller_cachedir:
        opts["_caller_cachedir"] = "/var/cache/salt/master/caller"
    res = hlp.check_salt_ssh_opts(opts)
    assert res is not opts
    assert res["vault"] == {"server": {"url": "http://vault:8200"}}
    assert res["id"] == res["minion_id"] == "test-minion"
    if caller_cachedir:
        assert res["cachedir"] == "/var/cache/salt/master/caller"
    else:
        assert res["cachedir"] == "/var/cache/salt/master"


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("no-tokens-to-replace", ["no-tokens-to-replace"]),
        ("single-dict:{minion}", ["single-dict:{minion}"]),
        ("single-list:{grains[roles]}", ["single-list:web", "single-list:database"]),
        (
            "multiple-lists:{grains[roles]}+{grains[aux]}",
            [
                "multiple-lists:web+foo",
                "multiple-lists:web+bar",
                "multiple-lists:database+foo",
                "multiple-lists:database+bar",
            ],
        ),
        (
            "single-list-with-dicts:{grains[id]}+{grains[roles]}+{grains[id]}",
            [
                "single-list-with-dicts:{grains[id]}+web+{grains[id]}",
                "single-list-with-dicts:{grains[id]}+database+{grains[id]}",
            ],
        ),
        (
            "deeply-nested-list:{grains[deep][foo][bar][baz]}",
            [
                "deeply-nested-list:hello",
                "deeply-nested-list:world",
            ],
        ),
        (
            "dict-keys:{grains[dict][roles]}",
            [
                "dict-keys:role_a",
                "dict-keys:role_b",
            ],
        ),
    ],
)
def test_expand_pattern_lists(pattern, expected):
    """
    Ensure expand_pattern_lists works as intended:
    - Expand list-valued patterns
    - Do not change non-list-valued tokens
    """
    pattern_vars = {
        "id": "test-minion",
        "roles": ["web", "database"],
        "aux": ["foo", "bar"],
        "deep": {"foo": {"bar": {"baz": ["hello", "world"]}}},
        "dict": {"roles": {"role_a": {"foo": "bar"}, "role_b": {"bar": "baz"}}},
    }

    mappings = {"minion": "test-minion", "grains": pattern_vars}
    output = hlp.expand_pattern_lists(pattern, **mappings)
    assert output == expected


@pytest.mark.parametrize(
    "inpt,expected",
    [
        (60.0, 60.0),
        (60, 60.0),
        ("60", 60.0),
        ("60s", 60.0),
        ("2m", 120.0),
        ("1h", 3600.0),
        ("1d", 86400.0),
        ("1.5s", 1.5),
        ("1.5m", 90.0),
        ("1.5h", 5400.0),
        ("7.5d", 648000.0),
    ],
)
def test_timestring_map(inpt, expected):
    assert hlp.timestring_map(inpt) == expected


@pytest.mark.parametrize(
    "inpt,expected",
    [
        (None, None),
        (60.0, 60),
        (60, 60),
        ("60", 60),
        ("60s", 60),
        ("2m", 120),
        ("1h", 3600),
        ("1d", 86400),
        ("1.5s", 1),
        ("1.5m", 90),
        ("1.5h", 5400),
        ("7.5d", 648000),
    ],
)
def test_timestring_map_with_int(inpt, expected):
    assert hlp.timestring_map(inpt, cast=int) == expected


def test_timestring_map_invalid_type():
    with pytest.raises(SaltInvocationError, match="Expected integer or time string"):
        hlp.timestring_map(b"1m")  # type: ignore


@pytest.mark.parametrize("inpt", ["1w", "foo", "m", "-1m", "1m "])
def test_timestring_map_invalid_time_string(inpt):
    with pytest.raises(SaltInvocationError, match="Invalid time string format"):
        hlp.timestring_map(inpt)


@pytest.mark.parametrize(
    "inpt,expected",
    [
        (None, None),
        ("", []),
        ("foo", ["foo"]),
        ("foo,bar,baz", ["foo", "bar", "baz"]),
        (["foo", "bar"], ["foo", "bar"]),
        (("foo", "bar"), ["foo", "bar"]),
    ],
)
def test_deserialize_csl(inpt, expected):
    assert hlp.deserialize_csl(inpt) == expected


def test_deserialize_csl_invalid_type():
    with pytest.raises(SaltInvocationError, match="Expected a comma-separated string list"):
        hlp.deserialize_csl(42)  # type: ignore


@pytest.mark.parametrize(
    "inpt,expected",
    [
        # valid base64 string is decoded
        ("aGVsbG8=", (b"hello", True)),
        # valid base64 bytes are decoded
        (b"aGVsbG8=", (b"hello", True)),
        # embedded newlines are ignored during validation
        (b"aGVs\nbG8=", (b"hello", True)),
        # decodable, but not canonical base64 (re-encoding differs)
        ("ab==", (b"ab==", False)),
        # incorrect padding raises during decoding
        ("abc", (b"abc", False)),
        # non-ASCII strings cannot be base64
        ("hëllo", ("hëllo".encode(), False)),
    ],
)
def test_try_base64(inpt, expected):
    assert hlp.try_base64(inpt) == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"foo": "set", "bar": None},
        {"foo": None, "bar": "set"},
        {"_min": 1, "_max": 2, "foo": "set", "bar": "set", "baz": None},
        {"_predicate": lambda x: x == "set", "foo": "set", "bar": "unset"},
    ],
)
def test_x_of_valid(kwargs):
    assert hlp.x_of(**kwargs) is None


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        (
            {"foo": None},
            "Either `foo` is required",
        ),
        (
            {"foo": None, "bar": None},
            "Either `foo` or `bar` is required",
        ),
        (
            {"foo": "set", "bar": "set"},
            "Either `foo` or `bar` is required (exclusive)",
        ),
        (
            {"foo": "set", "bar": "set", "baz": None},
            "Only specify either `foo`, `bar` or `baz` (exclusive)",
        ),
        (
            {"_min": 2, "_max": 3, "foo": "set", "bar": None, "baz": None},
            "At least two of `foo`, `bar` or `baz` must be passed",
        ),
        (
            {"_min": 1, "_max": 2, "foo": "set", "bar": "set", "baz": "set"},
            "At most two of `foo`, `bar` or `baz` can be specified",
        ),
    ],
)
def test_x_of_invalid(kwargs, expected):
    with pytest.raises(SaltInvocationError) as excinfo:
        hlp.x_of(**kwargs)
    assert str(excinfo.value) == expected


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        ({"foo": "set", "bar": None}, None),
        ({"foo": "set", "bar": "set"}, SaltInvocationError),
    ],
)
def test_one_of(kwargs, expected):
    """
    Ensure one_of is a shorthand for the default x_of parameters
    """
    if expected is None:
        assert hlp.one_of(**kwargs) is None
    else:
        with pytest.raises(expected):
            hlp.one_of(**kwargs)


@pytest.mark.parametrize(
    "creation_time,expected",
    [
        ("2022-08-22T17:16:21-09:30", 1661222781),
        ("2022-08-22T17:16:21-01:00", 1661192181),
        ("2022-08-22T17:16:21+00:00", 1661188581),
        ("2022-08-22T17:16:21Z", 1661188581),
        ("2022-08-22T17:16:21+02:00", 1661181381),
        ("2022-08-22T17:16:21+12:30", 1661143581),
    ],
)
def test_iso_to_timestamp_polyfill(creation_time, expected):
    with patch("saltext.vault.utils.vault.helpers.datetime.datetime") as _d:
        _d.fromisoformat.side_effect = AttributeError
        # needs from datetime import datetime, otherwise results
        # in infinite recursion

        # pylint: disable=unnecessary-lambda
        _d.side_effect = lambda *args: datetime(*args)
        res = hlp.iso_to_timestamp(creation_time)
        assert res == expected
