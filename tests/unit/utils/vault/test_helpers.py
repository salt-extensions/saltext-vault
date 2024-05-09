# this needs to be from! see test_iso_to_timestamp_polyfill
from datetime import datetime
from unittest.mock import patch

import pytest

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
    assert hlp._get_salt_run_type(opts_runtype) == expected  # pylint: disable=protected-access


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
