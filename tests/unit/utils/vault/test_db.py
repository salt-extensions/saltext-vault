import pytest

from saltext.vault.utils.vault import db


@pytest.mark.parametrize(
    "name,expected",
    (
        ("mysql", {"name": "mysql", "required": ["connection_url"]}),
        ("custom", {"name": "", "required": []}),
    ),
)
def test_get_plugin_meta(name, expected):
    ret = db.get_plugin_meta(name).copy()
    assert ret == expected


@pytest.mark.parametrize(
    "name,expected",
    (
        ("mysql", "mysql-database-plugin"),
        ("redis_elasticache", "redis-elasticache-database-plugin"),
        ("custom", "custom-database-plugin"),
    ),
)
def test_get_plugin_name(name, expected):
    ret = db.get_plugin_name(name)
    assert ret == expected


@pytest.mark.parametrize(
    "name,mount,cache,static,expected",
    (
        (None, None, None, None, "db.*.*.*.*"),
        ("test", None, None, None, "db.*.*.test.*"),
        ("test", None, True, None, "db.*.*.test.default"),
        ("test", None, "alt", None, "db.*.*.test.alt"),
        ("test", None, "alt", False, "db.*.dynamic.test.alt"),
        ("test", None, "alt", True, "db.*.static.test.default"),
        ("test", None, None, True, "db.*.static.test.default"),
        ("test", None, True, True, "db.*.static.test.default"),
        ("test", "foo", True, True, "db.foo.static.test.default"),
        ("test", "foo", None, True, "db.foo.static.test.default"),
        ("test", "foo", None, False, "db.foo.dynamic.test.*"),
        ("test", "foo", "alt2", False, "db.foo.dynamic.test.alt2"),
    ),
)
def test_create_cache_pattern(name, mount, cache, static, expected):
    ret = db.create_cache_pattern(name=name, mount=mount, cache=cache, static=static)
    assert ret == expected
