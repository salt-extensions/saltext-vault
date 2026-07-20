import contextlib
import logging
from unittest.mock import patch

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_secrets"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def vault_secrets_defaults(secret_mounts, mid):
    def _add(path, **vals):
        for mount in secret_mounts:
            secrets[f"{mount}/{path}"] = vals

    secrets = {}
    _add("hard/coded", foo="bar")
    _add("roles/foo", roles_foo="foo")
    _add("roles/bar", roles_bar="bar")
    _add("roles/foo_conflict", foo={"foo": "foo"})
    _add("roles/bar_conflict", foo={"bar": "bar"})
    _add("roles/foo_merge_lists", foo=["foo"])
    _add("roles/bar_merge_lists", foo=["bar"])
    _add(f"minions/{mid}", minion_foo="foo")
    return secrets


@pytest.fixture
def pillar():
    return {
        "hard": "hard",
        "roles": ["foo", "bar"],
        "roles_map": {"foo": {}, "bar": {}},
        "roles_missing": ["missing_1", "missing_2"],
        "roles_partial": ["foo", "missing"],
    }


@pytest.fixture
def vault(loaders):
    return loaders.pillars.vault


@pytest.fixture(scope="module")
def mid(loaders):
    return loaders.opts["id"]


def test_hardcoded(vault, mid):
    res = vault.ext_pillar(mid, {}, path="secret/hard/coded")
    assert res == {"foo": "bar"}


def test_hardcoded_absent(vault, mid):
    res = vault.ext_pillar(mid, {}, path="secret/missing/path")
    assert res == {}


def test_minion_template(vault, mid, pillar):
    res = vault.ext_pillar(mid, pillar, path="secret/minions/{minion}")
    assert res == {"minion_foo": "foo"}


def test_pillar_template_single(vault, mid, pillar):
    res = vault.ext_pillar(mid, pillar, path="secret/{pillar[hard]}/coded")
    assert res == {"foo": "bar"}


def test_pillar_template_no_pillar(vault, mid, pillar, caplog):
    with caplog.at_level(logging.WARN):
        res = vault.ext_pillar(mid, pillar, path="secret/{pillar[missing]}")
    assert res == {}
    assert "Could not resolve pillar path pattern" in caplog.text


def test_pillar_template_single_absent(vault, mid, pillar, caplog):
    with caplog.at_level(logging.INFO):
        res = vault.ext_pillar(mid, pillar, path="secret/{pillar[hard]}/missing")
    assert res == {}
    assert "Vault secret not found for" in caplog.text


def test_unknown_template_var(vault, mid, pillar, caplog):
    with caplog.at_level(logging.INFO):
        res = vault.ext_pillar(mid, pillar, path="secret/{grains[id]}/missing")
    assert res == {}
    assert "Could not resolve pillar path pattern" in caplog.text


def test_pillar_template_multi_list(vault, mid, pillar):
    res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles]}")
    assert res == {"roles_foo": "foo", "roles_bar": "bar"}


def test_pillar_template_multi_dict(vault, mid, pillar):
    res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles_map]}")
    assert res == {"roles_foo": "foo", "roles_bar": "bar"}


def test_pillar_template_multi_absent(vault, mid, pillar):
    res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles_missing]}")
    assert res == {}


def test_pillar_template_multi_partial_absent(vault, mid, pillar, caplog):
    with caplog.at_level(logging.INFO):
        res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles_partial]}")
    assert res == {"roles_foo": "foo"}
    assert "Vault secret not found for" in caplog.text


@contextlib.contextmanager
def _opts(loaders, **kwargs):
    # Note: In Salt >= 3008, it's enough to patch.dict(vault.loader.pack["__opts__"], ...), which is faster
    with patch.dict(loaders.opts, kwargs):
        loaders.pillars.clean_modules()
        loaders.pillars.clear()
        loaders._pillars = None
        yield loaders.pillars.vault


@pytest.mark.parametrize("default", ("smart", "overwrite"))
def test_merge_strategy_default(mid, pillar, default, loaders):
    with _opts(loaders, pillar_source_merging_strategy=default) as vault:
        res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles]}_conflict")
    if default == "overwrite":
        assert res == {"foo": {"bar": "bar"}}
    else:
        assert res == {"foo": {"foo": "foo", "bar": "bar"}}


@pytest.mark.parametrize("default", ("smart", "overwrite"))
@pytest.mark.parametrize("override", ("smart", "overwrite"))
def test_merge_strategy_override(mid, pillar, default, override, loaders):
    with _opts(loaders, pillar_source_merging_strategy=default) as vault:
        res = vault.ext_pillar(
            mid,
            pillar,
            path="secret/roles/{pillar[roles]}_conflict",
            merge_strategy=override,
        )
    if override == "overwrite":
        assert res == {"foo": {"bar": "bar"}}
    else:
        assert res == {"foo": {"foo": "foo", "bar": "bar"}}


@pytest.mark.parametrize("default", (False, True))
def test_merge_lists_default(mid, pillar, default, loaders):
    with _opts(loaders, pillar_merge_lists=default) as vault:
        res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles]}_merge_lists")
    if default:
        assert res == {"foo": ["foo", "bar"]}
    else:
        assert res == {"foo": ["bar"]}


@pytest.mark.parametrize("default", (False, True))
@pytest.mark.parametrize("override", (False, True))
def test_merge_lists_override(mid, pillar, default, override, loaders):
    with _opts(loaders, pillar_merge_lists=default) as vault:
        res = vault.ext_pillar(
            mid,
            pillar,
            path="secret/roles/{pillar[roles]}_merge_lists",
            merge_lists=override,
        )
    if override:
        assert res == {"foo": ["foo", "bar"]}
    else:
        assert res == {"foo": ["bar"]}


def test_nesting_key_single(vault, mid):
    res = vault.ext_pillar(mid, {}, path="secret/hard/coded", nesting_key="nesting")
    assert res == {"nesting": {"foo": "bar"}}


def test_nesting_key_multi(vault, pillar, mid):
    res = vault.ext_pillar(mid, pillar, path="secret/roles/{pillar[roles]}", nesting_key="nesting")
    assert res == {"nesting": {"roles_foo": "foo", "roles_bar": "bar"}}
