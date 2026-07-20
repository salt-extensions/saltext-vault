import logging
from unittest.mock import ANY
from unittest.mock import patch

import pytest
from salt.exceptions import InvalidConfigError

import saltext.vault.utils.vault as vaultutil
from saltext.vault.pillar import vault


@pytest.fixture
def configure_loader_modules():
    return {vault: {}}


@pytest.fixture
def data():
    return {"foo": "bar"}


@pytest.fixture
def read_kv(data):
    with patch("saltext.vault.utils.vault.read_kv", autospec=True) as read:
        read.return_value = data
        yield read


def test_any_path_required():
    with pytest.raises(InvalidConfigError, match="Need a Vault path.*"):
        vault.ext_pillar("test-minion", {})


def test_ext_pillar_disabled_during_pillar_rendering(read_kv):
    """
    Ensure ext_pillar returns an empty dict when called during pillar
    template rendering to prevent a cyclic dependency.
    """
    extra = {"_vault_runner_is_compiling_pillar_templates": True}
    res = vault.ext_pillar("test-minion", {}, path="secret/path", extra_minion_data=extra)
    assert res == {}
    read_kv.assert_not_called()


def test_ext_pillar_handles_other_exceptions(read_kv, caplog):
    expected = {"foo": "foo"}
    read_kv.side_effect = (expected.copy(), vaultutil.VaultPermissionDeniedError)
    with caplog.at_level(logging.WARN):
        ext_pillar = vault.ext_pillar(
            "test-minion",
            {"roles": ["db", "web"]},
            path="salt/roles/{pillar[roles]}",
        )
    assert ext_pillar == expected
    assert "Error fetching Vault secret" in caplog.text


@pytest.mark.parametrize("kwarg", (False, True))
def test_path_required_in_deprecated_config(caplog, kwarg):
    args, kwargs = [], {}
    if kwarg:
        kwargs["conf"] = "foo=bar bar=baz"
    else:
        args.append("foo=bar bar=baz")
    with caplog.at_level(logging.ERROR):
        res = vault.ext_pillar("test-minion", {}, *args, **kwargs)
    assert res == {}
    assert "is not a valid Vault ext_pillar config" in caplog.text


@pytest.mark.parametrize("kwarg", (True, False))
@pytest.mark.parametrize(
    "conf",
    (
        "path=secret/path",
        "I have no idea why this was accepted before: path=secret/path",
    ),
)
def test_deprecated_config(read_kv, data, kwarg, conf):
    """
    Ensure the previous config with the ``path=`` prefix is still recognized,
    but warned about.
    """
    with pytest.deprecated_call(match="`path=`"):
        if kwarg:
            ext_pillar = vault.ext_pillar("testminion", {}, conf=conf)
        else:
            ext_pillar = vault.ext_pillar("testminion", {}, conf)
        read_kv.assert_called_once_with("secret/path", opts=ANY, context=ANY)
        assert ext_pillar == data
