import logging
from unittest.mock import ANY
from unittest.mock import patch

import pytest
import salt.exceptions

import saltext.vault.utils.vault as vaultutil
from saltext.vault.modules import vault_secret

# pylint: disable=unused-import
from tests.unit.fixtures.vault import data
from tests.unit.fixtures.vault import patch_kv
from tests.unit.fixtures.vault import read_kv
from tests.unit.fixtures.vault import write_kv

# pylint: enable=unused-import


@pytest.fixture
def configure_loader_modules():
    return {
        vault_secret: {
            "__grains__": {"id": "test-minion"},
        },
    }


@pytest.fixture
def data_list():
    return ["foo"]


@pytest.fixture
def list_kv(data_list):
    with patch("saltext.vault.utils.vault.list_kv", autospec=True) as _list:
        _list.return_value = data_list
        yield _list


@pytest.fixture
def read_kv_not_found(read_kv):
    read_kv.side_effect = vaultutil.VaultNotFoundError
    yield read_kv


@pytest.fixture
def list_kv_not_found(list_kv):
    list_kv.side_effect = vaultutil.VaultNotFoundError
    yield list_kv


@pytest.fixture
def delete_kv():
    with patch("saltext.vault.utils.vault.delete_kv", autospec=True) as delete_kv:
        yield delete_kv


@pytest.fixture
def destroy_kv():
    with patch("saltext.vault.utils.vault.destroy_kv", autospec=True) as destroy_kv:
        yield destroy_kv


@pytest.mark.usefixtures("read_kv")
@pytest.mark.parametrize(
    "key,expected",
    [
        pytest.param(None, {"foo": "bar"}, id="full_data"),
        pytest.param("foo", "bar", id="single_key"),
    ],
)
def test_read_secret(key, expected):
    """
    Ensure read_secret works as expected without and with specified key.
    KV v1/2 is handled in the utils module.
    """
    res = vault_secret.read("some/path", key=key)
    assert res == expected


@pytest.mark.usefixtures("read_kv")
def test_read_with_key_and_metadata(caplog):
    with caplog.at_level(logging.WARN):
        res = vault_secret.read("some/path", key="foo", metadata=True)
    assert "Cannot read metadata when" in caplog.text
    assert res == "bar"


@pytest.mark.usefixtures("read_kv_not_found", "list_kv_not_found")
@pytest.mark.parametrize("func", ["read", "list_"])
def test_read_list_secret_with_default(func):
    """
    Ensure read_secret and list_secrets with defaults set return those
    if the path was not found.
    """
    tgt = getattr(vault_secret, func)
    res = tgt("some/path", default=["f"])
    assert res == ["f"]


@pytest.mark.usefixtures("read_kv_not_found", "list_kv_not_found")
@pytest.mark.parametrize("func", ["read", "list_"])
def test_read_list_secret_without_default(func):
    """
    Ensure read_secret and list_secrets without defaults set raise
    a CommandExecutionError when the path is not found.
    """
    tgt = getattr(vault_secret, func)
    with pytest.raises(salt.exceptions.CommandExecutionError, match=".*VaultNotFoundError.*"):
        tgt("some/path")


@pytest.mark.usefixtures("list_kv")
def test_list_secrets():
    res = vault_secret.list_("some/path")
    assert res == ["foo"]


def test_write_secret(data, write_kv):
    """
    Ensure write_secret parses kwargs as expected
    """
    path = "secret/some/path"
    res = vault_secret.write(path, **data)
    assert res
    write_kv.assert_called_once_with(path, data, opts=ANY, context=ANY)


def test_write_raw(data, write_kv):
    """
    Ensure write_secret works as expected
    """
    path = "secret/some/path"
    res = vault_secret.write_raw(path, data)
    assert res
    write_kv.assert_called_once_with(path, data, opts=ANY, context=ANY)


@pytest.mark.parametrize(
    "func,kwargs,target",
    (
        pytest.param("read", {}, "read_kv", id="read"),
        pytest.param("read_meta", {}, "read_kv_meta", id="read_meta"),
        pytest.param("write", {"foo": "bar"}, "write_kv", id="write"),
        pytest.param("write_raw", {"raw": {"foo": "bar"}}, "write_kv", id="write_raw"),
        pytest.param("patch", {"foo": "bar"}, "patch_kv", id="patch"),
        pytest.param("patch_raw", {"raw": {"foo": "bar"}}, "patch_kv", id="patch_raw"),
        pytest.param("list_", {}, "list_kv", id="list"),
        pytest.param("delete", {}, "delete_kv", id="delete"),
        pytest.param("destroy", {}, "destroy_kv", id="destroy"),
        pytest.param("wipe", {}, "wipe_kv", id="wipe"),
    ),
)
def test_func_converts_errors(func, kwargs, target):
    """
    Ensure write_secret handles exceptions as expected
    """
    if func == "read_meta":
        msg = "Failed to read secret metadata! VaultInvocationError: booh"
    else:
        msg = f"Failed to {func.split('_', maxsplit=1)[0]} secret{'s' if func == 'list_' else ''}! VaultInvocationError: booh"
    with patch(f"saltext.vault.utils.vault.{target}", autospec=True) as tgt:
        tgt.side_effect = vaultutil.VaultInvocationError("booh")
        with pytest.raises(salt.exceptions.CommandExecutionError, match=msg):
            getattr(vault_secret, func)("secret/some/path", **kwargs)


def test_patch_secret(data, patch_kv):
    """
    Ensure patch_secret parses kwargs as expected
    """
    path = "secret/some/path"
    res = vault_secret.patch(path, **data)
    assert res
    patch_kv.assert_called_once_with(path, data, opts=ANY, context=ANY)


@pytest.mark.parametrize(
    "args",
    [
        pytest.param([], id="no_versions"),
        pytest.param([1, 2], id="versions"),
    ],
)
def test_delete_secret(delete_kv, args):
    """
    Ensure delete_secret works as expected
    """
    path = "secret/some/path"
    res = vault_secret.delete(path, *args)
    assert res
    delete_kv.assert_called_once_with(
        path, opts=ANY, context=ANY, versions=args or None, all_versions=False
    )


@pytest.mark.parametrize(
    "args",
    [
        pytest.param([], id="no_versions"),
        pytest.param([1], id="one_version"),
        pytest.param([1, 2], id="two_versions"),
    ],
)
def test_destroy_secret(destroy_kv, args):
    """
    Ensure destroy_secret works as expected
    """
    path = "secret/some/path"
    res = vault_secret.destroy(path, *args)
    assert res
    destroy_kv.assert_called_once_with(
        path, args or None, opts=ANY, context=ANY, all_versions=False
    )
