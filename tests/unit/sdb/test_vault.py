from unittest.mock import ANY
from unittest.mock import patch

import pytest
import salt.exceptions

import saltext.vault.utils.vault as vaultutil
from saltext.vault.sdb import vault


@pytest.fixture
def configure_loader_modules():
    return {vault: {}}


@pytest.fixture
def data():
    return {"bar": "super awesome"}


@pytest.fixture
def read_kv(data):
    with patch("saltext.vault.utils.vault.read_kv", autospec=True) as read:
        read.return_value = data
        yield read


@pytest.fixture
def read_kv_not_found(read_kv):
    read_kv.side_effect = vaultutil.VaultNotFoundError


@pytest.fixture
def read_kv_not_found_once(read_kv, data):
    read_kv.side_effect = (vaultutil.VaultNotFoundError, data)
    yield read_kv


@pytest.fixture
def read_kv_err(read_kv):
    read_kv.side_effect = vaultutil.VaultPermissionDeniedError("damn")
    yield read_kv


@pytest.fixture
def write_kv():
    with patch("saltext.vault.utils.vault.write_kv", autospec=True) as write:
        yield write


@pytest.fixture
def write_kv_err(write_kv):
    write_kv.side_effect = vaultutil.VaultPermissionDeniedError("damn")
    yield write_kv


@pytest.fixture
def patch_kv():
    with patch("saltext.vault.utils.vault.patch_kv", autospec=True) as patch_kv:
        yield patch_kv


@pytest.mark.parametrize(
    "key,exp_path",
    [
        ("path/to/foo/bar", "path/to/foo"),
        ("path/to/foo?bar", "path/to/foo"),
    ],
)
def test_set(write_kv, key, exp_path, data):
    """
    Test salt.sdb.vault.set_ with current and old (question mark) syntax.
    KV v1/2 distinction is unnecessary, since that is handled in the utils module.
    """
    vault.set_(key, "super awesome")
    write_kv.assert_called_once_with(exp_path, data, opts=ANY, context=ANY)


@pytest.mark.usefixtures("write_kv_err")
def test_set_err():
    """
    Test that salt.sdb.vault.set_ raises CommandExecutionError from other exceptions
    """
    with pytest.raises(salt.exceptions.CommandExecutionError, match="damn"):
        vault.set_("path/to/foo/bar", "foo")


def test_set_patch(read_kv, patch_kv):
    read_kv.return_value = {"bar": "baz"}
    vault.set_("path/to/foo", "bar", {"patch": True})
    patch_kv.assert_called_once_with("path/to", {"foo": "bar"}, opts=ANY, context=ANY)


@pytest.mark.parametrize(
    "exception", (vaultutil.VaultPermissionDeniedError, vaultutil.VaultNotFoundError)
)
def test_set_patch_exception_fallback(patch_kv, write_kv, read_kv, exception):
    read_kv.return_value = {"bar": "baz"}
    patch_kv.side_effect = exception("missing authorization or secret for patch")
    vault.set_("path/to/foo", "bar", {"patch": True})
    patch_kv.assert_called_once_with("path/to", {"foo": "bar"}, opts=ANY, context=ANY)
    write_kv.assert_called_once_with("path/to", {"foo": "bar", "bar": "baz"}, opts=ANY, context=ANY)


@pytest.mark.parametrize(
    "key,exp_path",
    [
        ("path/to/foo/bar", "path/to/foo"),
        ("path/to/foo?bar", "path/to/foo"),
    ],
)
def test_get(read_kv, key, exp_path):
    """
    Test salt.sdb.vault.get_ with current and old (question mark) syntax.
    KV v1/2 distinction is unnecessary, since that is handled in the utils module.
    """
    res = vault.get(key)
    assert res == "super awesome"
    read_kv.assert_called_once_with(f"{exp_path}", opts=ANY, context=ANY)


@pytest.mark.usefixtures("read_kv")
def test_get_missing_key():
    """
    Test that salt.sdb.vault.get returns None if vault does not have the key
    but does have the entry.
    """
    res = vault.get("path/to/foo/foo")
    assert res is None


@pytest.mark.usefixtures("read_kv_not_found")
def test_get_missing():
    """
    Test that salt.sdb.vault.get returns None if vault does have the entry.
    """
    res = vault.get("path/to/foo/foo")
    assert res is None


def test_get_whole_dataset(read_kv_not_found_once, data):
    """
    Test that salt.sdb.vault.get retries the whole path without key if the
    first request reported the dataset was not found.
    """
    res = vault.get("path/to/foo")
    assert res == data
    read_kv_not_found_once.assert_called_with("path/to/foo", opts=ANY, context=ANY)
    assert read_kv_not_found_once.call_count == 2


@pytest.mark.usefixtures("read_kv_err")
def test_get_err():
    """
    Test that salt.sdb.vault.get raises CommandExecutionError from other exceptions
    """
    with pytest.raises(salt.exceptions.CommandExecutionError, match="damn"):
        vault.get("path/to/foo/bar")
