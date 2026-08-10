from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault as vault_exe
from saltext.vault.states import vault_secret


@pytest.fixture
def configure_loader_modules():
    return {vault_secret: {"__opts__": {"test": False}}}


@pytest.fixture
def read_secret():
    _read = Mock(spec=vault_exe.read_secret)
    with patch.dict(vault_secret.__salt__, {"vault.read_secret": _read}):
        yield _read


@pytest.fixture
def write_raw():
    _write = Mock(spec=vault_exe.write_raw, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault.write_raw": _write}):
        yield _write


@pytest.fixture
def patch_raw():
    _patch = Mock(spec=vault_exe.patch_raw, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault.patch_raw": _patch}):
        yield _patch


@pytest.fixture
def delete_secret():
    _delete = Mock(spec=vault_exe.delete_secret, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault.delete_secret": _delete}):
        yield _delete


@pytest.fixture
def destroy_secret():
    _destroy = Mock(spec=vault_exe.destroy_secret, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault.destroy_secret": _destroy}):
        yield _destroy


@pytest.fixture
def wipe_secret():
    _wipe = Mock(spec=vault_exe.wipe_secret, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault.wipe_secret": _wipe}):
        yield _wipe


@pytest.mark.parametrize(
    "func,kwargs",
    (
        ("present", {"values": {"foo": "bar"}}),
        ("absent", {}),
    ),
)
def test_errors_are_reported(read_secret, func, kwargs):
    read_secret.side_effect = CommandExecutionError("booh")
    res = getattr(vault_secret, func)("secret/path", **kwargs)
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]


def test_absent_invalid_operation():
    with pytest.raises(SaltInvocationError, match="Invalid value 'defenestrate' for `operation`.*"):
        vault_secret.absent("secret/path", operation="defenestrate")


@pytest.mark.parametrize("verb", ("write", "patch"))
def test_present_write_failures_are_reported(read_secret, write_raw, patch_raw, verb):
    if verb == "write":
        read_secret.side_effect = CommandExecutionError("VaultNotFoundError: not found")
    else:
        read_secret.return_value = {"foo": "bar"}
    mock = write_raw if verb == "write" else patch_raw
    mock.return_value = False
    res = vault_secret.present("secret/path", {"foo": "baz"})
    assert res["result"] is False
    assert res["comment"] == f"Failed to {verb} secret, see logs for details"
    assert not res["changes"]


@pytest.mark.parametrize("operation", ("delete", "destroy", "wipe"))
@pytest.mark.usefixtures("delete_secret", "destroy_secret", "wipe_secret")
def test_absent_removal_failures_are_reported(read_secret, operation, request):
    read_secret.return_value = {"foo": "bar"}
    request.getfixturevalue(f"{operation}_secret").return_value = False
    res = vault_secret.absent("secret/path", operation=operation)
    assert res["result"] is False
    assert res["comment"] == f"Failed to {operation} secret, see logs for details"
    assert not res["changes"]
