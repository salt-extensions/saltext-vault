from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_secret as vault_secret_exe
from saltext.vault.states import vault_secret


@pytest.fixture
def configure_loader_modules():
    return {vault_secret: {"__opts__": {"test": False}}}


@pytest.fixture
def read_secret():
    _read = Mock(spec=vault_secret_exe.read)
    with patch.dict(vault_secret.__salt__, {"vault_secret.read": _read}):
        yield _read


@pytest.fixture
def write_raw():
    _write = Mock(spec=vault_secret_exe.write_raw, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault_secret.write_raw": _write}):
        yield _write


@pytest.fixture
def patch_raw():
    _patch = Mock(spec=vault_secret_exe.patch_raw, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault_secret.patch_raw": _patch}):
        yield _patch


@pytest.fixture
def delete_secret():
    _delete = Mock(spec=vault_secret_exe.delete, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault_secret.delete": _delete}):
        yield _delete


@pytest.fixture
def destroy_secret():
    _destroy = Mock(spec=vault_secret_exe.destroy, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault_secret.destroy": _destroy}):
        yield _destroy


@pytest.fixture
def wipe_secret():
    _wipe = Mock(spec=vault_secret_exe.wipe, return_value=True)
    with patch.dict(vault_secret.__salt__, {"vault_secret.wipe": _wipe}):
        yield _wipe


@pytest.mark.parametrize(
    "func,kwargs",
    (
        pytest.param("present", {"values": {"foo": "bar"}}, id="present"),
        pytest.param("absent", {}, id="absent"),
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
    mock.side_effect = CommandExecutionError("Failed to foo secret! VaultServerError: booh")
    res = vault_secret.present("secret/path", {"foo": "baz"})
    assert res["result"] is False
    assert res["comment"] == "Failed to foo secret! VaultServerError: booh"
    assert not res["changes"]


@pytest.mark.parametrize("operation", ("delete", "destroy", "wipe"))
@pytest.mark.usefixtures("delete_secret", "destroy_secret", "wipe_secret")
def test_absent_removal_failures_are_reported(read_secret, operation, request):
    read_secret.return_value = {"foo": "bar"}
    request.getfixturevalue(f"{operation}_secret").side_effect = CommandExecutionError(
        "Failed to foo secret! VaultServerError: booh"
    )
    res = vault_secret.absent("secret/path", operation=operation)
    assert res["result"] is False
    assert res["comment"] == "Failed to foo secret! VaultServerError: booh"
    assert not res["changes"]
