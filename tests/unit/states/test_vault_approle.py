from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_approle as vault_approle_exe
from saltext.vault.states import vault_approle


@pytest.fixture
def configure_loader_modules():
    return {vault_approle: {"__opts__": {"test": False}}}


@pytest.fixture
def read():
    _read = Mock(spec=vault_approle_exe.read)
    with patch.dict(vault_approle.__salt__, {"vault_approle.read": _read}):
        yield _read


@pytest.fixture
def write():
    _write = Mock(return_value=True, spec=vault_approle_exe.write)
    with patch.dict(vault_approle.__salt__, {"vault_approle.write": _write}):
        yield _write


@pytest.fixture
def delete():
    _delete = Mock(return_value=True, spec=vault_approle_exe.delete)
    with patch.dict(vault_approle.__salt__, {"vault_approle.delete": _delete}):
        yield _delete


def test_present_missing_approle_is_created(read, write):
    read.side_effect = CommandExecutionError("VaultNotFoundError: AppRole does not exist")
    res = vault_approle.present("foo")
    assert res["result"] is True
    assert res["changes"] == {"created": "foo"}
    write.assert_called_once()


def test_absent_missing_approle_no_changes(read, delete):
    read.side_effect = CommandExecutionError("VaultNotFoundError: AppRole does not exist")
    res = vault_approle.absent("foo")
    assert res["result"] is True
    assert not res["changes"]
    delete.assert_not_called()


@pytest.mark.parametrize("func", ("present", "absent"))
@pytest.mark.parametrize("err", (CommandExecutionError, SaltInvocationError))
def test_errors_are_reported(read, write, delete, func, err):
    read.side_effect = err("booh")
    res = getattr(vault_approle, func)("foo")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]
    write.assert_not_called()
    delete.assert_not_called()
