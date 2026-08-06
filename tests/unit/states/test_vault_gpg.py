from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_gpg as vault_gpg_exe
from saltext.vault.states import vault_gpg


@pytest.fixture
def configure_loader_modules():
    return {vault_gpg: {}}


@pytest.fixture
def read_key():
    _read = Mock(spec=vault_gpg_exe.read_key)
    with patch.dict(vault_gpg.__salt__, {"vault_gpg.read_key": _read}):
        yield _read


@pytest.fixture
def create_key():
    _create = Mock(spec=vault_gpg_exe.create_key, return_value=True)
    with patch.dict(vault_gpg.__salt__, {"vault_gpg.create_key": _create}):
        yield _create


@pytest.fixture
def delete_key():
    _delete = Mock(spec=vault_gpg_exe.delete_key, return_value=True)
    with patch.dict(vault_gpg.__salt__, {"vault_gpg.delete_key": _delete}):
        yield _delete


@pytest.mark.parametrize("func", ("key_present", "key_absent", "keychain_present"))
@pytest.mark.parametrize("err", (CommandExecutionError, SaltInvocationError))
def test_errors_are_reported(read_key, create_key, delete_key, func, err):
    read_key.side_effect = err("booh")
    res = getattr(vault_gpg, func)("foo")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]
    create_key.assert_not_called()
    delete_key.assert_not_called()


def test_key_present_regenerate_requires_gpg_modules(read_key, create_key, delete_key):
    """
    When the Salt release does not provide gpg.read_key (<3008),
    ``regenerate`` cannot inspect changes and should not fail the state.
    """
    read_key.return_value = {
        "fingerprint": "deadbeefcafebabe",
        "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
        "exportable": False,
    }
    res = vault_gpg.key_present("foo", regenerate=True)
    assert res["result"] is True
    assert "requires Salt 3008" in res["comment"]
    assert not res["changes"]
    create_key.assert_not_called()
    delete_key.assert_not_called()
