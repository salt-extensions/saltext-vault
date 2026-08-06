from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_ssh as vault_ssh_exe
from saltext.vault.states import vault_ssh


@pytest.fixture
def configure_loader_modules():
    return {vault_ssh: {"__opts__": {"test": False}}}


@pytest.fixture
def read_ca():
    _read_ca = Mock(spec=vault_ssh_exe.read_ca)
    with patch.dict(vault_ssh.__salt__, {"vault_ssh.read_ca": _read_ca}):
        yield _read_ca


@pytest.fixture
def read_role():
    _read_role = Mock(spec=vault_ssh_exe.read_role)
    with patch.dict(vault_ssh.__salt__, {"vault_ssh.read_role": _read_role}):
        yield _read_role


@pytest.fixture
def delete_role():
    _delete_role = Mock(spec=vault_ssh_exe.read_role)
    with patch.dict(vault_ssh.__salt__, {"vault_ssh.delete_role": _delete_role}):
        yield _delete_role


@pytest.fixture
def write_role_otp():
    _write = Mock(spec=vault_ssh_exe.write_role_otp, return_value=True)
    with patch.dict(vault_ssh.__salt__, {"vault_ssh.write_role_otp": _write}):
        yield _write


@pytest.mark.parametrize("err", (CommandExecutionError, SaltInvocationError))
@pytest.mark.parametrize(
    "func,kwargs,err_mock",
    (
        ("ca_present", {}, "read_ca"),
        ("ca_absent", {}, "read_ca"),
        ("role_present_otp", {"default_user": "user"}, "read_role"),
        ("role_present_ca", {"allow_user_certificates": True}, "read_role"),
        ("role_absent", {}, "delete_role"),
    ),
)
def test_errors_are_reported(func, kwargs, err_mock, err, request):
    if func == "role_absent":
        read_role = request.getfixturevalue("read_role")
        read_role.return_value = {}
    mock = request.getfixturevalue(err_mock)
    mock.side_effect = err("booh")
    res = getattr(vault_ssh, func)("foo", **kwargs)
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]


def test_role_present_verification_reported_absent(read_role, write_role_otp):
    read_role.side_effect = CommandExecutionError("VaultNotFoundError: role not found")
    res = vault_ssh.role_present_otp("foo", "user")
    assert res["result"] is False
    assert "There were no errors during role management" in res["comment"]
    assert "reported as absent" in res["comment"]
    assert not res["changes"]
    write_role_otp.assert_called_once()


def test_role_present_verification_params_mismatch(read_role, write_role_otp):
    read_role.side_effect = (
        CommandExecutionError("VaultNotFoundError: role not found"),
        {"key_type": "otp", "default_user": "other", "port": 22},
    )
    res = vault_ssh.role_present_otp("foo", "user")
    assert res["result"] is False
    assert "There were no errors during role management" in res["comment"]
    assert "the reported parameters do not match" in res["comment"]
    assert "default_user" in res["comment"]
    write_role_otp.assert_called_once()


def test_role_present_verification_errors_are_reported(read_role, write_role_otp):
    read_role.side_effect = (
        CommandExecutionError("VaultNotFoundError: role not found"),
        CommandExecutionError("booh"),
    )
    res = vault_ssh.role_present_otp("foo", "user")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]
    write_role_otp.assert_called_once()


def test_role_absent_read_errors_are_reported(read_role, delete_role):
    read_role.side_effect = CommandExecutionError("booh")
    res = vault_ssh.role_absent("foo")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]
    delete_role.assert_not_called()


def test_role_absent_verification_errors_are_reported(read_role, delete_role):
    read_role.side_effect = ({"key_type": "otp"}, CommandExecutionError("booh"))
    res = vault_ssh.role_absent("foo")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]
    delete_role.assert_called_once()


def test_role_absent_verification_reported_present(read_role, delete_role):
    read_role.return_value = {"key_type": "otp"}
    res = vault_ssh.role_absent("foo")
    assert res["result"] is False
    assert "There were no errors during role deletion" in res["comment"]
    assert "still reported as present" in res["comment"]
    assert not res["changes"]
    delete_role.assert_called_once()


@pytest.mark.parametrize("port", ("foo", ["22"]))
def test_role_present_otp_invalid_port(read_role, port):
    res = vault_ssh.role_present_otp("foo", "user", port=port)
    assert res["result"] is False
    assert res["comment"] == "'port' must be castable to an integer"
    assert not res["changes"]
    read_role.assert_not_called()


def test_role_present_ca_requires_cert_type(read_role):
    res = vault_ssh.role_present_ca("foo")
    assert res["result"] is False
    assert (
        res["comment"] == "Either allow_user_certificates or allow_host_certificates must be true"
    )
    assert not res["changes"]
    read_role.assert_not_called()
