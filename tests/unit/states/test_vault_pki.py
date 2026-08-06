from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_pki as vault_pki_exe
from saltext.vault.states import vault_pki


@pytest.fixture
def configure_loader_modules():
    return {vault_pki: {"__opts__": {}, "__low__": {"__id__": "test"}}}


@pytest.fixture
def read_role():
    _read_role = Mock(spec=vault_pki_exe.read_role)
    with patch.dict(vault_pki.__salt__, {"vault_pki.read_role": _read_role}):
        yield _read_role


@pytest.fixture
def file_mocks():
    file_managed_ret = {
        "file_|-test_|-test_|-managed": {"result": True, "comment": "", "changes": {}}
    }
    mocks = {
        "state.single": Mock(return_value=file_managed_ret),
        "file.is_link": Mock(return_value=False),
        "file.file_exists": Mock(return_value=False),
    }
    with patch.dict(vault_pki.__salt__, mocks):
        yield mocks


def test_certificate_managed_invalid_encoding():
    res = vault_pki.certificate_managed(
        "/etc/pki/cert.pem", "example.com", "role", "pk", encoding="foo"
    )
    assert res["result"] is False
    assert "Invalid value 'foo' for encoding" in res["comment"]
    assert not res["changes"]


@pytest.mark.parametrize("ttl_remaining", ("720h", "1000h"))
def test_certificate_managed_invalid_ttl_remaining(ttl_remaining):
    res = vault_pki.certificate_managed(
        "/etc/pki/cert.pem", "example.com", "role", "pk", ttl_remaining=ttl_remaining
    )
    assert res["result"] is False
    assert "cannot be larger or equal to ttl" in res["comment"]
    assert not res["changes"]


def test_certificate_managed_file_test_failure_is_reported(file_mocks):
    file_mocks["state.single"].return_value = {
        "file_|-test_|-test_|-managed": {"result": False, "comment": "booh", "changes": {}}
    }
    res = vault_pki.certificate_managed("/etc/pki/cert.pem", "example.com", "role", "pk")
    assert res["result"] is False
    assert res["comment"] == "Problem while testing file.managed changes, see its output"
    assert not res["changes"]
    assert res["sub_state_run"][0]["comment"] == "booh"


@pytest.mark.usefixtures("file_mocks")
@pytest.mark.parametrize("err", (CommandExecutionError, SaltInvocationError))
def test_certificate_managed_errors_are_reported(read_role, err):
    read_role.side_effect = err("booh")
    res = vault_pki.certificate_managed("/etc/pki/cert.pem", "example.com", "role", "pk")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]


@pytest.mark.parametrize("func", ("role_managed", "role_absent"))
@pytest.mark.parametrize("err", (CommandExecutionError, SaltInvocationError))
def test_role_errors_are_reported(read_role, func, err):
    read_role.side_effect = err("booh")
    res = getattr(vault_pki, func)("role")
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]


@pytest.mark.parametrize(
    "fret_result,current,expected_comment",
    (
        (False, False, "Could not create file, see file.managed output"),
        (False, True, "Could not update file, see file.managed output"),
        (True, True, None),
        (None, False, None),
    ),
)
def test_check_file_ret(fret_result, current, expected_comment):
    ret = {
        "name": "test",
        "result": True,
        "comment": "The certificate has been created",
        "changes": {"created": True},
    }
    res = vault_pki._check_file_ret({"result": fret_result}, ret, current)
    if expected_comment is None:
        # The state result should not have been modified
        assert res is True
        assert ret["result"] is True
        assert ret["comment"] == "The certificate has been created"
        assert ret["changes"] == {"created": True}
    else:
        assert res is False
        assert ret["result"] is False
        assert ret["comment"] == expected_comment
        assert not ret["changes"]
