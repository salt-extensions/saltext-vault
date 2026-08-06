from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_plugin as vault_plugin_exe
from saltext.vault.states import vault_plugin


@pytest.fixture
def configure_loader_modules():
    return {vault_plugin: {"__opts__": {"test": False}}}


@pytest.fixture
def get_config():
    _get_config = Mock(spec=vault_plugin_exe.get_config)
    with patch.dict(vault_plugin.__salt__, {"vault_plugin.get_config": _get_config}):
        yield _get_config


@pytest.fixture
def list_detailed():
    _list_detailed = Mock(spec=vault_plugin_exe.list_detailed)
    with patch.dict(vault_plugin.__salt__, {"vault_plugin.list_detailed": _list_detailed}):
        yield _list_detailed


@pytest.fixture
def pinned_version():
    _pinned_version = Mock(spec=vault_plugin_exe.pinned_version)
    with patch.dict(vault_plugin.__salt__, {"vault_plugin.pinned_version": _pinned_version}):
        yield _pinned_version


@pytest.fixture
def deregister():
    _deregister = Mock(spec=vault_plugin_exe.deregister, return_value=True)
    with patch.dict(vault_plugin.__salt__, {"vault_plugin.deregister": _deregister}):
        yield _deregister


@pytest.mark.parametrize("err", (CommandExecutionError, SaltInvocationError))
@pytest.mark.parametrize(
    "func,kwargs,err_mock",
    (
        ("registered", {}, "get_config"),
        ("version_registered", {"version": "v1.0.0"}, "get_config"),
        ("unregistered", {}, "get_config"),
        ("version_unregistered", {"version": "v1.0.0"}, "list_detailed"),
        ("version_pinned", {"version": "v1.0.0"}, "pinned_version"),
        ("version_unpinned", {}, "pinned_version"),
    ),
)
def test_errors_are_reported(func, kwargs, err_mock, err, request):
    mock = request.getfixturevalue(err_mock)
    mock.side_effect = err("booh")
    res = getattr(vault_plugin, func)("foo", "auth", **kwargs)
    assert res["result"] is False
    assert res["comment"] == "booh"
    assert not res["changes"]


def test_version_unregistered_deregister_failures_are_reported(list_detailed, deregister):
    list_detailed.return_value = [{"version": "v1.0.0"}, {"version": "v1.1.0"}]
    deregister.side_effect = (True, CommandExecutionError("booh"))
    res = vault_plugin.version_unregistered("foo", "auth", "v1.*")
    assert res["result"] is False
    assert res["changes"] == {"deregistered": ["v1.0.0"]}
    assert "Some versions could not be deregistered" in res["comment"]
    assert "v1.1.0: booh" in res["comment"]
