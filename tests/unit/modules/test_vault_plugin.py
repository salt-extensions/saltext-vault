from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_plugin
from saltext.vault.utils import vault


@pytest.fixture
def configure_loader_modules():
    return {
        vault_plugin: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", return_value=True, autospec=True) as _query:
        yield _query


@pytest.mark.parametrize(
    "func,kwargs",
    (
        ("list_", {"plugin_type": "auth"}),
        ("list_versions", {"plugin_type": "auth", "name": "foo"}),
        ("list_detailed", {}),
        ("list_pins", {}),
        ("pinned_version", {"plugin_type": "auth", "name": "foo"}),
        ("pin", {"plugin_type": "auth", "name": "foo", "version": "v1.0.0"}),
        ("unpin", {"plugin_type": "auth", "name": "foo"}),
        ("get_config", {"plugin_type": "auth", "name": "foo"}),
        ("register", {"plugin_type": "auth", "name": "foo"}),
        ("deregister", {"plugin_type": "auth", "name": "foo"}),
        ("reload", {"plugin_type": "auth", "name": "foo"}),
        ("reload_named", {"name": "foo"}),
        ("reload_mounts", {"mounts": "foo"}),
    ),
)
def test_func_converts_errors(func, kwargs, query):
    query.side_effect = vault.VaultException("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_plugin, func)(**kwargs)


@pytest.mark.parametrize(
    "func,kwargs",
    (
        ("list_", {}),
        ("list_versions", {"name": "foo"}),
        ("list_detailed", {}),
        ("list_pins", {}),
        ("pinned_version", {"name": "foo"}),
        ("pin", {"name": "foo", "version": "v1.0.0"}),
        ("unpin", {"name": "foo"}),
        ("get_config", {"name": "foo"}),
        ("register", {"name": "foo"}),
        ("deregister", {"name": "foo"}),
        ("reload", {"name": "foo"}),
    ),
)
def test_func_validates_plugin_type(func, kwargs, query):
    with pytest.raises(SaltInvocationError, match="Invalid value 'invalid' for `plugin_type`.*"):
        getattr(vault_plugin, func)(plugin_type="invalid", **kwargs)
    query.assert_not_called()


@pytest.mark.parametrize(
    "kwargs,expected_payload",
    (
        # command defaults to the plugin name
        ({}, {"command": "foo"}),
        ({"command": "run-foo"}, {"command": "run-foo"}),
        # with an OCI image, there is no command default
        (
            {"oci_image": "example.com/foo:1", "runtime": "runsc"},
            {"oci_image": "example.com/foo:1", "runtime": "runsc"},
        ),
        (
            {"oci_image": "example.com/foo:1"},
            {"oci_image": "example.com/foo:1"},
        ),
        (
            {"oci_image": "example.com/foo:1", "command": "run-foo"},
            {"oci_image": "example.com/foo:1", "command": "run-foo"},
        ),
        ({"download": True}, {"command": "foo", "download": True}),
    ),
)
def test_register_payload(query, kwargs, expected_payload):
    """
    Ensure the payload only contains specified parameters, especially that
    the command only defaults to the plugin name when no OCI image is
    registered and that a runtime is only ever set together with an image
    """
    assert vault_plugin.register("auth", "foo", **kwargs) is True
    query.assert_called_once()
    assert query.call_args[0][1] == "sys/plugins/catalog/auth/foo"
    assert query.call_args[1]["payload"] == expected_payload


@pytest.mark.parametrize(
    "catalog_response",
    (
        vault.VaultException("listing failed as well"),
        {"data": {"detailed": []}},
    ),
)
def test_get_config_version_fallback_failure(query, catalog_response):
    query.side_effect = (
        vault.VaultNotFoundError("nope"),  # plugin config lookup
        vault.VaultNotFoundError("no pin"),  # pinned_version
        catalog_response,  # list_detailed
    )
    with pytest.raises(CommandExecutionError, match="VaultNotFoundError: nope"):
        vault_plugin.get_config("auth", "foo")
    assert query.call_count == 3


def test_get_config_version_fallback_converts_errors(query):
    query.side_effect = (
        vault.VaultNotFoundError("nope"),  # plugin config lookup
        {"data": {"version": "v1.2.3"}},  # pinned_version
        vault.VaultException("booh"),  # versioned plugin config lookup
    )
    with pytest.raises(CommandExecutionError, match="VaultException: booh"):
        vault_plugin.get_config("auth", "foo")
    assert query.call_count == 3
    assert query.call_args[1]["payload"] == {"version": "v1.2.3"}
