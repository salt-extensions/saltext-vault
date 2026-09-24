import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_plugin
from saltext.vault.utils import vault

# pylint: disable=unused-import
from tests.unit.fixtures.vault import query

# pylint: enable=unused-import


@pytest.fixture
def configure_loader_modules():
    return {
        vault_plugin: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.mark.parametrize(
    "func,kwargs",
    (
        pytest.param("list_", {"plugin_type": "auth"}, id="list_"),
        pytest.param("list_versions", {"plugin_type": "auth", "name": "foo"}, id="list_versions"),
        pytest.param("list_detailed", {}, id="list_detailed"),
        pytest.param("list_pins", {}, id="list_pins"),
        pytest.param("pinned_version", {"plugin_type": "auth", "name": "foo"}, id="pinned_version"),
        pytest.param("pin", {"plugin_type": "auth", "name": "foo", "version": "v1.0.0"}, id="pin"),
        pytest.param("unpin", {"plugin_type": "auth", "name": "foo"}, id="unpin"),
        pytest.param("get_config", {"plugin_type": "auth", "name": "foo"}, id="get_config"),
        pytest.param("register", {"plugin_type": "auth", "name": "foo"}, id="register"),
        pytest.param("deregister", {"plugin_type": "auth", "name": "foo"}, id="deregister"),
        pytest.param("reload", {"plugin_type": "auth", "name": "foo"}, id="reload"),
        pytest.param("reload_named", {"name": "foo"}, id="reload_named"),
        pytest.param("reload_mounts", {"mounts": "foo"}, id="reload_mounts"),
    ),
)
def test_func_converts_errors(func, kwargs, query):
    query.side_effect = vault.VaultException("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_plugin, func)(**kwargs)


@pytest.mark.parametrize(
    "func,kwargs",
    (
        pytest.param("list_", {}, id="list_"),
        pytest.param("list_versions", {"name": "foo"}, id="list_versions"),
        pytest.param("list_detailed", {}, id="list_detailed"),
        pytest.param("list_pins", {}, id="list_pins"),
        pytest.param("pinned_version", {"name": "foo"}, id="pinned_version"),
        pytest.param("pin", {"name": "foo", "version": "v1.0.0"}, id="pin"),
        pytest.param("unpin", {"name": "foo"}, id="unpin"),
        pytest.param("get_config", {"name": "foo"}, id="get_config"),
        pytest.param("register", {"name": "foo"}, id="register"),
        pytest.param("deregister", {"name": "foo"}, id="deregister"),
        pytest.param("reload", {"name": "foo"}, id="reload"),
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
        pytest.param({}, {"command": "foo"}, id="default_command"),
        pytest.param({"command": "run-foo"}, {"command": "run-foo"}, id="explicit_command"),
        # with an OCI image, there is no command default
        pytest.param(
            {"oci_image": "example.com/foo:1", "runtime": "runsc"},
            {"oci_image": "example.com/foo:1", "runtime": "runsc"},
            id="oci_image_runtime",
        ),
        pytest.param(
            {"oci_image": "example.com/foo:1"},
            {"oci_image": "example.com/foo:1"},
            id="oci_image",
        ),
        pytest.param(
            {"oci_image": "example.com/foo:1", "command": "run-foo"},
            {"oci_image": "example.com/foo:1", "command": "run-foo"},
            id="oci_image_command",
        ),
        pytest.param({"download": True}, {"command": "foo", "download": True}, id="download"),
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
        pytest.param(vault.VaultException("listing failed as well"), id="listing_fails"),
        pytest.param({"data": {"detailed": []}}, id="empty_catalog"),
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
