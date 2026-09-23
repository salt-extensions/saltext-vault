"""
Shared fixtures for the vault_plugin test suites.
"""

import pytest

from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_list
from tests.support.vault import vault_plugin_pin
from tests.support.vault import vault_plugin_register
from tests.support.vault import vault_plugin_show_pin
from tests.support.vault import vault_plugin_unpin


@pytest.fixture(scope="module")
def _secret_plugin(vault_plugins):
    name = "foo_secret"
    path = vault_plugins / name
    alt_path = vault_plugins / "explicit-cmd"
    path.touch()
    path.chmod(0o755)
    alt_path.touch()
    alt_path.chmod(0o755)
    try:
        yield {
            "name": name,
            "plugin_type": "secret",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    finally:
        path.unlink(missing_ok=True)
        alt_path.unlink(missing_ok=True)


@pytest.fixture
def secret_plugin(_secret_plugin):
    return _secret_plugin.copy()


@pytest.fixture(scope="module")
def _auth_plugin(vault_plugins):
    name = "bar_auth"
    path = vault_plugins / name
    path.touch()
    path.chmod(0o755)
    try:
        yield {
            "name": name,
            "plugin_type": "auth",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    finally:
        path.unlink(missing_ok=True)


@pytest.fixture
def auth_plugin(_auth_plugin):
    return _auth_plugin.copy()


@pytest.fixture(scope="module")
def _db_plugin(vault_plugins):
    name = "quux-database-plugin"
    path = vault_plugins / name
    path.touch()
    path.chmod(0o755)
    try:
        yield {
            "name": name,
            "plugin_type": "database",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    finally:
        path.unlink(missing_ok=True)


@pytest.fixture
def db_plugin(_db_plugin):
    return _db_plugin.copy()


@pytest.fixture
def plugins_registered(request):
    defs = getattr(request, "param", {"secret_plugin": [], "db_plugin": [], "auth_plugin": []})
    for fixture, versions in defs.items():
        payload = request.getfixturevalue(fixture).copy()
        if "command" not in payload:
            payload["command"] = payload["name"]
        for version in versions or [""]:
            payload["version"] = version
            vault_plugin_register(**payload)
    yield defs


@pytest.fixture
def plugins_pinned(plugins_registered, request):  # pylint: disable=unused-argument
    # Requires Vault >= 1.16, ensure tests are marked with
    # @pytest.mark.requires_backend("vault>=1.16")
    for fixture, pinned in request.param.items():
        plugin_def = request.getfixturevalue(fixture)
        vault_plugin_pin(plugin_def["plugin_type"], plugin_def["name"], version=pinned)
    yield request.param


@pytest.fixture
def clean_plugins(container):
    try:
        yield
    finally:
        for plugin in vault_plugin_list(lambda x: not x["builtin"]):
            if container.matches("vault>=1.16") and vault_plugin_show_pin(
                plugin["type"], plugin["name"]
            ):
                vault_plugin_unpin(plugin["type"], plugin["name"])
            vault_plugin_deregister(plugin["type"], plugin["name"], version=plugin["version"])
