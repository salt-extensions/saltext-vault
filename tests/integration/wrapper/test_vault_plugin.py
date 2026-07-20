import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_plugin import _auth_plugin
from tests.functional.modules.test_vault_plugin import _db_plugin
from tests.functional.modules.test_vault_plugin import _secret_plugin
from tests.functional.modules.test_vault_plugin import auth_plugin
from tests.functional.modules.test_vault_plugin import db_plugin
from tests.functional.modules.test_vault_plugin import plugins_pinned
from tests.functional.modules.test_vault_plugin import plugins_registered
from tests.functional.modules.test_vault_plugin import secret_plugin
from tests.functional.modules.test_vault_plugin import test_list
from tests.functional.modules.test_vault_plugin import test_list_includes_custom_versioned
from tests.functional.modules.test_vault_plugin import test_list_versions
from tests.functional.modules.test_vault_plugin import test_pinned_version
from tests.functional.modules.test_vault_plugin import test_plugin_register

# pylint: enable=unused-import
from tests.support.helpers import WrapperFuncProxy
from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_list
from tests.support.vault import vault_plugin_read
from tests.support.vault import vault_plugin_show_pin
from tests.support.vault import vault_plugin_unpin

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_secret_id
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "plugin_admin",
                ],
            },
        }
    }


@pytest.fixture
def vault_plugin(salt_ssh_cli, container):
    try:
        yield WrapperFuncProxy("vault_plugin", salt_ssh_cli)
    finally:
        for plugin in vault_plugin_list(lambda x: not x["builtin"]):
            if (
                "vault" in container
                and "latest" in container
                and vault_plugin_show_pin(plugin["type"], plugin["name"])
            ):
                vault_plugin_unpin(plugin["type"], plugin["name"])
            vault_plugin_deregister(plugin["type"], plugin["name"], version=plugin["version"])


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": [],
            "db_plugin": ["9.0.0", "9.1.0", "9.2.0"],
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
def test_list_detailed(vault_plugin, auth_plugin, db_plugin, secret_plugin):
    # Just basic testing for wrapper
    res = vault_plugin.list_detailed()
    assert any(plugin["name"] == auth_plugin["name"] for plugin in res)
    assert any(plugin["name"] == db_plugin["name"] for plugin in res)
    assert any(plugin["name"] == secret_plugin["name"] for plugin in res)
    assert any(plugin["name"] == "mysql-database-plugin" for plugin in res)


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "db_plugin": ["9.0.0", "9.1.0", "9.2.0"],
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "db_plugin": "v9.1.0",
            "secret_plugin": "v9.2.3",
        },
    ),
    indirect=True,
)
def test_list_pins(vault_plugin, plugins_pinned, db_plugin, secret_plugin):
    # Just basic testing for wrapper
    res = vault_plugin.list_pins()
    db_pin = {"type": "database", "name": db_plugin["name"], "version": plugins_pinned["db_plugin"]}
    secret_pin = {
        "type": "secret",
        "name": secret_plugin["name"],
        "version": plugins_pinned["secret_plugin"],
    }
    assert len(res) == 2
    assert db_pin in res
    assert secret_pin in res


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "db_plugin": ["3.4.5"],
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
def test_pin(vault_plugin, secret_plugin, db_plugin, container):
    if "vault" not in container or "latest" not in container:
        pytest.skip("Pins are only supported on recent Vault versions")
    res = vault_plugin.pin("secret", secret_plugin["name"], version="9.2.3")
    assert res is True
    assert vault_plugin_show_pin("secret", secret_plugin["name"]) == "v9.2.3"

    # try with now and globally. just don't crash
    res = vault_plugin.pin(
        "database", db_plugin["name"], version="3.4.5", now=True, now_globally=True
    )
    assert res is True
    assert vault_plugin_show_pin("database", db_plugin["name"]) == "v3.4.5"


@pytest.mark.usefixtures("plugins_registered", "plugins_pinned")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "db_plugin": ["3.4.5"],
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "db_plugin": "v3.4.5",
            "secret_plugin": "v9.2.3",
        },
    ),
    indirect=True,
)
def test_unpin(vault_plugin, secret_plugin, db_plugin):
    res = vault_plugin.unpin("secret", secret_plugin["name"])
    assert res is True
    assert vault_plugin_show_pin("secret", secret_plugin["name"]) is False

    # try with now and globally. just don't crash
    res = vault_plugin.unpin("database", db_plugin["name"], now=True, now_globally=True)
    assert res is True
    assert vault_plugin_show_pin("database", db_plugin["name"]) is False


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": [],
            "db_plugin": ["9.0.0", "9.1.0", "9.2.0"],
        },
    ),
    indirect=True,
)
def test_get_config_without_version(vault_plugin, auth_plugin, db_plugin):
    res = vault_plugin.get_config("auth", auth_plugin["name"])
    _ = res.pop("declarative", None), res.pop("oci", None)
    expected = vault_plugin_read("auth", auth_plugin["name"])
    assert res == expected
    res = vault_plugin.get_config("database", db_plugin["name"])
    _ = res.pop("declarative", None), res.pop("oci", None)
    expected = vault_plugin_read("database", db_plugin["name"], "9.2.0")
    assert res == expected


@pytest.mark.usefixtures("plugins_registered", "plugins_pinned")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "db_plugin": ["9.0.0", "9.1.0", "9.2.0"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "db_plugin": "v9.1.0",
        },
    ),
    indirect=True,
)
def test_get_config_without_version_but_pin(vault_plugin, db_plugin):
    res = vault_plugin.get_config("database", db_plugin["name"])
    expected = vault_plugin_read("database", db_plugin["name"], "9.1.0")
    assert res == expected


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": [],
            "db_plugin": ["9.0.0", "9.1.0", "9.2.0"],
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
def test_get_config_with_version(vault_plugin, auth_plugin, db_plugin):
    # Explicit unversioned success
    res = vault_plugin.get_config("auth", auth_plugin["name"], version="")
    # remove OpenBao-specific, unmanaged output
    _ = res.pop("declarative", None), res.pop("oci", None)
    expected = vault_plugin_read("auth", auth_plugin["name"])
    assert res == expected

    # Explicit versioned success
    res = vault_plugin.get_config("database", db_plugin["name"], "9.0.0")
    _ = res.pop("declarative", None), res.pop("oci", None)
    expected = vault_plugin_read("database", db_plugin["name"], "9.0.0")
    assert res == expected


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
def test_plugin_deregister(vault_plugin, secret_plugin):
    res = vault_plugin.deregister("secret", secret_plugin["name"], "9.2.3")
    assert res is True
    assert vault_plugin_read(**secret_plugin, version="9.2.3", _nofail=True) is False
    assert vault_plugin_read(**secret_plugin)
    res = vault_plugin.deregister("secret", secret_plugin["name"])
    assert res is True
    assert vault_plugin_read(**secret_plugin, _nofail=True) is False


def test_reload(vault_plugin, container):
    if "vault" not in container or "latest" not in container:
        pytest.skip("API is only available on recent Vault versions")
    res = vault_plugin.reload("auth", "approle", globally=True)
    assert res
    assert isinstance(res, str)


@pytest.mark.usefixtures("secret_mounts")
@pytest.mark.parametrize("secret_mounts", [("ssh", "database")], indirect=True)
def test_reload_named(vault_plugin):
    res = vault_plugin.reload_named("ssh")
    assert res
    assert isinstance(res, str)


@pytest.mark.usefixtures("secret_mounts")
@pytest.mark.parametrize("secret_mounts", [("ssh", "database")], indirect=True)
def test_reload_mounts(vault_plugin):
    res = vault_plugin.reload_mounts(["ssh", "database"], globally=True)
    assert res
    assert isinstance(res, str)
