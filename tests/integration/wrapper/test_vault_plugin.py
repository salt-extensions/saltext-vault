import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.helpers import WrapperFuncProxy
from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_list
from tests.support.vault import vault_plugin_pin
from tests.support.vault import vault_plugin_read
from tests.support.vault import vault_plugin_register
from tests.support.vault import vault_plugin_show_pin
from tests.support.vault import vault_plugin_unpin

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
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
def vault_plugin(salt_ssh_cli, container):
    try:
        yield WrapperFuncProxy(salt_ssh_cli)
    finally:
        for plugin in vault_plugin_list(lambda x: not x["builtin"]):
            if (
                "vault" in container
                and "latest" in container
                and vault_plugin_show_pin(plugin["type"], plugin["name"])
            ):
                vault_plugin_unpin(plugin["type"], plugin["name"])
            vault_plugin_deregister(plugin["type"], plugin["name"], version=plugin["version"])


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
def plugins_pinned(plugins_registered, request, container):  # pylint: disable=unused-argument
    if "vault" not in container or "latest" not in container:
        pytest.skip("Pins are only supported on recent Vault versions")
    for fixture, pinned in request.param.items():
        plugin_def = request.getfixturevalue(fixture)
        vault_plugin_pin(plugin_def["plugin_type"], plugin_def["name"], version=pinned)
    yield request.param


def _test_list(vault_plugin, auth_plugin, db_plugin, secret_plugin):
    auth = vault_plugin.list("auth")
    assert auth_plugin["name"] in auth
    dbs = vault_plugin.list("database")
    assert db_plugin["name"] in dbs
    secret = vault_plugin.list("secret")
    assert secret_plugin["name"] in secret


@pytest.mark.usefixtures("plugins_registered")
def test_list(vault_plugin, auth_plugin, db_plugin, secret_plugin):
    _test_list(vault_plugin, auth_plugin, db_plugin, secret_plugin)


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    ({"db_plugin": ["v1.0.0"], "auth_plugin": ["v1.0.0"], "secret_plugin": ["v1.0.0"]},),
    indirect=True,
)
def test_list_includes_custom_versioned(vault_plugin, auth_plugin, db_plugin, secret_plugin):
    _test_list(vault_plugin, auth_plugin, db_plugin, secret_plugin)


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": [],
            "db_plugin": ["1.0.0", "1.1.0", "1.2.0"],
            "secret_plugin": ["", "1.2.3"],
        },
    ),
    indirect=True,
)
def test_list_versions(vault_plugin, auth_plugin, db_plugin, secret_plugin):
    res = vault_plugin.list_versions("auth", auth_plugin["name"])
    assert res == [""]
    res = vault_plugin.list_versions("database", db_plugin["name"])
    assert set(res) == {"v1.0.0", "v1.1.0", "v1.2.0"}
    res = vault_plugin.list_versions("secret", secret_plugin["name"])
    assert set(res) == {"", "v1.2.3"}


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
            "secret_plugin": ["", "9.2.3"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "secret_plugin": "v9.2.3",
        },
    ),
    indirect=True,
)
def test_pinned_version(vault_plugin, plugins_pinned, secret_plugin):
    res = vault_plugin.pinned_version("secret", secret_plugin["name"])
    assert res == plugins_pinned["secret_plugin"]


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


def _assert_plug(plugin_def):
    plugin = vault_plugin_read(**plugin_def)
    for key, val in plugin_def.items():
        if key == "plugin_type":
            continue
        assert plugin[key] == val


def test_plugin_register(vault_plugin, secret_plugin):
    secret_plugin.update({"command": "explicit-cmd", "version": "v1.2.3", "args": ["foo", "bar"]})
    res = vault_plugin.register(**secret_plugin)
    assert res is True
    _assert_plug(secret_plugin)


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


def test_reload_named(vault_plugin):
    res = vault_plugin.reload_named("approle")
    assert res
    assert isinstance(res, str)


def test_reload_mounts(vault_plugin):
    res = vault_plugin.reload_mounts(["secret-v1", "salt"], globally=True)
    assert res
    assert isinstance(res, str)
