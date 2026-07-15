import logging

import pytest

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
]

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def minion_config_overrides(vault_port):
    return {
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
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
def vault_plugin(states, container):
    try:
        yield states.vault_plugin
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


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


def _reg_new(ret, secret_plugin, testmode, version=None):
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes == {"registered": secret_plugin["name"]}
    assert ("would have" in ret.comment) is testmode
    assert ret.comment.endswith("registered")
    plugin = vault_plugin_read("secret", secret_plugin["name"], version=version, _nofail=True)
    if testmode:
        assert plugin is False
    else:
        assert plugin
        assert plugin["sha256"] == secret_plugin["sha256"]


def test_registered_new(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.registered(
        secret_plugin["name"], plugin_type="secret", sha256=secret_plugin["sha256"], test=testmode
    )
    _reg_new(ret, secret_plugin, testmode)


def test_registered_version_new(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.version_registered(
        secret_plugin["name"],
        plugin_type="secret",
        sha256=secret_plugin["sha256"],
        version="1.0.0",
        test=testmode,
    )
    _reg_new(ret, secret_plugin, testmode, "v1.0.0")


def _reg_upd(ret, secret_plugin, testmode, changes, version=None):
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ("would have" in ret.comment) is testmode
    assert ret.comment.endswith("updated")
    plugin = vault_plugin_read("secret", secret_plugin["name"], version=version)
    for param, newval in changes.items():
        oldval = secret_plugin.get(param)
        if param == "command":
            oldval = secret_plugin["name"]
        elif isinstance(newval, list):
            oldval = oldval or []
        assert ret.changes[param] == {"old": oldval, "new": newval}
        assert (plugin[param] == newval) is not testmode


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "secret_plugin": [],
        },
    ),
    indirect=True,
)
def test_registered_update_changes(vault_plugin, secret_plugin, testmode):
    changes = {
        "sha256": "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        "command": "explicit-cmd",
        "args": ["foo", "bar"],
    }
    ret = vault_plugin.registered(
        secret_plugin["name"],
        plugin_type="secret",
        **changes,
        test=testmode,
    )
    _reg_upd(ret, secret_plugin, testmode, changes)


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "secret_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_registered_version_update_changes(vault_plugin, secret_plugin, testmode):
    changes = {
        "sha256": "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        "command": "explicit-cmd",
        "args": ["foo", "bar"],
    }
    ret = vault_plugin.version_registered(
        secret_plugin["name"],
        plugin_type="secret",
        **changes,
        version="1.2.3",
        test=testmode,
    )
    _reg_upd(ret, secret_plugin, testmode, changes, "1.2.3")


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "secret_plugin": [],
        },
    ),
    indirect=True,
)
def test_registered_ok(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.registered(
        secret_plugin["name"], plugin_type="secret", sha256=secret_plugin["sha256"], test=testmode
    )
    assert ret.result is True
    assert not ret.changes
    assert "as specified" in ret.comment


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "secret_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_registered_version_ok(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.version_registered(
        secret_plugin["name"],
        plugin_type="secret",
        version="1.2.3",
        sha256=secret_plugin["sha256"],
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes
    assert "as specified" in ret.comment


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "db_plugin": [],
        },
    ),
    indirect=True,
)
def test_unregistered_changes(vault_plugin, db_plugin, testmode):
    ret = vault_plugin.unregistered(
        db_plugin["name"],
        plugin_type="database",
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes == {"deregistered": db_plugin["name"]}
    assert ("would have" in ret.comment) is testmode
    plugin = vault_plugin_read("database", db_plugin["name"], _nofail=True)
    assert bool(plugin) is testmode


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "db_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_unregistered_ok(vault_plugin, db_plugin, testmode):
    ret = vault_plugin.unregistered(
        db_plugin["name"],
        plugin_type="database",
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes
    assert "already absent" in ret.comment


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_unregistered_version_changes(vault_plugin, auth_plugin, testmode):
    ret = vault_plugin.version_unregistered(
        auth_plugin["name"],
        plugin_type="auth",
        version="1.2.3",
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes == {"deregistered": ["v1.2.3"]}
    assert ("would have" in ret.comment) is testmode
    plugin = vault_plugin_read("auth", auth_plugin["name"], version="1.2.3", _nofail=True)
    assert bool(plugin) is testmode


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3", "v1.2.4", "v1.2.5", "v1.3.0"],
        },
    ),
    indirect=True,
)
def test_unregistered_version_multiple_changes(vault_plugin, auth_plugin, testmode):
    expected_absent = {"v1.2.3", "v1.2.4", "v1.2.5"}
    ret = vault_plugin.version_unregistered(
        auth_plugin["name"],
        plugin_type="auth",
        version="1.2.*",
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert set(ret.changes["deregistered"]) == expected_absent
    assert ("would have" in ret.comment) is testmode
    for version in expected_absent:
        plugin = vault_plugin_read("auth", auth_plugin["name"], version=version, _nofail=True)
        assert bool(plugin) is testmode
    assert vault_plugin_read("auth", auth_plugin["name"], version="1.3.0", _nofail=True)


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["", "v1.2.3", "v1.3.4"],
        },
    ),
    indirect=True,
)
def test_unregistered_version_does_not_delete_unversioned(vault_plugin, auth_plugin, testmode):
    expected_absent = {"v1.2.3", "v1.3.4"}
    ret = vault_plugin.version_unregistered(
        auth_plugin["name"],
        plugin_type="auth",
        version="*",
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert set(ret.changes["deregistered"]) == expected_absent
    assert ("would have" in ret.comment) is testmode
    for version in expected_absent:
        plugin = vault_plugin_read("auth", auth_plugin["name"], version=version, _nofail=True)
        assert bool(plugin) is testmode
    assert vault_plugin_read("auth", auth_plugin["name"], _nofail=True)


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_unregistered_version_ok(vault_plugin, auth_plugin, testmode):
    ret = vault_plugin.version_unregistered(
        auth_plugin["name"],
        plugin_type="auth",
        version="2.3.4",
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes
    assert "already absent" in ret.comment


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_version_pinned_create_changes(vault_plugin, auth_plugin, testmode, container):
    if "vault" not in container or "latest" not in container:
        pytest.skip("Pins are only supported on recent Vault versions")
    ret = vault_plugin.version_pinned(
        auth_plugin["name"],
        plugin_type="auth",
        version="1.2.3",
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes == {"old": None, "new": "1.2.3"}
    assert ("would have" in ret.comment) is testmode
    pin = vault_plugin_show_pin("auth", auth_plugin["name"])
    assert bool(pin) is not testmode


@pytest.mark.usefixtures("plugins_registered", "plugins_pinned")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3", "v2.3.4"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "auth_plugin": "v1.2.3",
        },
    ),
    indirect=True,
)
def test_version_pinned_update_changes(vault_plugin, auth_plugin, testmode):
    ret = vault_plugin.version_pinned(
        auth_plugin["name"],
        plugin_type="auth",
        version="2.3.4",
        now=True,
        now_globally=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes == {"old": "v1.2.3", "new": "2.3.4"}
    assert ("would have" in ret.comment) is testmode
    pin = vault_plugin_show_pin("auth", auth_plugin["name"])
    assert (pin == "v2.3.4") is not testmode


@pytest.mark.usefixtures("plugins_registered", "plugins_pinned")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "auth_plugin": "v1.2.3",
        },
    ),
    indirect=True,
)
def test_version_pinned_ok(vault_plugin, auth_plugin, testmode):
    ret = vault_plugin.version_pinned(
        auth_plugin["name"],
        plugin_type="auth",
        version="1.2.3",
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes
    assert "already pinned" in ret.comment


@pytest.mark.usefixtures("plugins_registered", "plugins_pinned")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "plugins_pinned",
    (
        {
            "auth_plugin": "v1.2.3",
        },
    ),
    indirect=True,
)
def test_version_unpinned_changes(vault_plugin, auth_plugin, testmode):
    ret = vault_plugin.version_unpinned(
        auth_plugin["name"],
        plugin_type="auth",
        now=True,
        now_globally=True,
        test=testmode,
    )
    assert ret.result in (None, True)
    assert (ret.result is None) is testmode
    assert ret.changes == {"old": "v1.2.3", "new": None}
    assert ("would have" in ret.comment) is testmode
    pin = vault_plugin_show_pin("auth", auth_plugin["name"])
    assert bool(pin) is testmode


@pytest.mark.usefixtures("plugins_registered")
@pytest.mark.parametrize(
    "plugins_registered",
    (
        {
            "auth_plugin": ["v1.2.3"],
        },
    ),
    indirect=True,
)
def test_version_unpinned_ok(vault_plugin, auth_plugin, testmode):
    ret = vault_plugin.version_unpinned(
        auth_plugin["name"],
        plugin_type="auth",
        test=testmode,
    )
    assert ret.result is True
    assert not ret.changes
    assert "already unpinned" in ret.comment


def test_version_registered_requires_version(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.version_registered(
        secret_plugin["name"],
        plugin_type="secret",
        sha256=secret_plugin["sha256"],
        version="",
        test=testmode,
    )
    assert ret.result is False
    assert "not empty" in ret.comment
    assert not ret.changes


def test_version_unregistered_requires_version(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.version_unregistered(
        secret_plugin["name"],
        plugin_type="secret",
        version="",
        test=testmode,
    )
    assert ret.result is False
    assert "not empty" in ret.comment
    assert not ret.changes


def test_version_pinned_requires_version(vault_plugin, secret_plugin, testmode):
    ret = vault_plugin.version_pinned(
        secret_plugin["name"],
        plugin_type="secret",
        version="",
        test=testmode,
    )
    assert ret.result is False
    assert "not empty" in ret.comment
    assert not ret.changes
