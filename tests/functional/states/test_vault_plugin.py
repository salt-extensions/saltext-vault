import logging

import pytest

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_plugin import _auth_plugin
from tests.common.fixtures.vault_plugin import _db_plugin
from tests.common.fixtures.vault_plugin import _secret_plugin
from tests.common.fixtures.vault_plugin import auth_plugin
from tests.common.fixtures.vault_plugin import db_plugin
from tests.common.fixtures.vault_plugin import plugins_pinned
from tests.common.fixtures.vault_plugin import plugins_registered
from tests.common.fixtures.vault_plugin import secret_plugin

# pylint: enable=unused-import
from tests.common.helpers.vault_plugin import reset_plugins
from tests.support.vault import vault_plugin_read
from tests.support.vault import vault_plugin_register
from tests.support.vault import vault_plugin_show_pin

pytestmark = genmarks()

log = logging.getLogger(__name__)


@pytest.fixture
def vault_plugin(states, container):
    try:
        yield states.vault_plugin
    finally:
        reset_plugins(container)


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
def test_registered_oci_image_runtime_change_detection(vault_plugin, secret_plugin):
    """
    Ensure specifying oci_image/runtime for a plugin whose current
    configuration does not report these parameters results in a clean
    change prediction instead of an uncaught KeyError.
    """
    ret = vault_plugin.registered(
        secret_plugin["name"],
        plugin_type="secret",
        sha256=secret_plugin["sha256"],
        oci_image="example/image",
        runtime="runsc",
        test=True,
    )
    assert ret.result is None
    assert "Traceback" not in ret.comment
    assert ret.changes.get("oci_image", {}).get("new") == "example/image"
    assert ret.changes.get("runtime", {}).get("new") == "runsc"


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
def test_registered_no_sha256_no_changes(vault_plugin, secret_plugin, testmode):
    """
    When sha256 is not specified (e.g. for plugins registered as an
    extracted .zip artifact, where it must be unset), an existing
    registration should not be reported as changed and reregistered
    on every run.
    """
    ret = vault_plugin.registered(secret_plugin["name"], plugin_type="secret", test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "as specified" in ret.comment


def test_registered_update_keeps_unmanaged_params(vault_plugin, secret_plugin):
    """
    The plugin catalog write replaces the whole configuration, so an
    update triggered by a single changed parameter should try to keep
    unspecified ones (e.g. command and args). ``env`` cannot be preserved
    because it is not reported by the API.
    """
    vault_plugin_register(
        secret_plugin["plugin_type"],
        secret_plugin["name"],
        sha256=secret_plugin["sha256"],
        command="explicit-cmd",
        args=["foo=bar"],
    )
    new_sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
    ret = vault_plugin.registered(secret_plugin["name"], plugin_type="secret", sha256=new_sha)
    assert ret.result is True
    assert ret.changes == {"sha256": {"old": secret_plugin["sha256"], "new": new_sha}}
    plugin = vault_plugin_read("secret", secret_plugin["name"])
    assert plugin["sha256"] == new_sha
    assert plugin["command"] == "explicit-cmd"
    assert plugin["args"] == ["foo=bar"]


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
    if not container.is_vault_latest():
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
