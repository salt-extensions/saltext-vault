import pytest

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import existing_secret
from tests.common.fixtures.vault import kv_mount
from tests.common.fixtures.vault import temp_kvv2_path
from tests.common.fixtures.vault import versionable_secret

# pylint: enable=unused-import
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_read_secret_metadata

pytestmark = genmarks(
    mounts=[[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
)


@pytest.fixture
def vault_secret(states):
    return states.vault_secret


@pytest.mark.parametrize("sync", (False, True))
def test_present_create(vault_secret, temp_kvv2_path, sync, testmode):
    values = {"foo": "bar"}
    ret = vault_secret.present(temp_kvv2_path, values=values, sync=sync, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    res = vault_read_secret(temp_kvv2_path)
    assert (res != values) is testmode


@pytest.mark.parametrize("sync", (False, True))
def test_present_already_present(vault_secret, versionable_secret, sync, testmode):
    values = {"user": "foo", "password": "bar"}
    ret = vault_secret.present(versionable_secret, values=values, sync=sync, test=testmode)
    assert ret.result is True
    assert "as specified" in ret.comment
    assert not ret.changes
    res = vault_read_secret(versionable_secret)
    assert res == values


@pytest.mark.parametrize("sync", (False, True))
def test_present_change(vault_secret, versionable_secret, sync, testmode):
    values = {"bar": "baz"}
    ret = vault_secret.present(versionable_secret, values=values, sync=sync, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert ("written" in ret.changes) is sync
    assert ("patched" in ret.changes) is not sync
    assert ret.changes[next(iter(ret.changes))] == versionable_secret
    res = vault_read_secret(versionable_secret)
    assert (res == values) is (not testmode and sync)
    assert ("user" in res) is (testmode or not sync)


def test_present_change_patch(vault_secret, versionable_secret, testmode):
    values = {"user": None, "password": "bar"}
    ret = vault_secret.present(versionable_secret, values=values, sync=False, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "patched" in ret.changes
    assert ret.changes["patched"] == versionable_secret
    res = vault_read_secret(versionable_secret)
    assert ("user" in res) is testmode
    assert (res != {"password": "bar"}) is testmode


def test_present_patch_scalar_to_mapping(vault_secret, versionable_secret, testmode):
    """
    Replacing an existing scalar value with a mapping in the default
    (patch) mode crashed with an uncaught ValueError raised by the
    local JSON merge patch implementation instead of applying the change.
    """
    values = {"user": {"bar": "baz"}}
    ret = vault_secret.present(versionable_secret, values=values, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert "Traceback" not in ret.comment
    assert ret.changes
    assert "patched" in ret.changes
    res = vault_read_secret(versionable_secret)
    values["password"] = "bar"
    assert (res == values) is not testmode


def test_present_path_key(vault_secret, temp_kvv2_path, testmode):
    """
    A secret key named ``path`` clashed with the first positional
    argument of the execution module functions the secret data is
    passed to as keyword arguments, resulting in an uncaught TypeError.
    """
    values = {"path": "foo"}
    ret = vault_secret.present(temp_kvv2_path, values=values, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert "Traceback" not in ret.comment
    assert ret.changes
    res = vault_read_secret(temp_kvv2_path)
    assert (res == values) is not testmode


def test_present_dunder_key(vault_secret, temp_kvv2_path, testmode):
    """
    Keys beginning with a double underscore were silently dropped by the
    execution module when passed as keyword arguments, so the state
    reported success without ever writing them and never converged.
    """
    values = {"__foo": "bar"}
    ret = vault_secret.present(temp_kvv2_path, values=values, test=testmode)
    assert ret.result is (None if testmode else True)
    if testmode:
        return
    assert vault_read_secret(temp_kvv2_path) == values
    ret = vault_secret.present(temp_kvv2_path, values=values)
    assert ret.result is True
    assert not ret.changes


def test_absent_already_absent(vault_secret, testmode):
    ret = vault_secret.absent("secret/foo/bar/nonexistent", test=testmode)
    assert ret.result is True
    assert "already absent" in ret.comment
    assert not ret.changes


def test_absent(vault_secret, versionable_secret, testmode):
    ret = vault_secret.absent(versionable_secret, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == versionable_secret
    res = vault_read_secret(versionable_secret)
    assert (res is None) is not testmode
    meta = vault_read_secret_metadata(versionable_secret)
    assert bool(meta["versions"]["1"]["deletion_time"]) is not testmode


def test_absent_destroy(vault_secret, versionable_secret, testmode):
    ret = vault_secret.absent(versionable_secret, operation="destroy", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "destroyed" in ret.changes
    assert ret.changes["destroyed"] == versionable_secret
    res = vault_read_secret(versionable_secret)
    assert (res is None) is not testmode
    meta = vault_read_secret_metadata(versionable_secret)
    assert bool(meta["versions"]["1"]["destroyed"]) is not testmode


def test_absent_wipe(vault_secret, versionable_secret, testmode):
    ret = vault_secret.absent(versionable_secret, operation="wipe", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "wiped" in ret.changes
    assert ret.changes["wiped"] == versionable_secret
    res = vault_read_secret(versionable_secret)
    assert (res is None) is not testmode
    meta = vault_read_secret_metadata(versionable_secret)
    assert (meta is None) is not testmode


@pytest.mark.parametrize("kv_mount", ("secret-v1",), indirect=True)
@pytest.mark.parametrize("operation", ("delete", "destroy", "wipe"))
def test_absent_kv_v1(vault_secret, existing_secret, operation, testmode):
    """
    On KV v1, all operations should remove the secret since the backend
    does not support versioning (as documented). ``destroy`` and ``wipe``
    fall back to delete, which is functionally equivalent.
    """
    ret = vault_secret.absent(existing_secret, operation=operation, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    res = vault_read_secret(existing_secret)
    assert (res is None) is not testmode
