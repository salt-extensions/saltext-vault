import pytest

from tests.support.vault import vault_read_secret
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts"),
]


@pytest.fixture
def vault_secret(states):
    yield states.vault_secret


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


@pytest.fixture
def temp_secret(modules):
    key = "secret/my/secret"
    yield key
    assert modules.vault.wipe_secret(key) is True


@pytest.fixture
def secret_present(temp_secret):
    vault_write_secret(temp_secret, foo="bar")
    assert vault_read_secret(temp_secret) == {"foo": "bar"}
    yield temp_secret


@pytest.mark.parametrize("sync", (False, True))
def test_present_create(vault_secret, temp_secret, sync, testmode):
    values = {"foo": "bar"}
    ret = vault_secret.present(temp_secret, values=values, sync=sync, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    res = vault_read_secret(temp_secret)
    assert (res != values) is testmode


@pytest.mark.parametrize("sync", (False, True))
def test_present_already_present(vault_secret, secret_present, sync, testmode):
    values = {"foo": "bar"}
    ret = vault_secret.present(secret_present, values=values, sync=sync, test=testmode)
    assert ret.result is True
    assert "as specified" in ret.comment
    assert not ret.changes
    res = vault_read_secret(secret_present)
    assert res == values


@pytest.mark.parametrize("sync", (False, True))
def test_present_change(vault_secret, secret_present, sync, testmode):
    values = {"bar": "baz"}
    ret = vault_secret.present(secret_present, values=values, sync=sync, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert ("written" in ret.changes) is sync
    assert ("patched" in ret.changes) is not sync
    assert ret.changes[next(iter(ret.changes))] == secret_present
    res = vault_read_secret(secret_present)
    assert (res == values) is (not testmode and sync)
    assert ("foo" in res) is (testmode or not sync)


def test_present_change_patch(vault_secret, secret_present, testmode):
    values = {"foo": None, "bar": "baz"}
    ret = vault_secret.present(secret_present, values=values, sync=False, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "patched" in ret.changes
    assert ret.changes["patched"] == secret_present
    res = vault_read_secret(secret_present)
    assert ("foo" in res) is testmode
    assert (res != {"bar": "baz"}) is testmode


def test_present_patch_scalar_to_mapping(vault_secret, secret_present, testmode):
    """
    Replacing an existing scalar value with a mapping in the default
    (patch) mode crashed with an uncaught ValueError raised by the
    local JSON merge patch implementation instead of applying the change.
    """
    values = {"foo": {"bar": "baz"}}
    ret = vault_secret.present(secret_present, values=values, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert "Traceback" not in ret.comment
    assert ret.changes
    assert "patched" in ret.changes
    res = vault_read_secret(secret_present)
    assert (res == values) is not testmode


def test_present_path_key(vault_secret, temp_secret, testmode):
    """
    A secret key named ``path`` clashed with the first positional
    argument of the execution module functions the secret data is
    passed to as keyword arguments, resulting in an uncaught TypeError.
    """
    values = {"path": "foo"}
    ret = vault_secret.present(temp_secret, values=values, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert "Traceback" not in ret.comment
    assert ret.changes
    res = vault_read_secret(temp_secret)
    assert (res == values) is not testmode


def test_present_dunder_key(vault_secret, temp_secret, testmode):
    """
    Keys beginning with a double underscore were silently dropped by the
    execution module when passed as keyword arguments, so the state
    reported success without ever writing them and never converged.
    """
    values = {"__foo": "bar"}
    ret = vault_secret.present(temp_secret, values=values, test=testmode)
    assert ret.result is (None if testmode else True)
    if testmode:
        return
    assert vault_read_secret(temp_secret) == values
    ret = vault_secret.present(temp_secret, values=values)
    assert ret.result is True
    assert not ret.changes


def test_absent_already_absent(vault_secret, testmode):
    ret = vault_secret.absent("secret/foo/bar/nonexistent", test=testmode)
    assert ret.result is True
    assert "already absent" in ret.comment
    assert not ret.changes


def test_absent(vault_secret, secret_present, testmode, modules):
    ret = vault_secret.absent(secret_present, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"] == secret_present
    res = vault_read_secret(secret_present)
    assert (res is None) is not testmode
    meta = modules.vault.read_secret_meta(secret_present)
    assert bool(meta["versions"]["1"]["deletion_time"]) is not testmode


def test_absent_destroy(vault_secret, secret_present, testmode, modules):
    ret = vault_secret.absent(secret_present, operation="destroy", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "destroyed" in ret.changes
    assert ret.changes["destroyed"] == secret_present
    res = vault_read_secret(secret_present)
    assert (res is None) is not testmode
    meta = modules.vault.read_secret_meta(secret_present)
    assert bool(meta["versions"]["1"]["destroyed"]) is not testmode


def test_absent_wipe(vault_secret, secret_present, testmode, modules):
    ret = vault_secret.absent(secret_present, operation="wipe", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    assert "wiped" in ret.changes
    assert ret.changes["wiped"] == secret_present
    res = vault_read_secret(secret_present)
    assert (res is None) is not testmode
    meta = modules.vault.read_secret_meta(secret_present)
    assert (meta is False) is not testmode


@pytest.mark.parametrize("secret_mounts", ((("kv", "secret-v1"),),), indirect=True)
@pytest.mark.parametrize("operation", ("delete", "destroy", "wipe"))
def test_absent_kv_v1(vault_secret, operation, testmode):
    """
    On KV v1, all operations should remove the secret since the backend
    does not support versioning (as documented). ``destroy`` and ``wipe``
    fall back to delete, which is functionally equivalent.
    """
    path = "secret-v1/my/secret"
    vault_write_secret(path, foo="bar")
    ret = vault_secret.absent(path, operation=operation, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("Would have" in ret.comment) is testmode
    assert ret.changes
    res = vault_read_secret(path)
    assert (res is None) is not testmode
