import logging

import pytest
from salt.exceptions import CommandExecutionError

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import kv_mount
from tests.common.fixtures.vault import versionable_secret
from tests.common.fixtures.vault import versioned_secret
from tests.common.fixtures.vault import versioned_secret_all_deleted
from tests.common.fixtures.vault import versioned_secret_deleted
from tests.common.fixtures.vault import versioned_secret_destroyed

# pylint: enable=unused-import
from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_read_secret_metadata

pytestmark = genmarks(
    mounts=[[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]], secrets=True
)

log = logging.getLogger(__name__)


@pytest.fixture
def vault_secret(modules, vault_secrets):  # pylint: disable=unused-argument
    return modules.vault_secret


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret-v1/my/secret": {"user": "foo", "password": "bar"},
        "secret-v1/delete/me": {"user": "foo"},
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }


def test_read(vault_secret, kv_mount):
    res = vault_secret.read(f"{kv_mount}/my/secret")
    assert res == {"user": "foo", "password": "bar"}


def test_read_key(vault_secret, kv_mount):
    res = vault_secret.read(f"{kv_mount}/my/secret", "user")
    assert res == "foo"


def test_read_missing(vault_secret, kv_mount):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*VaultNotFound.*"):
        vault_secret.read(f"{kv_mount}/missing/secret")


def test_read_missing_default(vault_secret, kv_mount):
    res = vault_secret.read(f"{kv_mount}/missing/secret", default="__missing__")
    assert res == "__missing__"


def test_read_missing_key(vault_secret, kv_mount):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*KeyError.*"):
        vault_secret.read(f"{kv_mount}/my/secret", "bar")


def test_read_missing_key_default(vault_secret, kv_mount):
    res = vault_secret.read(f"{kv_mount}/my/secret", "bar", default="__missing__")
    assert res == "__missing__"


def test_read_with_metadata(vault_secret):
    res = vault_secret.read("secret/my/secret", metadata=True)
    assert res
    assert "data" in res
    assert "metadata" in res
    expected_read = {"password": "bar", "user": "foo"}
    assert res["data"] == expected_read


@pytest.mark.parametrize("key", (None, "password"))
def test_read_version(vault_secret, versioned_secret, key):
    ret = vault_secret.read(versioned_secret, key, version=1)
    if not key:
        ret = ret["password"]
    assert ret == "bar"
    ret = vault_secret.read(versioned_secret, key, version=2)
    if not key:
        ret = ret["password"]
    assert ret == "hunter1"


def test_read_version_missing(vault_secret, versioned_secret):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*VaultNotFound.*"):
        vault_secret.read(versioned_secret, version=3)


def test_read_version_missing_default(vault_secret, versioned_secret):
    res = vault_secret.read(versioned_secret, version=3, default="__missing__")
    assert res == "__missing__"


def test_read_secret_deleted(vault_secret, versioned_secret_deleted):
    ret = vault_secret.read_meta(versioned_secret_deleted)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


def test_read_secret_destroyed(vault_secret, versioned_secret_destroyed):
    ret = vault_secret.read_meta(versioned_secret_destroyed)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert curr_vers["destroyed"]


def test_read_meta(vault_secret, versioned_secret):
    ret = vault_secret.read_meta(versioned_secret)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


@pytest.mark.parametrize("raw", (False, True))
def test_write(vault_secret, kv_mount, raw):
    path = f"{kv_mount}/write/{'raw_' if raw else ''}secret"
    data = {"user": "foo", "password": "bar"}
    if raw:
        res = vault_secret.write_raw(path, data)
    else:
        res = vault_secret.write(path, **data)
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    assert vault_read_secret(path) == data


@pytest.mark.parametrize("raw", (False, True))
def test_patch(vault_secret, kv_mount, raw):
    path = f"{kv_mount}/patched_{'raw_' if raw else ''}secret"
    if raw:
        res = vault_secret.write_raw(path, {"foo": "bar"})
    else:
        res = vault_secret.write(path, foo="bar")
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    if raw:
        res = vault_secret.patch_raw(path, {"bar": "baz"})
    else:
        res = vault_secret.patch(path, bar="baz")
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 2
    assert vault_read_secret(path) == {"foo": "bar", "bar": "baz"}


def test_list(vault_secret, kv_mount):
    ret = vault_secret.list(f"{kv_mount}/my/")
    assert ret == ["secret"]


def test_delete(vault_secret, kv_mount):
    path = f"{kv_mount}/delete/me"
    assert vault_read_secret(path) is not None
    assert vault_secret.delete(path) is True
    assert vault_read_secret(path) is None
    if "v1" not in kv_mount:
        metadata = vault_read_secret_metadata(path)
        curr_vers = metadata["versions"][str(metadata["current_version"])]
        assert curr_vers["deletion_time"]
        assert not curr_vers["destroyed"]


def test_delete_latest(vault_secret, versioned_secret):
    res = vault_secret.delete(versioned_secret)
    assert res is True
    ret = vault_read_secret(versioned_secret, version=1)
    assert ret["password"] == "bar"
    ret = vault_read_secret(versioned_secret, version=2)
    assert ret is None


def test_delete_version(vault_secret, versioned_secret):
    res = vault_secret.delete(versioned_secret, 1)
    assert res is True
    ret = vault_secret.read(versioned_secret, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault_secret.read(versioned_secret)
    assert ret["password"] == "hunter1"
    res = vault_secret.delete(versioned_secret, "2")
    assert res is True
    ret = vault_secret.read(versioned_secret, default="__deleted__")
    assert ret == "__deleted__"


def test_delete_all_versions(vault_secret, versioned_secret):
    res = vault_secret.delete(versioned_secret, all_versions=True)
    assert res is True
    ret = vault_secret.read(versioned_secret, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault_secret.read(versioned_secret, default="__deleted__")
    assert ret == "__deleted__"


def test_delete_all_versions_latest_deleted_already(vault_secret, versioned_secret_deleted):
    res = vault_secret.delete(versioned_secret_deleted, all_versions=True)
    assert res is True
    ret = vault_secret.read(versioned_secret_deleted, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault_secret.read(versioned_secret_deleted, default="__deleted__")
    assert ret == "__deleted__"


def test_restore(vault_secret, versioned_secret_deleted):
    ret = vault_secret.restore(versioned_secret_deleted)
    assert ret is True
    curr = vault_read_secret(versioned_secret_deleted)
    assert curr["password"] == "hunter1"


def test_restore_version(vault_secret, versioned_secret_deleted):
    ret = vault_secret.restore(versioned_secret_deleted, 1)
    assert ret is True
    curr = vault_read_secret(versioned_secret_deleted, version=1)
    assert curr["password"] == "bar"
    curr = vault_read_secret(versioned_secret_deleted, version=2)
    assert curr is None


def test_restore_all_versions(vault_secret, versioned_secret_all_deleted):
    ret = vault_secret.restore(versioned_secret_all_deleted, all_versions=True)
    assert ret is True
    curr = vault_read_secret(versioned_secret_all_deleted, version=1)
    assert curr["password"] == "bar"
    curr = vault_read_secret(versioned_secret_all_deleted, version=2)
    assert curr["password"] == "hunter1"


def test_restore_latest_not_deleted(vault_secret, versioned_secret):
    vault_delete_secret(versioned_secret, versions=1)
    with pytest.raises(CommandExecutionError, match="No secret version to restore."):
        vault_secret.restore(versioned_secret)


def test_destroy_latest(vault_secret, versioned_secret):
    assert vault_secret.destroy(versioned_secret) is True
    ret = vault_read_secret(versioned_secret)
    assert ret is None
    ret = vault_read_secret(versioned_secret, version=1)
    assert ret["password"] == "bar"


def test_destroy_versions(vault_secret, versioned_secret):
    assert vault_secret.destroy(versioned_secret, "1") is True
    ret = vault_secret.read(versioned_secret)
    assert ret["password"] == "hunter1"
    assert vault_secret.destroy(versioned_secret, 2) is True
    ret = vault_secret.read(versioned_secret, default="__destroyed__")
    assert ret == "__destroyed__"


def test_destroy_all_versions(vault_secret, versioned_secret):
    assert vault_secret.destroy(versioned_secret, all_versions=True) is True
    for version in range(2):
        ret = vault_secret.read(versioned_secret, default="__destroyed__", version=version + 1)
        assert ret == "__destroyed__"


def test_wipe(vault_secret, versioned_secret):
    assert vault_secret.wipe(versioned_secret) is True
    with pytest.raises(CommandExecutionError, match="VaultNotFound"):
        vault_secret.read_meta(versioned_secret)
