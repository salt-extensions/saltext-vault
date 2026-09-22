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


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret-v1/my/secret": {"user": "foo", "password": "bar"},
        "secret-v1/delete/me": {"user": "foo"},
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }


def test_read_secret(vault, kv_mount):
    res = vault.read_secret(f"{kv_mount}/my/secret")
    assert res == {"user": "foo", "password": "bar"}


def test_read_secret_key(vault, kv_mount):
    res = vault.read_secret(f"{kv_mount}/my/secret", "user")
    assert res == "foo"


def test_read_secret_missing(vault, kv_mount):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*VaultNotFound.*"):
        vault.read_secret(f"{kv_mount}/missing/secret")


def test_read_secret_missing_default(vault, kv_mount):
    res = vault.read_secret(f"{kv_mount}/missing/secret", default="__missing__")
    assert res == "__missing__"


def test_read_secret_missing_key(vault, kv_mount):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*KeyError.*"):
        vault.read_secret(f"{kv_mount}/my/secret", "bar")


def test_read_secret_missing_key_default(vault, kv_mount):
    res = vault.read_secret(f"{kv_mount}/my/secret", "bar", default="__missing__")
    assert res == "__missing__"


def test_read_secret_with_metadata(vault):
    res = vault.read_secret("secret/my/secret", metadata=True)
    assert res
    assert "data" in res
    assert "metadata" in res
    expected_read = {"password": "bar", "user": "foo"}
    assert res["data"] == expected_read


def test_write_secret(vault, kv_mount):
    data = {"user": "foo", "password": "bar"}
    res = vault.write_secret(f"{kv_mount}/write/secret", **data)
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    assert vault_read_secret(f"{kv_mount}/write/secret") == data


def test_write_raw(vault, kv_mount):
    data = {"user": "foo", "password": "bar"}
    res = vault.write_secret(f"{kv_mount}/write_raw_secret", **data)
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    assert vault_read_secret(f"{kv_mount}/write_raw_secret") == data


@pytest.mark.parametrize("keys_only", (None, False, True))
def test_list_secrets(vault, keys_only, kv_mount):
    ret = vault.list_secrets(f"{kv_mount}/my/", keys_only=keys_only)
    assert ret
    if keys_only:
        keys = ret
    else:
        assert "keys" in ret
        keys = ret["keys"]
    assert keys == ["secret"]


def test_delete_secret(vault, kv_mount):
    path = f"{kv_mount}/delete/me"
    assert vault_read_secret(path) is not None
    assert vault.delete_secret(path) is True
    assert vault_read_secret(path) is None
    if "v1" not in kv_mount:
        metadata = vault_read_secret_metadata(path)
        curr_vers = metadata["versions"][str(metadata["current_version"])]
        assert curr_vers["deletion_time"]
        assert not curr_vers["destroyed"]


def test_patch_secret(vault, kv_mount):
    res = vault.write_secret(f"{kv_mount}/patched_secret", foo="bar")
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    res = vault.patch_secret(f"{kv_mount}/patched_secret", bar="baz")
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 2
    assert vault_read_secret(f"{kv_mount}/patched_secret") == {"foo": "bar", "bar": "baz"}


def test_patch_raw(vault, kv_mount):
    res = vault.write_raw(f"{kv_mount}/patched_raw_secret", {"foo": "bar"})
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    res = vault.patch_raw(f"{kv_mount}/patched_raw_secret", {"bar": "baz"})
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 2
    assert vault_read_secret(f"{kv_mount}/patched_raw_secret") == {"foo": "bar", "bar": "baz"}


@pytest.mark.parametrize("key", (None, "password"))
def test_read_secret_version(vault, versioned_secret, key):
    ret = vault.read_secret(versioned_secret, key, version=1)
    if not key:
        ret = ret["password"]
    assert ret == "bar"
    ret = vault.read_secret(versioned_secret, key, version=2)
    if not key:
        ret = ret["password"]
    assert ret == "hunter1"


def test_read_secret_version_missing(vault, versioned_secret):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*VaultNotFound.*"):
        vault.read_secret(versioned_secret, version=3)


def test_read_secret_version_missing_default(vault, versioned_secret):
    res = vault.read_secret(versioned_secret, version=3, default="__missing__")
    assert res == "__missing__"


def test_read_secret_meta(vault, versioned_secret):
    ret = vault.read_secret_meta(versioned_secret)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


def test_read_secret_meta_deleted(vault, versioned_secret_deleted):
    ret = vault.read_secret_meta(versioned_secret_deleted)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


def test_read_secret_meta_destroyed(vault, versioned_secret_destroyed):
    ret = vault.read_secret_meta(versioned_secret_destroyed)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert curr_vers["destroyed"]


def test_restore_secret(vault, versioned_secret_deleted):
    ret = vault.restore_secret(versioned_secret_deleted)
    assert ret is True
    curr = vault_read_secret(versioned_secret_deleted)
    assert curr["password"] == "hunter1"


def test_restore_secret_version(vault, versioned_secret_deleted):
    ret = vault.restore_secret(versioned_secret_deleted, 1)
    assert ret is True
    curr = vault_read_secret(versioned_secret_deleted, version=1)
    assert curr["password"] == "bar"
    curr = vault_read_secret(versioned_secret_deleted, version=2)
    assert curr is None


def test_restore_secret_all_versions(vault, versioned_secret_all_deleted):
    ret = vault.restore_secret(versioned_secret_all_deleted, all_versions=True)
    assert ret is True
    curr = vault_read_secret(versioned_secret_all_deleted, version=1)
    assert curr["password"] == "bar"
    curr = vault_read_secret(versioned_secret_all_deleted, version=2)
    assert curr["password"] == "hunter1"


def test_restore_secret_latest_not_deleted(vault, versioned_secret):
    vault_delete_secret(versioned_secret, versions=1)
    with pytest.raises(CommandExecutionError, match="No secret version to restore."):
        vault.restore_secret(versioned_secret)


def test_delete_secret_latest(vault, versioned_secret):
    res = vault.delete_secret(versioned_secret)
    assert res is True
    ret = vault_read_secret(versioned_secret, version=1)
    assert ret["password"] == "bar"
    ret = vault_read_secret(versioned_secret, version=2)
    assert ret is None


def test_delete_secret_version(vault, versioned_secret):
    res = vault.delete_secret(versioned_secret, 1)
    assert res is True
    ret = vault.read_secret(versioned_secret, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault.read_secret(versioned_secret)
    assert ret["password"] == "hunter1"
    res = vault.delete_secret(versioned_secret, "2")
    assert res is True
    ret = vault.read_secret(versioned_secret, default="__deleted__")
    assert ret == "__deleted__"


def test_delete_secret_all_versions(vault, versioned_secret):
    res = vault.delete_secret(versioned_secret, all_versions=True)
    assert res is True
    ret = vault.read_secret(versioned_secret, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault.read_secret(versioned_secret, default="__deleted__")
    assert ret == "__deleted__"


def test_delete_secret_all_versions_latest_deleted_already(vault, versioned_secret_deleted):
    res = vault.delete_secret(versioned_secret_deleted, all_versions=True)
    assert res is True
    ret = vault.read_secret(versioned_secret_deleted, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault.read_secret(versioned_secret_deleted, default="__deleted__")
    assert ret == "__deleted__"


def test_destroy_secret_latest(vault, versioned_secret):
    assert vault.destroy_secret(versioned_secret) is True
    ret = vault_read_secret(versioned_secret)
    assert ret is None
    ret = vault_read_secret(versioned_secret, version=1)
    assert ret["password"] == "bar"


def test_destroy_secret_versions(vault, versioned_secret):
    assert vault.destroy_secret(versioned_secret, "1") is True
    ret = vault.read_secret(versioned_secret)
    assert ret["password"] == "hunter1"
    assert vault.destroy_secret(versioned_secret, 2) is True
    ret = vault.read_secret(versioned_secret, default="__destroyed__")
    assert ret == "__destroyed__"


def test_destroy_secret_all_versions(vault, versioned_secret):
    assert vault.destroy_secret(versioned_secret, all_versions=True) is True
    for version in range(2):
        ret = vault.read_secret(versioned_secret, default="__destroyed__", version=version + 1)
        assert ret == "__destroyed__"


def test_wipe_secret(vault, versioned_secret):
    assert vault.wipe_secret(versioned_secret) is True
    assert vault.read_secret_meta(versioned_secret) is False
