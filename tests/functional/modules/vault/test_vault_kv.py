import logging

import pytest
from salt.exceptions import CommandExecutionError

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import kv_mount
from tests.common.fixtures.vault import versionable_secret
from tests.common.fixtures.vault import versioned_secret
from tests.common.fixtures.vault import versioned_secret_deleted

# pylint: enable=unused-import
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_read_secret_metadata

pytestmark = genmarks(
    mounts=[[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]], secrets=True
) + [pytest.mark.filterwarnings(r"ignore:The `vault\.:DeprecationWarning")]

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


@pytest.mark.parametrize("raw", (False, True))
def test_write(vault, kv_mount, raw):
    path = f"{kv_mount}/write/{'raw_' if raw else ''}secret"
    data = {"user": "foo", "password": "bar"}
    if raw:
        res = vault.write_raw(path, data)
    else:
        res = vault.write_secret(path, **data)
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    assert vault_read_secret(path) == data


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


@pytest.mark.parametrize("raw", (False, True))
def test_patch(vault, kv_mount, raw):
    path = f"{kv_mount}/patched_{'raw_' if raw else ''}secret"
    if raw:
        res = vault.write_raw(path, {"foo": "bar"})
    else:
        res = vault.write_secret(path, foo="bar")
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    if raw:
        res = vault.patch_raw(path, {"bar": "baz"})
    else:
        res = vault.patch_secret(path, bar="baz")
    if "v1" in kv_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 2
    assert vault_read_secret(path) == {"foo": "bar", "bar": "baz"}


def test_read_secret_meta(vault, versioned_secret):
    ret = vault.read_secret_meta(versioned_secret)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


def test_restore_secret(vault, versioned_secret_deleted):
    ret = vault.restore_secret(versioned_secret_deleted)
    assert ret is True
    curr = vault_read_secret(versioned_secret_deleted)
    assert curr["password"] == "hunter1"


def test_destroy_secret_versions(vault, versioned_secret):
    assert vault.destroy_secret(versioned_secret, "1") is True
    ret = vault.read_secret(versioned_secret)
    assert ret["password"] == "hunter1"
    assert vault.destroy_secret(versioned_secret, 2) is True
    ret = vault.read_secret(versioned_secret, default="__destroyed__")
    assert ret == "__destroyed__"


def test_wipe_secret(vault, versioned_secret):
    assert vault.wipe_secret(versioned_secret) is True
    assert vault.read_secret_meta(versioned_secret) is False
