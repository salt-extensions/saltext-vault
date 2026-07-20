import logging

import pytest
from salt.exceptions import CommandExecutionError
from saltfactories.utils import random_string

from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_destroy_secret
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_read_secret_metadata
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("secret_mounts", "vault_secrets"),
    pytest.mark.parametrize(
        "secret_mounts",
        [[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
        indirect=True,
    ),
]

log = logging.getLogger(__name__)


@pytest.fixture
def vault(modules, secret_mounts):  # pylint: disable=unused-argument
    return modules.vault


@pytest.fixture(params=("secret-v1", "secret"))
def secret_mount(request):
    return request.param


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret-v1/my/secret": {"user": "foo", "password": "bar"},
        "secret-v1/delete/me": {"user": "foo"},
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }


def test_read_secret(vault, secret_mount):
    res = vault.read_secret(f"{secret_mount}/my/secret")
    assert res == {"user": "foo", "password": "bar"}


def test_read_secret_key(vault, secret_mount):
    res = vault.read_secret(f"{secret_mount}/my/secret", "user")
    assert res == "foo"


def test_read_secret_missing(vault, secret_mount):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*VaultNotFound.*"):
        vault.read_secret(f"{secret_mount}/missing/secret")


def test_read_secret_missing_default(vault, secret_mount):
    res = vault.read_secret(f"{secret_mount}/missing/secret", default="__missing__")
    assert res == "__missing__"


def test_read_secret_missing_key(vault, secret_mount):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*KeyError.*"):
        vault.read_secret(f"{secret_mount}/my/secret", "bar")


def test_read_secret_missing_key_default(vault, secret_mount):
    res = vault.read_secret(f"{secret_mount}/my/secret", "bar", default="__missing__")
    assert res == "__missing__"


def test_read_secret_with_metadata(vault):
    res = vault.read_secret("secret/my/secret", metadata=True)
    assert res
    assert "data" in res
    assert "metadata" in res
    expected_read = {"password": "bar", "user": "foo"}
    assert res["data"] == expected_read


def test_write_secret(vault, secret_mount):
    data = {"user": "foo", "password": "bar"}
    res = vault.write_secret(f"{secret_mount}/write/secret", **data)
    if "v1" in secret_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    assert vault_read_secret(f"{secret_mount}/write/secret") == data


def test_write_raw(vault, secret_mount):
    data = {"user": "foo", "password": "bar"}
    res = vault.write_secret(f"{secret_mount}/write_raw_secret", **data)
    if "v1" in secret_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    assert vault_read_secret(f"{secret_mount}/write_raw_secret") == data


@pytest.mark.parametrize("keys_only", (None, False, True))
def test_list_secrets(vault, keys_only, secret_mount):
    ret = vault.list_secrets(f"{secret_mount}/my/", keys_only=keys_only)
    assert ret
    if keys_only:
        keys = ret
    else:
        assert "keys" in ret
        keys = ret["keys"]
    assert keys == ["secret"]


def test_delete_secret(vault, secret_mount):
    path = f"{secret_mount}/delete/me"
    assert vault_read_secret(path) is not None
    assert vault.delete_secret(path) is True
    assert vault_read_secret(path) is None
    if "v1" not in secret_mount:
        metadata = vault_read_secret_metadata(path)
        curr_vers = metadata["versions"][str(metadata["current_version"])]
        assert curr_vers["deletion_time"]
        assert not curr_vers["destroyed"]


def test_patch_secret(vault, secret_mount):
    res = vault.write_secret(f"{secret_mount}/patched_secret", foo="bar")
    if "v1" in secret_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 1
    res = vault.patch_secret(f"{secret_mount}/patched_secret", bar="baz")
    if "v1" in secret_mount:
        assert res is True
    else:
        assert res
        assert "created_time" in res
        assert res["destroyed"] is False
        assert res["deletion_time"] == ""
        assert res["version"] == 2
    assert vault_read_secret(f"{secret_mount}/patched_secret") == {"foo": "bar", "bar": "baz"}


@pytest.fixture
def existing_secret(secret_mounts):  # pylint: disable=unused-argument
    secret_key = "secret/versions/" + random_string("test", uppercase=False)
    vault_write_secret(secret_key, user="foo", password="bar")
    return secret_key


@pytest.fixture
def existing_secret_version(existing_secret):
    vault_write_secret(existing_secret, user="foo", password="hunter1")
    return existing_secret


@pytest.fixture
def existing_secret_deleted(existing_secret_version):
    vault_delete_secret(existing_secret_version)
    return existing_secret_version


@pytest.fixture
def existing_secret_destroyed(existing_secret_version):
    vault_destroy_secret(existing_secret_version, 2)
    return existing_secret_version


@pytest.fixture
def existing_secret_all_deleted(existing_secret_version):
    vault_delete_secret(existing_secret_version, versions=[1, 2])
    return existing_secret_version


@pytest.mark.parametrize("key", (None, "password"))
def test_read_secret_version(vault, existing_secret_version, key):
    ret = vault.read_secret(existing_secret_version, key, version=1)
    if not key:
        ret = ret["password"]
    assert ret == "bar"
    ret = vault.read_secret(existing_secret_version, key, version=2)
    if not key:
        ret = ret["password"]
    assert ret == "hunter1"


def test_read_secret_version_missing(vault, existing_secret_version):
    with pytest.raises(CommandExecutionError, match="Failed to read secret.*VaultNotFound.*"):
        vault.read_secret(existing_secret_version, version=3)


def test_read_secret_version_missing_default(vault, existing_secret_version):
    res = vault.read_secret(existing_secret_version, version=3, default="__missing__")
    assert res == "__missing__"


def test_read_secret_meta(vault, existing_secret_version):
    ret = vault.read_secret_meta(existing_secret_version)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


def test_read_secret_meta_deleted(vault, existing_secret_deleted):
    ret = vault.read_secret_meta(existing_secret_deleted)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert curr_vers["deletion_time"]
    assert not curr_vers["destroyed"]


def test_read_secret_meta_destroyed(vault, existing_secret_destroyed):
    ret = vault.read_secret_meta(existing_secret_destroyed)
    assert ret
    assert "cas_required" in ret
    assert "versions" in ret
    assert set(ret["versions"]) == {"1", "2"}
    curr_vers = ret["versions"][str(ret["current_version"])]
    assert not curr_vers["deletion_time"]
    assert curr_vers["destroyed"]


def test_restore_secret(vault, existing_secret_deleted):
    ret = vault.restore_secret(existing_secret_deleted)
    assert ret is True
    curr = vault_read_secret(existing_secret_deleted)
    assert curr["password"] == "hunter1"


def test_restore_secret_version(vault, existing_secret_deleted):
    ret = vault.restore_secret(existing_secret_deleted, 1)
    assert ret is True
    curr = vault_read_secret(existing_secret_deleted, version=1)
    assert curr["password"] == "bar"
    curr = vault_read_secret(existing_secret_deleted, version=2)
    assert curr is None


def test_restore_secret_all_versions(vault, existing_secret_all_deleted):
    ret = vault.restore_secret(existing_secret_all_deleted, all_versions=True)
    assert ret is True
    curr = vault_read_secret(existing_secret_all_deleted, version=1)
    assert curr["password"] == "bar"
    curr = vault_read_secret(existing_secret_all_deleted, version=2)
    assert curr["password"] == "hunter1"


def test_restore_secret_latest_not_deleted(vault, existing_secret_version):
    vault_delete_secret(existing_secret_version, versions=1)
    with pytest.raises(CommandExecutionError, match="No secret version to restore."):
        vault.restore_secret(existing_secret_version)


def test_delete_secret_latest(vault, existing_secret_version):
    res = vault.delete_secret(existing_secret_version)
    assert res is True
    ret = vault_read_secret(existing_secret_version, version=1)
    assert ret["password"] == "bar"
    ret = vault_read_secret(existing_secret_version, version=2)
    assert ret is None


def test_delete_secret_version(vault, existing_secret_version):
    res = vault.delete_secret(existing_secret_version, 1)
    assert res is True
    ret = vault.read_secret(existing_secret_version, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault.read_secret(existing_secret_version)
    assert ret["password"] == "hunter1"
    res = vault.delete_secret(existing_secret_version, "2")
    assert res is True
    ret = vault.read_secret(existing_secret_version, default="__deleted__")
    assert ret == "__deleted__"


def test_delete_secret_all_versions(vault, existing_secret_version):
    res = vault.delete_secret(existing_secret_version, all_versions=True)
    assert res is True
    ret = vault.read_secret(existing_secret_version, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault.read_secret(existing_secret_version, default="__deleted__")
    assert ret == "__deleted__"


def test_delete_secret_all_versions_latest_deleted_already(vault, existing_secret_deleted):
    res = vault.delete_secret(existing_secret_deleted, all_versions=True)
    assert res is True
    ret = vault.read_secret(existing_secret_deleted, default="__deleted__", version=1)
    assert ret == "__deleted__"
    ret = vault.read_secret(existing_secret_deleted, default="__deleted__")
    assert ret == "__deleted__"


def test_destroy_secret_latest(vault, existing_secret_version):
    assert vault.destroy_secret(existing_secret_version) is True
    ret = vault_read_secret(existing_secret_version)
    assert ret is None
    ret = vault_read_secret(existing_secret_version, version=1)
    assert ret["password"] == "bar"


def test_destroy_secret_versions(vault, existing_secret_version):
    assert vault.destroy_secret(existing_secret_version, "1") is True
    ret = vault.read_secret(existing_secret_version)
    assert ret["password"] == "hunter1"
    assert vault.destroy_secret(existing_secret_version, 2) is True
    ret = vault.read_secret(existing_secret_version, default="__destroyed__")
    assert ret == "__destroyed__"


def test_destroy_secret_all_versions(vault, existing_secret_version):
    assert vault.destroy_secret(existing_secret_version, all_versions=True) is True
    for version in range(2):
        ret = vault.read_secret(
            existing_secret_version, default="__destroyed__", version=version + 1
        )
        assert ret == "__destroyed__"


def test_wipe_secret(vault, existing_secret_version):
    assert vault.wipe_secret(existing_secret_version) is True
    assert vault.read_secret_meta(existing_secret_version) is False
