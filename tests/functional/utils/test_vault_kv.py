import pytest

from saltext.vault.utils import vault
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import temp_kvv2_path
from tests.common.fixtures.vault import versionable_secret
from tests.common.fixtures.vault import versioned_secret

# pylint: enable=unused-import

pytestmark = genmarks(mounts=True)


@pytest.fixture
def kv(minion_opts):
    return vault.get_kv(minion_opts, {})


def test_kv_delete_all_versions(kv, versioned_secret):
    """
    Ensure that delete with all_versions soft-deletes all versions
    and succeeds early when there is no version left to delete
    """
    kv.delete(versioned_secret, all_versions=True)
    with pytest.raises(vault.VaultNotFoundError):
        kv.read(versioned_secret)
    versions = kv.read_meta(versioned_secret)["versions"]
    assert len(versions) == 2
    assert all(meta["deletion_time"] for meta in versions.values())
    # All versions have been soft-deleted already, nothing left to do.
    assert kv.delete(versioned_secret, all_versions=True) is True


def test_kv_delete_all_versions_missing_secret(kv, temp_kvv2_path):
    """
    Ensure that delete with all_versions does not fail when the secret
    does not exist since the delete API endpoint behaves the same
    """
    with pytest.raises(vault.VaultNotFoundError):
        kv.read_meta(temp_kvv2_path)
    assert kv.delete(temp_kvv2_path, all_versions=True) is True


def test_kv_restore_all_versions_only_restores_soft_deleted(kv, temp_kvv2_path):
    """
    Ensure that restore with all_versions only considers versions that
    can actually be restored, skipping destroyed and active ones
    """
    for val in ("one", "two", "three"):
        kv.write(temp_kvv2_path, {"foo": val})
    kv.destroy(temp_kvv2_path, 1)
    kv.delete(temp_kvv2_path, versions=2)
    kv.restore(temp_kvv2_path, all_versions=True)
    versions = kv.read_meta(temp_kvv2_path)["versions"]
    assert versions["1"]["destroyed"] is True
    assert not versions["2"]["deletion_time"]
    assert not versions["3"]["deletion_time"]
    assert kv.read(temp_kvv2_path, version=2) == {"foo": "two"}


def test_kv_destroy_missing_secret(kv, temp_kvv2_path):
    """
    Ensure that destroy does not fail when the secret does not exist
    since the destroy API endpoint behaves the same
    """
    with pytest.raises(vault.VaultNotFoundError):
        kv.read_meta(temp_kvv2_path)
    assert kv.destroy(temp_kvv2_path) is True


def test_kv_destroy_all_versions_skips_destroyed(kv, temp_kvv2_path):
    """
    Ensure that destroy with all_versions only considers versions that
    have not been destroyed before and succeeds early when there is
    no version left to destroy
    """
    for val in ("one", "two", "three"):
        kv.write(temp_kvv2_path, {"foo": val})
    kv.destroy(temp_kvv2_path, 1)
    versions = kv.read_meta(temp_kvv2_path)["versions"]
    assert versions["1"]["destroyed"] is True
    assert not any(meta["destroyed"] for version, meta in versions.items() if version != "1")
    kv.destroy(temp_kvv2_path, all_versions=True)
    versions = kv.read_meta(temp_kvv2_path)["versions"]
    assert all(meta["destroyed"] for meta in versions.values())
    # All versions have been destroyed already, nothing left to do.
    assert kv.destroy(temp_kvv2_path, all_versions=True) is True


def test_kv_destroy_defaults_to_most_recent(kv, versioned_secret):
    """
    Ensure that destroy without version specifications destroys the
    most recent version only and succeeds early when it has been
    destroyed before
    """
    kv.destroy(versioned_secret)
    versions = kv.read_meta(versioned_secret)["versions"]
    assert not versions["1"]["destroyed"]
    assert versions["2"]["destroyed"] is True
    # The most recent version has been destroyed already, nothing left to do.
    assert kv.destroy(versioned_secret) is True
    assert not kv.read_meta(versioned_secret)["versions"]["1"]["destroyed"]


def test_kv_write_cas(kv, temp_kvv2_path):
    """
    Ensure that writes with a CAS parameter only succeed when the
    secret version has not changed since it was read
    """
    kv.write(temp_kvv2_path, {"foo": "bar"})
    current = kv.read(temp_kvv2_path, include_metadata=True)
    assert current["metadata"]["version"] == 1

    # The version still matches the read one, this should work.
    kv.write(temp_kvv2_path, {"foo": "baz"}, cas=1)
    assert kv.read(temp_kvv2_path) == {"foo": "baz"}

    # The write above bumped the version, so the read one is stale now.
    with pytest.raises(vault.VaultInvocationError, match="check-and-set parameter"):
        kv.write(temp_kvv2_path, {"foo": "stale"}, cas=1)
    assert kv.read(temp_kvv2_path) == {"foo": "baz"}
