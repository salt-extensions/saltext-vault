import pytest

from saltext.vault.utils import vault
from tests.support.vault import vault_delete

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts"),
]


@pytest.fixture
def kv(minion_opts):
    return vault.get_kv(minion_opts, {})


@pytest.fixture
def secret_path(kv):  # pylint: disable=unused-argument
    path = "secret/foo"
    try:
        yield path
    finally:
        vault_delete("secret/metadata/foo")


def test_kv_delete_all_versions(kv, secret_path):
    """
    Ensure that delete with all_versions soft-deletes all versions
    and succeeds early when there is no version left to delete
    """
    kv.write(secret_path, {"foo": "bar"})
    kv.write(secret_path, {"foo": "baz"})
    kv.delete(secret_path, all_versions=True)
    with pytest.raises(vault.VaultNotFoundError):
        kv.read(secret_path)
    versions = kv.read_meta(secret_path)["versions"]
    assert len(versions) == 2
    assert all(meta["deletion_time"] for meta in versions.values())
    # All versions have been soft-deleted already, nothing left to do.
    assert kv.delete(secret_path, all_versions=True) is True


def test_kv_delete_all_versions_missing_secret(kv, secret_path):
    """
    Ensure that delete with all_versions does not fail when the secret
    does not exist since the delete API endpoint behaves the same
    """
    with pytest.raises(vault.VaultNotFoundError):
        kv.read_meta(secret_path)
    assert kv.delete(secret_path, all_versions=True) is True


def test_kv_restore_all_versions_only_restores_soft_deleted(kv, secret_path):
    """
    Ensure that restore with all_versions only considers versions that
    can actually be restored, skipping destroyed and active ones
    """
    for val in ("one", "two", "three"):
        kv.write(secret_path, {"foo": val})
    kv.destroy(secret_path, 1)
    kv.delete(secret_path, versions=2)
    kv.restore(secret_path, all_versions=True)
    versions = kv.read_meta(secret_path)["versions"]
    assert versions["1"]["destroyed"] is True
    assert not versions["2"]["deletion_time"]
    assert not versions["3"]["deletion_time"]
    assert kv.read(secret_path, version=2) == {"foo": "two"}


def test_kv_destroy_missing_secret(kv, secret_path):
    """
    Ensure that destroy does not fail when the secret does not exist
    since the destroy API endpoint behaves the same
    """
    with pytest.raises(vault.VaultNotFoundError):
        kv.read_meta(secret_path)
    assert kv.destroy(secret_path) is True


def test_kv_destroy_all_versions_skips_destroyed(kv, secret_path):
    """
    Ensure that destroy with all_versions only considers versions that
    have not been destroyed before and succeeds early when there is
    no version left to destroy
    """
    for val in ("one", "two", "three"):
        kv.write(secret_path, {"foo": val})
    kv.destroy(secret_path, 1)
    versions = kv.read_meta(secret_path)["versions"]
    assert versions["1"]["destroyed"] is True
    assert not any(meta["destroyed"] for version, meta in versions.items() if version != "1")
    kv.destroy(secret_path, all_versions=True)
    versions = kv.read_meta(secret_path)["versions"]
    assert all(meta["destroyed"] for meta in versions.values())
    # All versions have been destroyed already, nothing left to do.
    assert kv.destroy(secret_path, all_versions=True) is True


def test_kv_destroy_defaults_to_most_recent(kv, secret_path):
    """
    Ensure that destroy without version specifications destroys the
    most recent version only and succeeds early when it has been
    destroyed before
    """
    kv.write(secret_path, {"foo": "one"})
    kv.write(secret_path, {"foo": "two"})
    kv.destroy(secret_path)
    versions = kv.read_meta(secret_path)["versions"]
    assert not versions["1"]["destroyed"]
    assert versions["2"]["destroyed"] is True
    # The most recent version has been destroyed already, nothing left to do.
    assert kv.destroy(secret_path) is True
    assert not kv.read_meta(secret_path)["versions"]["1"]["destroyed"]


def test_kv_write_cas(kv, secret_path):
    """
    Ensure that writes with a CAS parameter only succeed when the
    secret version has not changed since it was read
    """
    kv.write(secret_path, {"foo": "bar"})
    current = kv.read(secret_path, include_metadata=True)
    assert current["metadata"]["version"] == 1

    # The version still matches the read one, this should work.
    kv.write(secret_path, {"foo": "baz"}, cas=1)
    assert kv.read(secret_path) == {"foo": "baz"}

    # The write above bumped the version, so the read one is stale now.
    with pytest.raises(vault.VaultInvocationError, match="check-and-set parameter"):
        kv.write(secret_path, {"foo": "stale"}, cas=1)
    assert kv.read(secret_path) == {"foo": "baz"}
