import pytest
import salt.cache


@pytest.fixture(scope="module")
def master_config_overrides():
    # ensure we get the session backend
    return {"vault": {"cache": {"backend": "session"}}}


def test_clear_cache_removes_rendered_policies_with_session_backend(runners, master_opts):
    """
    Rendered minion policies are always cached on the master via the regular
    Salt cache (default: localfs), independently of the Vault ``cache:backend``
    setting. ``vault.clear_cache`` must therefore remove them even when the
    Vault cache backend is ``session`` (the default).
    """
    minion_id = "test-clear-cache-minion"
    cbank = f"minions/{minion_id}/vault"
    cache = salt.cache.factory(master_opts)
    cache.flush(cbank, "policies")

    # Populate the rendered-policies cache.
    policies = runners.vault.show_policies(minion_id)
    assert policies == ["salt_minion"]
    assert cache.contains(cbank, "policies")

    assert runners.vault.clear_cache() is True
    assert not cache.contains(cbank, "policies")


def test_clear_cache_with_minion_list(runners, master_opts):
    """
    When ``minions`` is passed a list of minion IDs, only cached data
    pertaining to these minions must be cleared, other minions' data
    must be kept.
    """
    minion_ids = ("test-clear-cache-listed-minion", "test-clear-cache-unlisted-minion")
    cache = salt.cache.factory(master_opts)
    for minion_id in minion_ids:
        cache.flush(f"minions/{minion_id}/vault", "policies")
        # Populate the rendered-policies cache.
        policies = runners.vault.show_policies(minion_id)
        assert policies == ["salt_minion"]
        assert cache.contains(f"minions/{minion_id}/vault", "policies")

    assert runners.vault.clear_cache(minions=[minion_ids[0]]) is True
    assert not cache.contains(f"minions/{minion_ids[0]}/vault", "policies")
    assert cache.contains(f"minions/{minion_ids[1]}/vault", "policies")


def test_clear_cache_master_only_keeps_minion_caches(runners, master_opts):
    """
    When ``minions=False`` is passed, cached data pertaining to minions,
    e.g. rendered policies, must be kept.
    """
    minion_id = "test-clear-cache-master-only-minion"
    cbank = f"minions/{minion_id}/vault"
    cache = salt.cache.factory(master_opts)
    cache.flush(cbank, "policies")

    # Populate the rendered-policies cache.
    policies = runners.vault.show_policies(minion_id)
    assert policies == ["salt_minion"]
    assert cache.contains(cbank, "policies")

    assert runners.vault.clear_cache(minions=False) is True
    assert cache.contains(cbank, "policies")
