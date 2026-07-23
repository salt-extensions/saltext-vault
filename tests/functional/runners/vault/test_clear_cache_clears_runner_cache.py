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
