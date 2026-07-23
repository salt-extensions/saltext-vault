import copy
from pathlib import Path
from unittest.mock import patch

import pytest
import salt.cache
import salt.crypt

from saltext.vault.utils.vault import factory as vfactory
from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "master_approle_mount", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # Backend is the same, regardless of Vault vs OpenBao
    pytest.mark.parametrize("vault_policies", (("salt_master", "salt_minion"),), indirect=True),
    # For tokens, the master needs to hold the minion policies itself to be able
    # to issue child tokens with them (unless we configure a token_role).
    pytest.mark.parametrize(
        "approle", ({"token_policies": ["salt_master", "salt_minion"]},), indirect=True
    ),
]


@pytest.fixture(scope="module", params=("token", "approle"))
def master_config_overrides(
    approle, master_approle_mount, request
):  # pylint: disable=unused-argument
    """
    Authenticate the master via AppRole, otherwise its (statically configured)
    token is exempt from revocation during cache clearance.
    """
    return {
        "vault": {
            "auth": {
                "method": "approle",
                "approle_mount": approle["mount"],
                "approle_name": "test-role",
                "role_id": approle["role_id"],
                "secret_id": approle["secret_id"],
            },
            "cache": {
                "backend": "disk",
                "expire_events": True,
            },
            "issue": {
                "type": request.param,
                "approle": {
                    "params": {
                        "token_explicit_max_ttl": "1h",
                    }
                },
                "token": {
                    "params": {
                        "explicit_max_ttl": "1h",
                    }
                },
            },
            "policies": {
                "assign": ["salt_minion"],
            },
        },
    }


@pytest.fixture(scope="module")
def master_runtime(master_opts):
    """
    The impersonation flow signs peer requests with the master key and
    executes the runner in-process, which requires some directories
    that are usually initialized during master startup.
    """
    Path(master_opts["pki_dir"]).mkdir(parents=True, exist_ok=True)
    (Path(master_opts["cachedir"]) / "proc").mkdir(parents=True, exist_ok=True)
    salt.crypt.MasterKeys(master_opts)


@pytest.fixture
def _event():
    with patch("saltext.vault.utils.vault.factory._get_event", autospec=True) as evt:
        yield evt


@pytest.fixture
def imp_minion_id():
    return "clear-cache-impersonated"


@pytest.fixture
def imp_client(
    master_opts, master_runtime, master_loaders, imp_minion_id
):  # pylint: disable=unused-argument
    """
    Build an authenticated client for an impersonated minion the same way
    pillar compilation does, including the in-process peer runner call.
    This caches the issued minion token in the master's context and cache.
    """
    imp_opts = copy.deepcopy(master_opts)
    imp_opts["minion_id"] = imp_minion_id
    imp_opts["grains"] = {"id": imp_minion_id}
    return vfactory.get_authd_client(imp_opts, master_loaders.context)


def test_clear_cache_revokes_all_tokens_and_clears_context(
    runners, master_loaders, master_opts, imp_client, imp_minion_id, _event, master
):
    """
    ``vault.clear_cache`` (runner) must revoke the master's own login token as
    well as the tokens cached for impersonated minions, remove the associated
    data from ``__context__`` and the persistent cache, and it must not send
    cache expiration events for the impersonated minion caches.
    """
    context = master_loaders.context

    # Authenticate the master client, which caches its login token.
    master_token = runners.vault.auth_info()["token"]
    assert master_token["ttl"] > 120

    imp_token = str(imp_client.auth.get_token())
    assert vault_write("auth/token/lookup", token=imp_token)["data"]["ttl"] > 120

    # Ensure the context cache is what we expect.
    imp_cbank = f"minions/{imp_minion_id}/vault/connection"
    assert "vault/connection/session" in context
    # Note: The master's token itself might only be present in the persistent
    # cache since it was cached by the in-process peer runner call.
    # The context cache is only populated during writes. TODO: Reconsider context cache implementation.
    assert "_vault_authd_client" in context["vault/connection/session"]
    assert imp_cbank in context
    assert "config" in context[imp_cbank]
    assert f"{imp_cbank}/session" in context
    assert "__token" in context[f"{imp_cbank}/session"]
    assert "_vault_authd_client" in context[f"{imp_cbank}/session"]

    # Ensure the persistent cache is what we expect.
    cache = salt.cache.factory(master_opts)
    assert cache.contains("vault/connection/session", "__token")
    assert cache.contains(imp_cbank, "config")
    assert cache.contains(f"{imp_cbank}/session", "__token")

    # Rendered policies were cached during minion token issuance (runner cache).
    # They are not cached when issuing approles though.
    if master.config["vault"]["issue"]["type"] == "token":
        assert cache.contains(f"minions/{imp_minion_id}/vault", "policies")

    # Now clear the cache.
    assert runners.vault.clear_cache() is True

    # Both tokens should have been revoked, i.e. their TTL should have
    # been reduced to at most 60s (default clear_attempt_revocation).
    server = vault_write("auth/token/lookup", token=master_token["id"])["data"]
    assert server["ttl"] <= 60
    server = vault_write("auth/token/lookup", token=imp_token)["data"]
    assert server["ttl"] <= 60

    # The context cache should have been cleared.
    assert "vault/connection/session" not in context
    assert not any(bank.startswith(f"minions/{imp_minion_id}/vault") for bank in context)

    # The persistent cache should have been cleared, including the runner cache.
    assert not cache.contains("vault/connection/session", "__token")
    assert not cache.contains(imp_cbank, "config")
    assert not cache.contains(f"{imp_cbank}/session", "__token")
    assert not cache.contains(f"minions/{imp_minion_id}/vault", "policies")

    # No cache expiration events should have been sent, especially not
    # for the impersonated minion caches (the minions don't lose their
    # own caches when the master clears its impersonated ones).
    _event.return_value.assert_not_called()
