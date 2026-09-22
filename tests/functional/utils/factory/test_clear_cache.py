import pytest

from saltext.vault.utils.vault.client import AuthenticatedVaultClient
from tests.common import gen_minion_opts
from tests.common.containers import genmarks
from tests.common.fixtures.vault import _event  # pylint: disable=unused-import
from tests.support.vault import vault_write

pytestmark = genmarks(internal_logic_only=True, mounts=True, policies="salt_minion", secrets=True)


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {"secret/foo": {"bar": "hi"}}


@pytest.fixture(scope="module")
def minion_config_overrides(approle):
    return gen_minion_opts(approle=approle, backend="disk", expire_events=True)


@pytest.mark.parametrize("connection,session", ((False, False), (True, False), (False, True)))
def test_clear_cache_revokes_login_token_and_sends_event(modules, _event, connection, session):
    """
    Clearing the Vault cache must revoke the token that is currently cached
    and clear the __context__ cache.
    This exercises the whole ``vault.clear_cache`` -> ``factory.clear_cache``
    -> ``client.token_revoke`` chain.

    Note: We don't need to revoke leases, their validity is bound to the token.
    """
    # Any authenticated request triggers an AppRole login and caches the token.
    info = modules.vault.query("GET", "auth/token/lookup-self")["data"]
    accessor = info["accessor"]
    assert info["ttl"] > 120
    # populate connection cache
    assert modules.vault.read_secret("secret/foo", "bar") == "hi"
    # ensure context cache is what we expect
    context = modules.pack["__context__"]
    assert context
    assert "vault/connection" in context
    assert "secret_path_metadata" in context["vault/connection"]
    assert "secret/foo" in context["vault/connection"]["secret_path_metadata"]
    assert "vault/connection/session" in context
    assert "__token" in context["vault/connection/session"]
    assert "_vault_authd_client" in context["vault/connection/session"]
    assert isinstance(
        context["vault/connection/session"]["_vault_authd_client"][0], AuthenticatedVaultClient
    )
    assert set(context["vault/connection/session"]["_vault_authd_client"][1]) == {
        "auth",
        "cache",
        "client",
        "server",
    }

    # now clear the cache
    modules.vault.clear_cache(connection=connection, session=session)

    # ensure the client/config is always removed from context
    assert context.get("vault/connection/session", {}).get("_vault_authd_client") is None
    connection_flushed = connection or not (connection or session)
    assert "vault/session" not in context

    # metadata cache is only removed when connection or root cache is flushed
    assert ("vault/connection" in context) is not connection_flushed
    assert (
        bool(context.get("vault/connection", {}).get("secret_path_metadata"))
        is not connection_flushed
    )

    # ensure the token has been "revoked", i.e. its ttl should be very short (60s by default)
    server = vault_write("auth/token/lookup-accessor", accessor=accessor)["data"]
    assert server["ttl"] <= 60

    # ensure we would have received an expiry event
    if session:
        scope = "session"
    elif connection:
        scope = "connection"
    else:
        scope = "vault"
    _event.return_value.assert_called_once_with(
        data={"scope": scope}, tag=f"vault/cache/{scope}/clear"
    )
