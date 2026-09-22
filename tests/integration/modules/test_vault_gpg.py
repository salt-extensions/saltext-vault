import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_gpg import cached_vault_gpg_bin
from tests.common.fixtures.vault_gpg import existing_key
from tests.common.fixtures.vault_gpg import gpg_mount
from tests.common.fixtures.vault_gpg import gpg_plugin

# pylint: enable=unused-import

pytestmark = genmarks(internal_logic_only=True, policies=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    # this fails to sign on the general API and should use the algo-specific ones
    return gen_master_opts(policies="gpg_sign_fallback")


def test_sign_fallback(salt_call_cli, gpg_mount, existing_key):
    salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    res = salt_call_cli.run(
        "vault_gpg.sign", existing_key, "Boop", encoding="ascii-armor", mount=gpg_mount
    )
    assert res.returncode == 0
    assert res.data
    assert isinstance(res.data, str)
    assert res.data.startswith("-----BEGIN PGP SIGNATURE")
