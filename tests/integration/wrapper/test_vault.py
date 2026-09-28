import pytest

from tests.common import CliFuncProxy
from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault import kv_mount
from tests.functional.modules.vault.test_vault_kv import test_read_secret

# pylint: enable=unused-import

pytestmark = genmarks(
    internal_logic=True,
    mounts=True,
    policies=True,
    secrets=True,
    kv_mount="secret",
)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk")


@pytest.fixture(scope="module")
def vault(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/my/secret": {"user": "foo", "password": "bar"},
        "secret/delete/me": {"user": "foo"},
    }


def test_clear_cache(salt_ssh_cli):
    """
    Ensure that the revocation client also respects Salt-SSH master opts
    and does not crash with InvalidConfig.
    """
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    token_id = ret.data["data"]["id"]
    ret = salt_ssh_cli.run("vault.clear_cache")
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data["data"]["id"] != token_id
