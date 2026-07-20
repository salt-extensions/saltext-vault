import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.helpers import PatchedEnviron
from tests.support.vault import vault_create_secret_id
from tests.support.vault import vault_delete_approle
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_get_role_id
from tests.support.vault import vault_write_approle

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "osenv": {"driver": "env"},
        "vault": {
            "auth": {
                "token": "sdb://osenv/VAULT_TOKEN",
            },
            "config_location": "local",
        },
    }


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "osenv": {"driver": "env"},
        "vault": {
            "auth": {
                "method": "approle",
                "role_id": "sdb://osenv/VAULT_ROLEID",
                "secret_id": "sdb://osenv/VAULT_SECRETID",
            },
        },
    }


@pytest.fixture(scope="module")
def approle_configured(container):  # pylint: disable=unused-argument
    vault_enable_auth_method("approle", "approle")
    vault_write_approle("sdbrole")
    try:
        role_id = vault_get_role_id("sdbrole")
        secret_id = vault_create_secret_id("sdbrole")
        yield {"role_id": role_id, "secret_id": secret_id}
    finally:
        vault_delete_approle("sdbrole")
        vault_disable_auth_method("approle")


@pytest.fixture(autouse=True)
def auth_in_env(approle_configured):
    with PatchedEnviron(
        VAULT_TOKEN="testsecret",
        VAULT_ROLEID=approle_configured["role_id"],
        VAULT_SECRETID=approle_configured["secret_id"],
    ):
        yield


def test_sdb_in_config_token(salt_call_cli):
    res = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert res.returncode == 0
    assert res.data["data"]["id"] == "testsecret"


def test_sdb_in_config_role_id_secret_id(salt_run_cli):
    res = salt_run_cli.run("vault.auth_info")
    assert res.returncode == 0
    assert res.data["token"]["meta"]["role_name"] == "sdbrole"
