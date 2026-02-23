import os

import pytest

from tests.support.vault import vault_create_secret_id
from tests.support.vault import vault_delete_approle
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_get_role_id
from tests.support.vault import vault_write_approle

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
]


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "osenv": {"driver": "env"},
        "vault": {
            "auth": {
                "method": "token",
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
            "config_location": "local",
        },
    }


@pytest.fixture(scope="module")
def approle_configured():
    vault_enable_auth_method("approle", ["-path=approle"])
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
    prev, os.environ["VAULT_TOKEN"], os.environ["VAULT_ROLEID"], os.environ["VAULT_SECRETID"] = (
        os.environ.get("VAULT_TOKEN"),
        "testsecret",
        approle_configured["role_id"],
        approle_configured["secret_id"],
    )
    try:
        yield
    finally:
        if prev is not None:
            os.environ["VAULT_TOKEN"] = prev
        else:
            os.environ.pop("VAULT_TOKEN")
        os.environ.pop("VAULT_ROLEID")
        os.environ.pop("VAULT_SECRETID")


def test_sdb_in_config_token(salt_call_cli):
    res = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert res.returncode == 0
    assert res.data["data"]["id"] == "testsecret"


def test_sdb_in_config_role_id_secret_id(salt_run_cli):
    res = salt_run_cli.run("vault.auth_info")
    assert res.returncode == 0
    assert res.data["token"]["meta"]["role_name"] == "sdbrole"
