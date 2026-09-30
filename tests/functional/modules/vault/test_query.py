import pytest
from saltfactories.utils import random_string

from tests.common.containers import genmarks
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytestmark = genmarks(mounts=(("ssh", "pki"),))


@pytest.fixture
def ssh_role():
    role = "query-test-role"
    vault_write(f"ssh/roles/{role}", key_type="otp", default_user="foo", cidr_list="10.0.0.0/8")
    return role  # no cleanup necessary, mounts are per-module


@pytest.fixture
def pki_role():
    role = "query-test-role"
    vault_write(f"pki/roles/{role}", allow_any_name=True, ttl="1h", max_ttl="24h")
    return role  # no cleanup necessary, mounts are per-module


def test_query_get(vault, ssh_role):
    res = vault.query("GET", f"ssh/roles/{ssh_role}")
    assert res["data"]["default_user"] == "foo"


def test_query_list(vault, ssh_role):
    res = vault.query("LIST", "ssh/roles")
    assert ssh_role in res["data"]["keys"]


def test_query_post(vault):
    accessor = vault.query("GET", "auth/token/lookup-self")["data"]["accessor"]
    res = vault.query("POST", "auth/token/lookup-accessor", {"accessor": accessor})
    assert "root" in res["data"]["policies"]


def test_query_put(vault):
    role = random_string("query-put-role", uppercase=False)
    res = vault.query(
        "PUT",
        f"ssh/roles/{role}",
        {"key_type": "otp", "default_user": "bar", "cidr_list": "10.0.0.0/8"},
    )
    assert res is True
    assert vault_read(f"ssh/roles/{role}")["data"]["default_user"] == "bar"


def test_query_patch(vault, pki_role):
    res = vault.query("PATCH", f"pki/roles/{pki_role}", {"ttl": "2h"})
    assert res["data"]["ttl"] == 7200
    updated = vault_read(f"pki/roles/{pki_role}")["data"]
    assert updated["ttl"] == 7200
    # JSON merge patch semantics: unrelated attributes are retained
    assert updated["allow_any_name"] is True


def test_query_delete(vault, ssh_role):
    res = vault.query("DELETE", f"ssh/roles/{ssh_role}")
    assert res is True
    assert ssh_role not in vault_list("ssh/roles")
