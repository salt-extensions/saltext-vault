import logging
from textwrap import dedent

import pytest

from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_list_policies
from tests.support.vault import vault_read_policy
from tests.support.vault import vault_write_policy

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
]

log = logging.getLogger(__name__)


@pytest.fixture
def vault(modules, container):  # pylint: disable=unused-argument
    try:
        yield modules.vault
    finally:
        # We're explicitly using the vault CLI and not the salt vault module
        policies = vault_list_policies()
        for policy in ("functional_test_policy", "policy_write_test"):
            if policy in policies:
                vault_delete_policy(policy)


@pytest.fixture
def policy_rules():
    return dedent("""
        path "secret/some/thing" {
            capabilities = ["read"]
        }
        """).strip()


@pytest.fixture
def existing_policy(policy_rules, container):  # pylint: disable=unused-argument
    name = "functional_test_policy"
    vault_write_policy(name, policy_rules)
    try:
        yield name
    finally:
        vault_delete_policy(name)


def test_policy_fetch(vault, policy_rules, existing_policy):
    ret = vault.policy_fetch(existing_policy)
    assert ret == policy_rules


def test_policy_fetch_missing(vault):
    ret = vault.policy_fetch("__does_not_exist__")
    assert ret is None


def test_policy_write(vault, policy_rules):
    ret = vault.policy_write("policy_write_test", policy_rules)
    assert ret is True
    assert vault_read_policy("policy_write_test") == policy_rules


def test_policy_delete(vault, existing_policy):
    ret = vault.policy_delete(existing_policy)
    assert ret is True
    assert "functional_test_policy" not in vault_list_policies()


def test_policies_list(vault, existing_policy):
    ret = vault.policies_list()
    assert existing_policy in ret
