from textwrap import dedent

import pytest

from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_list_policies
from tests.support.vault import vault_write_policy


@pytest.fixture
def clean_policies():
    try:
        yield
    finally:
        # We're explicitly using the vault CLI and not the salt vault module
        test_policies = [policy for policy in vault_list_policies() if policy.startswith("test_")]
        for policy in test_policies:
            vault_delete_policy(policy)


@pytest.fixture
def temp_policy_rules():
    return dedent("""
        path "secret/some/thing" {
            capabilities = ["read"]
        }
        """).strip()


@pytest.fixture
def temp_policy(temp_policy_rules, container):  # pylint: disable=unused-argument
    name = "test_functional_policy"
    vault_write_policy(name, temp_policy_rules)
    try:
        yield name
    finally:
        vault_delete_policy(name)
