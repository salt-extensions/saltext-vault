"""
Shared fixtures for the vault_approle test suites.
"""

import pytest
from saltfactories.utils import random_string

from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_list
from tests.support.vault import vault_write


@pytest.fixture(scope="module", autouse=True)
def approle_auth(container):  # pylint: disable=unused-argument
    name = random_string("approle-test", uppercase=False)
    assert vault_enable_auth_method("approle", name)
    try:
        yield name
    finally:
        assert vault_disable_auth_method(name)


@pytest.fixture(params=[["testrole"]])
def roles_setup(approle_auth, request):  # pylint: disable=unused-argument
    try:
        for role_name in request.param:
            role_args = request.getfixturevalue(role_name)
            vault_write(f"auth/{approle_auth}/role/{role_name}", **role_args)
            assert role_name in vault_list(f"auth/{approle_auth}/role")
        yield
    finally:
        for role_name in request.param:
            if role_name in vault_list(f"auth/{approle_auth}/role"):
                vault_delete(f"auth/{approle_auth}/role/{role_name}")
                assert role_name not in vault_list(f"auth/{approle_auth}/role")
