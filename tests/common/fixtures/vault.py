"""
Shared fixtures for the core vault test suites.
"""

from textwrap import dedent
from unittest.mock import patch

import pytest
from saltfactories.utils import random_string

from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_destroy_secret
from tests.support.vault import vault_list_policies
from tests.support.vault import vault_write_policy
from tests.support.vault import vault_write_secret


@pytest.fixture
def _event():
    with patch("saltext.vault.utils.vault.factory._get_event", autospec=True) as evt:
        yield evt


@pytest.fixture(params=("secret", "secret-v1"))
def kv_mount(request):
    return request.param


@pytest.fixture
def clean_kv_mount(kv_mount):
    try:
        yield
    finally:
        vault_delete_secret(kv_mount, metadata=True, recursive=True)


@pytest.fixture
def temp_kv_path(kv_mount):
    """
    Depends on the parametrized ``kv_mount`` fixture.
    Intended for tests that target both KV backend versions.
    """
    return f"{kv_mount}/temp/" + random_string("test", uppercase=False)


@pytest.fixture
def existing_secret(kv_mount, secret_mounts, request):  # pylint: disable=unused-argument
    """
    Depends on the parametrized ``kv_mount`` fixture.
    Represents an existing secret whose data is parametrizable.
    """
    secret_path = f"{kv_mount}/temp/" + random_string("test", uppercase=False)
    data = getattr(request, "param", {"user": "foo", "password": "bar"})
    vault_write_secret(secret_path, **data)
    return secret_path


@pytest.fixture
def temp_kvv2_path():
    """
    Does not use a parametrized fixture, the mount is hardcoded to ``secret``,
    which is a KV v2 mount in this test suite's convention.
    Needed for KV v2-only functionality (versioning).
    """
    return "secret/temp/" + random_string("test", uppercase=False)


@pytest.fixture
def versionable_secret(secret_mounts):  # pylint: disable=unused-argument
    """
    Does not use a parametrized fixture, the mount is hardcoded to ``secret``,
    which is a KV v2 mount in this test suite's convention.
    Represents a secret path that is at version 1.
    """
    secret_path = "secret/temp/" + random_string("test", uppercase=False)
    vault_write_secret(secret_path, user="foo", password="bar")
    return secret_path


@pytest.fixture
def versioned_secret(versionable_secret):
    """
    Represents a secret path that is at version 2.
    """
    vault_write_secret(versionable_secret, user="foo", password="hunter1")
    return versionable_secret


@pytest.fixture
def versioned_secret_deleted(versioned_secret):
    """
    Represents a secret path that is at version 2, but version 2 is deleted.
    """
    vault_delete_secret(versioned_secret)
    return versioned_secret


@pytest.fixture
def versioned_secret_destroyed(versioned_secret):
    """
    Represents a secret path that is at version 2, but version 2 is destroyed.
    """
    vault_destroy_secret(versioned_secret, 2)
    return versioned_secret


@pytest.fixture
def versioned_secret_all_deleted(versioned_secret):
    """
    Represents a secret path that is at version 2, but both versions are deleted.
    """
    vault_delete_secret(versioned_secret, versions=[1, 2])
    return versioned_secret


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
