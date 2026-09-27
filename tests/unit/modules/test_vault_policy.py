from unittest.mock import ANY

import pytest
import salt.exceptions

import saltext.vault.utils.vault as vaultutil
from saltext.vault.modules import vault_policy

# pylint: disable=unused-import
from tests.unit.fixtures.vault import api_delete
from tests.unit.fixtures.vault import api_get
from tests.unit.fixtures.vault import api_put

# pylint: enable=unused-import


@pytest.fixture
def configure_loader_modules():
    return {
        vault_policy: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def policy_response():
    return {
        "name": "test-policy",
        "rules": 'path "secret/*"\\n{\\n  capabilities = ["read"]\\n}',
    }


@pytest.fixture
def policies_list_response():
    return {
        "policies": ["default", "root", "test-policy"],
    }


def test_policy_fetch(api_get, policy_response):
    """
    Ensure policy_fetch returns rules only and calls the API as expected
    """
    api_get.return_value = policy_response
    res = vault_policy.fetch("test-policy")
    assert res == policy_response["rules"]
    api_get.assert_called_once_with("sys/policy/test-policy", opts=ANY, context=ANY)


def test_policy_fetch_not_found(api_get):
    """
    Ensure policy_fetch returns None when the policy was not found
    """
    api_get.side_effect = vaultutil.VaultNotFoundError
    res = vault_policy.fetch("test-policy")
    assert res is None


@pytest.mark.parametrize(
    "func,args",
    [
        pytest.param("fetch", [], id="fetch"),
        pytest.param("write", ["rule"], id="write"),
        pytest.param("delete", [], id="delete"),
        pytest.param("list_", None, id="list"),
    ],
)
def test_policy_functions_raise_errors(api_get, api_put, api_delete, func, args):
    """
    Ensure policy functions raise CommandExecutionErrors
    """
    api_get.side_effect = api_put.side_effect = api_delete.side_effect = (
        vaultutil.VaultPermissionDeniedError
    )
    func = getattr(vault_policy, func)
    with pytest.raises(
        salt.exceptions.CommandExecutionError, match=".*VaultPermissionDeniedError.*"
    ):
        if args is None:
            func()
        else:
            func("test-policy", *args)


def test_policy_write(api_put, policy_response):
    """
    Ensure policy_write calls the API as expected
    """
    api_put.return_value = True
    res = vault_policy.write("test-policy", policy_response["rules"])
    assert res
    api_put.assert_called_once_with(
        "sys/policy/test-policy",
        opts=ANY,
        context=ANY,
        payload={"policy": policy_response["rules"]},
    )


def test_policy_delete(api_delete):
    """
    Ensure policy_delete calls the API as expected
    """
    api_delete.return_value = True
    res = vault_policy.delete("test-policy")
    assert res
    api_delete.assert_called_once_with("sys/policy/test-policy", opts=ANY, context=ANY)


def test_policy_delete_handles_not_found(api_delete):
    """
    Ensure policy_delete returns False instead of raising CommandExecutionError
    when a policy was absent already.
    """
    api_delete.side_effect = vaultutil.VaultNotFoundError
    res = vault_policy.delete("test-policy")
    assert not res


def test_policies_list(api_get, policies_list_response):
    """
    Ensure policies_list returns policy list only and calls the API as expected
    """
    api_get.return_value = policies_list_response
    res = vault_policy.list_()
    assert res == policies_list_response["policies"]
    api_get.assert_called_once_with("sys/policy", opts=ANY, context=ANY)


@pytest.mark.parametrize(
    "func,kwargs",
    [
        pytest.param("fetch", {"policy": "test-policy"}, id="fetch"),
        pytest.param("write", {"policy": "test-policy", "rules": "rule"}, id="write"),
        pytest.param("delete", {"policy": "test-policy"}, id="delete"),
        pytest.param("list_", {}, id="list"),
    ],
)
def test_func_converts_errors(func, kwargs, api_get, api_put, api_delete):
    """
    Ensure remote errors are converted into CommandExecutionErrors
    """
    api_get.side_effect = api_put.side_effect = api_delete.side_effect = vaultutil.VaultException(
        "booh"
    )
    with pytest.raises(salt.exceptions.CommandExecutionError, match="booh"):
        getattr(vault_policy, func)(**kwargs)
