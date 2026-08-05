from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_approle
from saltext.vault.utils import vault


@pytest.fixture
def configure_loader_modules():
    return {
        vault_approle: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def approle_api():
    with patch("saltext.vault.utils.vault.get_approle_api", autospec=True) as api:
        yield api


@pytest.fixture
def approle_store():
    with patch("saltext.vault.utils.vault.approle.get_store", autospec=True) as store:
        yield store


@pytest.mark.parametrize(
    "func,method,kwargs",
    (
        ("list_", "list_approles", {}),
        ("read", "read_approle", {"name": "foo"}),
        ("write", "write_approle", {"name": "foo"}),
        ("delete", "delete_approle", {"name": "foo"}),
        ("get_role_id", "read_role_id", {"name": "foo"}),
        ("get_secret_id", "generate_secret_id", {"name": "foo", "cache": False}),
        ("lookup_secret_id", "read_secret_id", {"name": "foo", "secret_id": "bar"}),
        ("destroy_secret_id", "destroy_secret_id", {"name": "foo", "secret_id": "bar"}),
    ),
)
def test_func_converts_errors(func, method, kwargs, approle_api):
    getattr(approle_api.return_value, method).side_effect = vault.VaultException("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_approle, func)(**kwargs)


@pytest.mark.parametrize(
    "func,method",
    (
        ("clear_cached", "destroy_cached"),
        ("list_cached", "list_cached_info"),
    ),
)
def test_cache_func_converts_errors(func, method, approle_store):
    getattr(approle_store.return_value, method).side_effect = vault.VaultException("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_approle, func)()


def test_get_secret_id_cache_errors_are_ignored(approle_api, approle_store):
    """
    Ensure that errors during cache retrieval do not prevent
    the generation of a new SecretID
    """
    secret_id = vault.VaultSecretId(
        secret_id="new-secret-id",
        secret_id_ttl=1337,
        secret_id_num_uses=0,
        creation_time=0,
    )
    approle_store.return_value.get.side_effect = vault.VaultException("cache error")
    approle_api.return_value.generate_secret_id.return_value = secret_id
    res = vault_approle.get_secret_id("foo")
    assert res == "new-secret-id"
    approle_store.return_value.get.assert_called_once()
    approle_api.return_value.generate_secret_id.assert_called_once()
    approle_store.return_value.store.assert_called_once_with("secid.approle.foo.default", secret_id)


@pytest.mark.parametrize("func", ("lookup_secret_id", "destroy_secret_id"))
def test_secret_id_funcs_require_secret_id_or_accessor(func):
    with pytest.raises(SaltInvocationError, match="Either secret_id or accessor is required"):
        getattr(vault_approle, func)("foo")
