import logging
from unittest.mock import ANY
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import salt.exceptions

import saltext.vault.utils.vault as vaultutil
from saltext.vault.modules import vault


@pytest.fixture
def vault_policy_mock():
    vpmock = Mock()
    vpmock.fetch.return_value = "yup"
    vpmock.write.return_value = "yup"
    vpmock.delete.return_value = "yup"
    vpmock.list_.return_value = "yup"
    return vpmock


@pytest.fixture
def vault_secret_mock():
    vsmock = Mock()
    vsmock.read.return_value = "yup"
    vsmock.read_meta.return_value = "yup"
    vsmock.write.return_value = "yup"
    vsmock.write_raw.return_value = "yup"
    vsmock.patch.return_value = "yup"
    vsmock.patch_raw.return_value = "yup"
    vsmock.list_.return_value = "yup"
    vsmock.delete.return_value = "yup"
    vsmock.restore.return_value = "yup"
    vsmock.destroy.return_value = "yup"
    vsmock.wipe.return_value = "yup"
    return vsmock


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", autospec=True) as query:
        yield query


@pytest.fixture
def configure_loader_modules(vault_policy_mock, vault_secret_mock):
    return {
        vault: {
            "__grains__": {"id": "test-minion"},
            "__salt__": {
                "vault_policy.fetch": vault_policy_mock.fetch,
                "vault_policy.write": vault_policy_mock.write,
                "vault_policy.delete": vault_policy_mock.delete,
                "vault_policy.list": vault_policy_mock.list_,
                "vault_secret.read": vault_secret_mock.read,
                "vault_secret.read_meta": vault_secret_mock.read_meta,
                "vault_secret.write": vault_secret_mock.write,
                "vault_secret.write_raw": vault_secret_mock.write_raw,
                "vault_secret.patch": vault_secret_mock.patch,
                "vault_secret.patch_raw": vault_secret_mock.patch_raw,
                "vault_secret.list": vault_secret_mock.list_,
                "vault_secret.delete": vault_secret_mock.delete,
                "vault_secret.restore": vault_secret_mock.restore,
                "vault_secret.destroy": vault_secret_mock.destroy,
                "vault_secret.wipe": vault_secret_mock.wipe,
            },
        },
    }


@pytest.mark.parametrize("func", ["read_secret", "list_secrets"])
@pytest.mark.parametrize("exc", (salt.exceptions.CommandExecutionError, TypeError))
@pytest.mark.filterwarnings(r"ignore:The `vault\.:DeprecationWarning")
def test_read_list_secret_with_default(func, exc, vault_secret_mock):
    """
    Ensure read_secret and list_secrets with defaults set return those
    if the path was not found, even if the migrated modules would error instead.
    """
    vault_secret_mock.list_.side_effect = vault_secret_mock.read.side_effect = exc
    tgt = getattr(vault, func)
    res = tgt("some/path", default=["f"])
    assert res == ["f"]


@pytest.mark.parametrize("func", ["read_secret", "list_secrets"])
@pytest.mark.parametrize("check", ("caught_err", "uncaught_err", "uncaught_cee_err"))
@pytest.mark.filterwarnings(r"ignore:The `vault\.:DeprecationWarning")
def test_read_list_secret_without_default(func, check, vault_secret_mock):
    """
    Ensure read_secret and list_secrets without defaults set raise
    a CommandExecutionError when the path is not found.
    """
    if func == "read_secret":
        prefix = "Failed to read secret!"
        tgt = vault_secret_mock.read
    else:
        prefix = "Failed to list secrets!"
        tgt = vault_secret_mock.list_

    if check == "caught_err":
        match = f"{prefix} VaultNotFoundError: some/path"
        tgt.side_effect = salt.exceptions.CommandExecutionError(match)
    elif check == "uncaught_err":
        match = f"{prefix} TypeError: booh"
        tgt.side_effect = TypeError("booh")
    else:
        match = f"{prefix} CommandExecutionError: booh"
        tgt.side_effect = salt.exceptions.CommandExecutionError("booh")
    tgt = getattr(vault, func)
    with pytest.raises(salt.exceptions.CommandExecutionError, match=f"^{match}$"):
        tgt("some/path")


@pytest.mark.parametrize(
    "keys_only,expected",
    [
        pytest.param(False, {"keys": ["foo"]}, id="wrapped_dict"),
        pytest.param(True, ["foo"], id="keys_only"),
    ],
)
@pytest.mark.filterwarnings(r"ignore:The `vault\.:DeprecationWarning")
def test_list_secrets(keys_only, expected, vault_secret_mock):
    """
    Ensure list_secrets works as expected. keys_only=False is default to
    stay backwards-compatible. There should not be a reason to have the
    function return a dict with a single predictable key otherwise.
    """
    vault_secret_mock.list_.return_value = ["foo"]
    res = vault.list_secrets("some/path", keys_only=keys_only)
    assert res == expected


@pytest.mark.parametrize(
    "func,secret_func,kwargs",
    (
        pytest.param("read_secret", "read", {"default": "foo"}, id="read_secret"),
        pytest.param("read_secret_meta", "read_meta", {}, id="read_secret_meta"),
        pytest.param("write_secret", "write", {"foo": "bar"}, id="write_secret"),
        pytest.param("write_raw", "write_raw", {"raw": {"foo": "bar"}}, id="write_raw"),
        pytest.param("patch_secret", "patch", {"foo": "bar"}, id="patch_secret"),
        pytest.param("patch_raw", "patch_raw", {"raw": {"foo": "bar"}}, id="patch_raw"),
        pytest.param("list_secrets", "list_", {"default": "foo"}, id="list_secrets"),
        pytest.param("delete_secret", "delete", {}, id="delete_secret"),
        pytest.param("destroy_secret", "destroy", {}, id="destroy_secret"),
        pytest.param("wipe_secret", "wipe", {}, id="wipe_secret"),
        # restore_secret always raised exceptions
    ),
)
@pytest.mark.parametrize("exc", (TypeError, salt.exceptions.CommandExecutionError))
def test_func_swallows_errors_and_warns_deprecated(
    func, secret_func, kwargs, exc, vault_secret_mock, caplog
):
    has_default = secret_func in ("read", "list_")
    if exc is salt.exceptions.CommandExecutionError:
        # Construct a CommandExecutionError which is already converted
        if secret_func == "read_meta":
            msg = "Failed to read secret metadata! TypeError: damn"
        else:
            msg = f"Failed to {secret_func.split('_', maxsplit=1)[0]} secret! TypeError: damn"
    else:
        msg = "damn"
    getattr(vault_secret_mock, secret_func).side_effect = exc(msg)
    with (
        caplog.at_level(logging.ERROR),
        pytest.deprecated_call(
            match=f"`vault.{func}`.*renamed to `vault_secret.{secret_func.rstrip('_')}`"
        ),
    ):
        res = getattr(vault, func)("secret/some/path", **kwargs)
        if has_default:
            pass
        else:
            if secret_func == "read_meta":
                assert "Failed to read secret metadata! TypeError: damn" in caplog.messages
            else:
                assert (
                    f"Failed to {secret_func.split('_', maxsplit=1)[0]} secret! TypeError: damn"
                    in caplog.messages
                )
            if exc is salt.exceptions.CommandExecutionError:
                # avoid duplicate prefixes
                assert "CommandExecutionError: Failed" not in caplog.messages
    if has_default:
        assert res == "foo"
    else:
        assert res is False


@pytest.mark.parametrize(
    "func,secret_func,kwargs",
    (
        pytest.param(
            "read_secret",
            "read",
            {"key": "key", "metadata": False, "version": 1},
            id="read_secret_key_version",
        ),
        pytest.param(
            "read_secret",
            "read",
            {"key": None, "metadata": True, "version": None},
            id="read_secret_metadata",
        ),
        pytest.param(
            "delete_secret", "delete", {"all_versions": True}, id="delete_secret_all_versions"
        ),
        pytest.param(
            "restore_secret", "restore", {"all_versions": True}, id="restore_secret_all_versions"
        ),
        pytest.param(
            "destroy_secret", "destroy", {"all_versions": True}, id="destroy_secret_all_versions"
        ),
    ),
)
@pytest.mark.filterwarnings(r"ignore:The `vault\.:DeprecationWarning")
def test_func_passes_kwargs(func, secret_func, kwargs, vault_secret_mock):
    getattr(vault_secret_mock, secret_func).return_value = "yup"
    res = getattr(vault, func)("secret/some/path", **kwargs)
    assert res == "yup"
    if secret_func == "read" and kwargs.get("key", "_not_set") is None:
        kwargs["key"] = ANY  # None => NOT_SET translation
    getattr(vault_secret_mock, secret_func).assert_called_once_with("secret/some/path", **kwargs)


@pytest.mark.parametrize(
    "func,secret_func",
    (
        pytest.param("delete_secret", "delete", id="delete_secret"),
        pytest.param("restore_secret", "restore", id="restore_secret"),
        pytest.param("destroy_secret", "destroy", id="destroy_secret"),
    ),
)
@pytest.mark.filterwarnings(r"ignore:The `vault\.:DeprecationWarning")
def test_func_passes_args(func, secret_func, vault_secret_mock):
    getattr(vault_secret_mock, secret_func).return_value = "yup"
    res = getattr(vault, func)("secret/some/path", 1, 2, 3)
    assert res == "yup"
    getattr(vault_secret_mock, secret_func).assert_called_once_with(
        "secret/some/path", 1, 2, 3, all_versions=False
    )


def test_clear_token_cache():
    """
    Ensure clear_token_cache wraps the utility function properly
    """
    with (
        patch("saltext.vault.utils.vault.clear_cache") as cache,
        pytest.deprecated_call(match="dropped in version 2"),
    ):
        vault.clear_token_cache()
        cache.assert_called_once_with(ANY, ANY, connection=True, session=False)


@pytest.mark.parametrize(
    "func,kwargs",
    [
        pytest.param("policy_fetch", {"policy": "test-policy"}, id="policy_fetch"),
        pytest.param("policy_write", {"policy": "test-policy", "rules": "rule"}, id="policy_write"),
        pytest.param("policy_delete", {"policy": "test-policy"}, id="policy_delete"),
        pytest.param("policies_list", {}, id="policies_list"),
    ],
)
def test_policy_functions_emit_warnings(func, kwargs):
    """
    Ensure policy functions emit deprecation warnings
    """
    _func = getattr(vault, func)
    with pytest.deprecated_call(
        match=f"was renamed to `vault_policy.{func.rsplit('_', maxsplit=1)[1]}`"
    ):
        assert _func(**kwargs) == "yup"


@pytest.mark.parametrize("method", ["POST", "DELETE"])
@pytest.mark.parametrize(
    "payload", [None, pytest.param({"data": {"foo": "bar"}}, id="with_payload")]
)
def test_query(query, method, payload):
    """
    Ensure query wraps the utility function properly
    """
    query.return_value = True
    endpoint = "test/endpoint"
    res = vault.query(method, endpoint, payload=payload)
    assert res
    query.assert_called_once_with(method, endpoint, opts=ANY, context=ANY, payload=payload)


def test_query_raises_errors(query):
    """
    Ensure query raises CommandExecutionErrors
    """
    query.side_effect = vaultutil.VaultPermissionDeniedError
    with pytest.raises(
        salt.exceptions.CommandExecutionError, match=".*VaultPermissionDeniedError.*"
    ):
        vault.query("GET", "test/endpoint")


@pytest.mark.parametrize(
    "func,kwargs,target",
    [
        pytest.param("query", {"method": "GET", "endpoint": "test/endpoint"}, "query", id="query"),
        pytest.param("get_server_config", {}, "get_authd_client", id="get_server_config"),
        pytest.param("clear_cache", {}, "clear_cache", id="clear_cache"),
        pytest.param("clear_token_cache", {}, "clear_cache", id="clear_token_cache"),
        pytest.param("update_config", {}, "update_config", id="update_config"),
    ],
)
@pytest.mark.filterwarnings("ignore:.*dropped in version 2:DeprecationWarning")
def test_func_converts_errors(func, kwargs, target):
    """
    Ensure remote errors are converted into CommandExecutionErrors
    """
    with patch(f"saltext.vault.utils.vault.{target}", autospec=True) as tgt:
        tgt.side_effect = vaultutil.VaultException("booh")
        with pytest.raises(salt.exceptions.CommandExecutionError, match="booh"):
            getattr(vault, func)(**kwargs)
