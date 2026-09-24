import logging
from unittest.mock import ANY
from unittest.mock import patch

import pytest
import salt.exceptions

import saltext.vault.utils.vault as vaultutil
from saltext.vault.modules import vault

# pylint: disable=unused-import
from tests.unit.fixtures.vault import data
from tests.unit.fixtures.vault import patch_kv
from tests.unit.fixtures.vault import read_kv
from tests.unit.fixtures.vault import write_kv
from tests.unit.fixtures.vault import write_kv_err

# pylint: enable=unused-import


@pytest.fixture
def configure_loader_modules():
    return {
        vault: {
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


@pytest.fixture
def data_list():
    return ["foo"]


@pytest.fixture
def list_kv(data_list):
    with patch("saltext.vault.utils.vault.list_kv", autospec=True) as _list:
        _list.return_value = data_list
        yield _list


@pytest.fixture
def read_kv_not_found(read_kv):
    read_kv.side_effect = vaultutil.VaultNotFoundError
    yield read_kv


@pytest.fixture
def list_kv_not_found(list_kv):
    list_kv.side_effect = vaultutil.VaultNotFoundError
    yield list_kv


@pytest.fixture
def patch_kv_err(patch_kv):
    patch_kv.side_effect = vaultutil.VaultPermissionDeniedError("damn")
    yield patch_kv


@pytest.fixture
def delete_kv():
    with patch("saltext.vault.utils.vault.delete_kv", autospec=True) as delete_kv:
        yield delete_kv


@pytest.fixture
def delete_kv_err(delete_kv):
    delete_kv.side_effect = vaultutil.VaultPermissionDeniedError("damn")
    yield delete_kv


@pytest.fixture
def destroy_kv():
    with patch("saltext.vault.utils.vault.destroy_kv", autospec=True) as destroy_kv:
        yield destroy_kv


@pytest.fixture
def destroy_kv_err(destroy_kv):
    destroy_kv.side_effect = vaultutil.VaultPermissionDeniedError("damn")
    yield destroy_kv


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", autospec=True) as query:
        yield query


@pytest.mark.usefixtures("read_kv")
@pytest.mark.parametrize(
    "key,expected",
    [
        pytest.param(None, {"foo": "bar"}, id="full_data"),
        pytest.param("foo", "bar", id="single_key"),
    ],
)
def test_read_secret(key, expected):
    """
    Ensure read_secret works as expected without and with specified key.
    KV v1/2 is handled in the utils module.
    """
    res = vault.read_secret("some/path", key=key)
    assert res == expected


@pytest.mark.usefixtures("read_kv_not_found", "list_kv_not_found")
@pytest.mark.parametrize("func", ["read_secret", "list_secrets"])
def test_read_list_secret_with_default(func):
    """
    Ensure read_secret and list_secrets with defaults set return those
    if the path was not found.
    """
    tgt = getattr(vault, func)
    res = tgt("some/path", default=["f"])
    assert res == ["f"]


@pytest.mark.usefixtures("read_kv_not_found", "list_kv_not_found")
@pytest.mark.parametrize("func", ["read_secret", "list_secrets"])
def test_read_list_secret_without_default(func):
    """
    Ensure read_secret and list_secrets without defaults set raise
    a CommandExecutionError when the path is not found.
    """
    tgt = getattr(vault, func)
    with pytest.raises(salt.exceptions.CommandExecutionError, match=".*VaultNotFoundError.*"):
        tgt("some/path")


@pytest.mark.usefixtures("list_kv")
@pytest.mark.parametrize(
    "keys_only,expected",
    [
        pytest.param(False, {"keys": ["foo"]}, id="wrapped_dict"),
        pytest.param(True, ["foo"], id="keys_only"),
    ],
)
def test_list_secrets(keys_only, expected):
    """
    Ensure list_secrets works as expected. keys_only=False is default to
    stay backwards-compatible. There should not be a reason to have the
    function return a dict with a single predictable key otherwise.
    """
    res = vault.list_secrets("some/path", keys_only=keys_only)
    assert res == expected


def test_write_secret(data, write_kv):
    """
    Ensure write_secret parses kwargs as expected
    """
    path = "secret/some/path"
    res = vault.write_secret(path, **data)
    assert res
    write_kv.assert_called_once_with(path, data, opts=ANY, context=ANY)


@pytest.mark.usefixtures("write_kv_err")
def test_write_secret_err(data, caplog):
    """
    Ensure write_secret handles exceptions as expected
    """
    with caplog.at_level(logging.ERROR):
        res = vault.write_secret("secret/some/path", **data)
        assert not res
        assert "Failed to write secret! VaultPermissionDeniedError: damn" in caplog.messages


def test_write_raw(data, write_kv):
    """
    Ensure write_secret works as expected
    """
    path = "secret/some/path"
    res = vault.write_raw(path, data)
    assert res
    write_kv.assert_called_once_with(path, data, opts=ANY, context=ANY)


@pytest.mark.usefixtures("write_kv_err")
def test_write_raw_err(data, caplog):
    """
    Ensure write_raw handles exceptions as expected
    """
    with caplog.at_level(logging.ERROR):
        res = vault.write_raw("secret/some/path", data)
        assert not res
        assert "Failed to write secret! VaultPermissionDeniedError: damn" in caplog.messages


def test_patch_secret(data, patch_kv):
    """
    Ensure patch_secret parses kwargs as expected
    """
    path = "secret/some/path"
    res = vault.patch_secret(path, **data)
    assert res
    patch_kv.assert_called_once_with(path, data, opts=ANY, context=ANY)


@pytest.mark.usefixtures("patch_kv_err")
def test_patch_secret_err(data, caplog):
    """
    Ensure patch_secret handles exceptions as expected
    """
    with caplog.at_level(logging.ERROR):
        res = vault.patch_secret("secret/some/path", **data)
        assert not res
        assert "Failed to patch secret! VaultPermissionDeniedError: damn" in caplog.messages


@pytest.mark.parametrize(
    "args",
    [
        pytest.param([], id="no_versions"),
        pytest.param([1, 2], id="versions"),
    ],
)
def test_delete_secret(delete_kv, args):
    """
    Ensure delete_secret works as expected
    """
    path = "secret/some/path"
    res = vault.delete_secret(path, *args)
    assert res
    delete_kv.assert_called_once_with(
        path, opts=ANY, context=ANY, versions=args or None, all_versions=False
    )


@pytest.mark.usefixtures("delete_kv_err")
@pytest.mark.parametrize(
    "args",
    [
        pytest.param([], id="no_versions"),
        pytest.param([1, 2], id="versions"),
    ],
)
def test_delete_secret_err(args, caplog):
    """
    Ensure delete_secret handles exceptions as expected
    """
    with caplog.at_level(logging.ERROR):
        res = vault.delete_secret("secret/some/path", *args)
        assert not res
        assert "Failed to delete secret! VaultPermissionDeniedError: damn" in caplog.messages


@pytest.mark.parametrize(
    "args",
    [
        pytest.param([], id="no_versions"),
        pytest.param([1], id="one_version"),
        pytest.param([1, 2], id="two_versions"),
    ],
)
def test_destroy_secret(destroy_kv, args):
    """
    Ensure destroy_secret works as expected
    """
    path = "secret/some/path"
    res = vault.destroy_secret(path, *args)
    assert res
    destroy_kv.assert_called_once_with(
        path, args or None, opts=ANY, context=ANY, all_versions=False
    )


@pytest.mark.usefixtures("destroy_kv_err")
@pytest.mark.parametrize(
    "args",
    [
        pytest.param([1], id="one_version"),
        pytest.param([1, 2], id="two_versions"),
    ],
)
def test_destroy_secret_err(caplog, args):
    """
    Ensure destroy_secret handles exceptions as expected
    """
    with caplog.at_level(logging.ERROR):
        res = vault.destroy_secret("secret/some/path", *args)
        assert not res
        assert "Failed to destroy secret! VaultPermissionDeniedError: damn" in caplog.messages


def test_clear_token_cache():
    """
    Ensure clear_token_cache wraps the utility function properly
    """
    with patch("saltext.vault.utils.vault.clear_cache") as cache:
        vault.clear_token_cache()
        cache.assert_called_once_with(ANY, ANY, connection=True, session=False)


def test_policy_fetch(query, policy_response):
    """
    Ensure policy_fetch returns rules only and calls the API as expected
    """
    query.return_value = policy_response
    res = vault.policy_fetch("test-policy")
    assert res == policy_response["rules"]
    query.assert_called_once_with("GET", "sys/policy/test-policy", opts=ANY, context=ANY)


def test_policy_fetch_not_found(query):
    """
    Ensure policy_fetch returns None when the policy was not found
    """
    query.side_effect = vaultutil.VaultNotFoundError
    res = vault.policy_fetch("test-policy")
    assert res is None


@pytest.mark.parametrize(
    "func,args",
    [
        pytest.param("policy_fetch", [], id="policy_fetch"),
        pytest.param("policy_write", ["rule"], id="policy_write"),
        pytest.param("policy_delete", [], id="policy_delete"),
        pytest.param("policies_list", None, id="policies_list"),
    ],
)
def test_policy_functions_raise_errors(query, func, args):
    """
    Ensure policy functions raise CommandExecutionErrors
    """
    query.side_effect = vaultutil.VaultPermissionDeniedError
    func = getattr(vault, func)
    with pytest.raises(
        salt.exceptions.CommandExecutionError, match=".*VaultPermissionDeniedError.*"
    ):
        if args is None:
            func()
        else:
            func("test-policy", *args)


def test_policy_write(query, policy_response):
    """
    Ensure policy_write calls the API as expected
    """
    query.return_value = True
    res = vault.policy_write("test-policy", policy_response["rules"])
    assert res
    query.assert_called_once_with(
        "POST",
        "sys/policy/test-policy",
        opts=ANY,
        context=ANY,
        payload={"policy": policy_response["rules"]},
        safe_to_retry=True,
    )


def test_policy_delete(query):
    """
    Ensure policy_delete calls the API as expected
    """
    query.return_value = True
    res = vault.policy_delete("test-policy")
    assert res
    query.assert_called_once_with("DELETE", "sys/policy/test-policy", opts=ANY, context=ANY)


def test_policy_delete_handles_not_found(query):
    """
    Ensure policy_delete returns False instead of raising CommandExecutionError
    when a policy was absent already.
    """
    query.side_effect = vaultutil.VaultNotFoundError
    res = vault.policy_delete("test-policy")
    assert not res


def test_policies_list(query, policies_list_response):
    """
    Ensure policies_list returns policy list only and calls the API as expected
    """
    query.return_value = policies_list_response
    res = vault.policies_list()
    assert res == policies_list_response["policies"]
    query.assert_called_once_with("GET", "sys/policy", opts=ANY, context=ANY)


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
        pytest.param("read_secret", {"path": "some/path"}, "read_kv", id="read_secret"),
        pytest.param("list_secrets", {"path": "some/path"}, "list_kv", id="list_secrets"),
        pytest.param("restore_secret", {"path": "some/path"}, "restore_kv", id="restore_secret"),
        pytest.param("policy_fetch", {"policy": "test-policy"}, "query", id="policy_fetch"),
        pytest.param(
            "policy_write", {"policy": "test-policy", "rules": "rule"}, "query", id="policy_write"
        ),
        pytest.param("policy_delete", {"policy": "test-policy"}, "query", id="policy_delete"),
        pytest.param("policies_list", {}, "query", id="policies_list"),
        pytest.param("query", {"method": "GET", "endpoint": "test/endpoint"}, "query", id="query"),
        pytest.param("get_server_config", {}, "get_authd_client", id="get_server_config"),
        pytest.param("clear_cache", {}, "clear_cache", id="clear_cache"),
        pytest.param("clear_token_cache", {}, "clear_cache", id="clear_token_cache"),
        pytest.param("update_config", {}, "update_config", id="update_config"),
    ],
)
def test_func_converts_errors(func, kwargs, target):
    """
    Ensure remote errors are converted into CommandExecutionErrors
    """
    with patch(f"saltext.vault.utils.vault.{target}", autospec=True) as tgt:
        tgt.side_effect = vaultutil.VaultException("booh")
        with pytest.raises(salt.exceptions.CommandExecutionError, match="booh"):
            getattr(vault, func)(**kwargs)


@pytest.mark.parametrize(
    "func,kwargs,target",
    [
        pytest.param(
            "read_secret_meta", {"path": "some/path"}, "read_kv_meta", id="read_secret_meta"
        ),
        pytest.param(
            "patch_raw", {"path": "some/path", "raw": {"foo": "bar"}}, "patch_kv", id="patch_raw"
        ),
        pytest.param("wipe_secret", {"path": "some/path"}, "wipe_kv", id="wipe_secret"),
    ],
)
def test_func_swallows_errors(func, kwargs, target, caplog):
    """
    Ensure remote errors result in a False return value for legacy reasons
    """
    with patch(f"saltext.vault.utils.vault.{target}", autospec=True) as tgt:
        tgt.side_effect = vaultutil.VaultException("booh")
        with caplog.at_level(logging.ERROR):
            res = getattr(vault, func)(**kwargs)
    assert res is False
    assert any("VaultException: booh" in msg for msg in caplog.messages)
