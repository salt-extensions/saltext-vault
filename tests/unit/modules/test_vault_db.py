import contextlib
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_db
from saltext.vault.utils import vault

# pylint: disable=unused-import
from tests.unit.fixtures.vault import query

# pylint: enable=unused-import


@pytest.fixture
def configure_loader_modules():
    return {
        vault_db: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def _conn_absent():
    with patch(
        "saltext.vault.modules.vault_db.fetch_connection", return_value=None, autospec=True
    ) as fetch:
        yield fetch


@pytest.mark.parametrize(
    "func,kwargs",
    (
        pytest.param("list_connections", {}, id="list_connections"),
        pytest.param("fetch_connection", {"name": "foo"}, id="fetch_connection"),
        pytest.param(
            "write_connection", {"name": "foo", "plugin": "custom"}, id="write_connection"
        ),
        pytest.param("delete_connection", {"name": "foo"}, id="delete_connection"),
        pytest.param("reset_connection", {"name": "foo"}, id="reset_connection"),
        pytest.param("rotate_root", {"name": "foo"}, id="rotate_root"),
        pytest.param("list_roles", {}, id="list_roles"),
        pytest.param("fetch_role", {"name": "foo"}, id="fetch_role"),
        pytest.param(
            "write_static_role",
            {"name": "foo", "connection": "bar", "username": "baz", "rotation_period": 42},
            id="write_static_role",
        ),
        pytest.param(
            "write_role",
            {"name": "foo", "connection": "bar", "creation_statements": "thou shall exist"},
            id="write_role",
        ),
        pytest.param("delete_role", {"name": "foo"}, id="delete_role"),
        pytest.param("get_creds", {"name": "foo", "cache": False}, id="get_creds"),
        pytest.param("rotate_static_role", {"name": "foo"}, id="rotate_static_role"),
    ),
)
def test_func_converts_errors(func, kwargs, query, request):
    query.side_effect = vault.VaultException("booh")
    if func == "write_connection":
        # otherwise we would test fetch_connection again
        request.getfixturevalue("_conn_absent")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_db, func)(**kwargs)


@pytest.mark.usefixtures("_conn_absent")
@pytest.mark.parametrize("plugin", ("mysql", "custom"))
def test_write_connection_missing_kwargs(plugin):
    if plugin == "custom":
        ctx = patch("saltext.vault.utils.vault.query", autospec=True)
    else:
        ctx = pytest.raises(SaltInvocationError, match="requires.*additional.*connection_url")
    with ctx:
        vault_db.write_connection("foo", plugin)


@pytest.mark.usefixtures("_conn_absent")
def test_write_connection_payload(query):
    kwargs = {
        "version": "1.2.3",
        "verify": True,
        "allowed_roles": ["*"],
        "root_rotation_statements": ["rotate!"],
        "password_policy": "yolo",
        "custom_arg": True,
    }
    assert vault_db.write_connection("foo", "custom", **kwargs, rotate=False, mount="bar") is True
    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == "bar/config/foo"
    expected_payload = kwargs.copy()
    expected_payload["plugin_name"] = "custom-database-plugin"
    expected_payload["plugin_version"] = expected_payload.pop("version")
    expected_payload["verify_connection"] = expected_payload.pop("verify")
    assert payload == expected_payload


@pytest.mark.usefixtures("_conn_absent")
@pytest.mark.parametrize("rotate", (False, True))
def test_write_connection_rotate(query, rotate):
    vault_db.write_connection("foo", "custom", rotate=rotate)
    endpoint = query.call_args[0][1]
    assert (endpoint == "database/config/foo") is not rotate
    assert (endpoint == "database/rotate-root/foo") is rotate


def test_write_static_role_payload(query):
    kwargs = {
        "rotation_period": 42,
        "rotation_statements": ["rotate!"],
        "credential_type": "password",
        "credential_config": {"password_policy": "yolo"},
    }
    assert vault_db.write_static_role("role", "conn", "user", **kwargs, mount="mount") is True
    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == "mount/static-roles/role"
    expected_payload = kwargs.copy()
    expected_payload["username"] = "user"
    expected_payload["db_name"] = "conn"
    assert payload == expected_payload


def test_write_role_payload(query):
    kwargs = {
        "creation_statements": ["cogito ergo sum"],
        "default_ttl": 42,
        "max_ttl": 1337,
        "revocation_statements": ["it's not you, it's me"],
        "rollback_statements": ["this should be fine"],
        "renew_statements": ["kekkon shitemo kudasai"],
        "credential_type": "rsa_private_key",
        "credential_config": {"key_bits": 1},
    }
    assert vault_db.write_role("role", "conn", **kwargs, mount="mount") is True
    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == "mount/roles/role"
    expected_payload = kwargs.copy()
    expected_payload["db_name"] = "conn"
    assert payload == expected_payload


@pytest.mark.parametrize(
    "typ,vals,expected",
    (
        pytest.param(None, None, True, id="no_config"),
        pytest.param(None, {"password_policy": "yolo"}, True, id="default_type_valid"),
        pytest.param(None, {"password_police": "??"}, False, id="default_type_invalid_key"),
        pytest.param(None, {"key_bits": 1}, False, id="default_type_rsa_config"),
        pytest.param("password", {"password_policy": "yolo"}, True, id="password_valid"),
        pytest.param("password", {"password_alice": "257"}, False, id="password_invalid_key"),
        pytest.param("password", {"key_bits": 1}, False, id="password_rsa_config"),
        pytest.param("rsa_private_key", {"key_bits": 1, "format": "red"}, True, id="rsa_valid"),
        pytest.param("rsa_private_key", {"key_fits": 0}, False, id="rsa_invalid_key"),
        pytest.param(
            "rsa_private_key", {"password_policy": "yolo"}, False, id="rsa_password_config"
        ),
        pytest.param("unknown", {"something": "else"}, True, id="unknown_type_unvalidated"),
    ),
)
@pytest.mark.usefixtures("query")
def test_write_role_credential_type_param_verification(typ, vals, expected):
    if expected:
        ctx = contextlib.nullcontext()
    else:
        ctx = pytest.raises(SaltInvocationError, match="invalid for credential type")
    with ctx:
        vault_db.write_static_role(
            "role", "conn", "user", 42, credential_type=typ, credential_config=vals
        )
