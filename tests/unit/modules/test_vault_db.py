import contextlib
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

import saltext.vault.utils.vault as vault
from saltext.vault.modules import vault_db


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


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", return_value=True, autospec=True) as _query:
        yield _query


@pytest.mark.parametrize(
    "func,kwargs",
    (
        ("list_connections", {}),
        ("fetch_connection", {"name": "foo"}),
        ("write_connection", {"name": "foo", "plugin": "custom"}),
        ("delete_connection", {"name": "foo"}),
        ("reset_connection", {"name": "foo"}),
        ("rotate_root", {"name": "foo"}),
        ("list_roles", {}),
        ("fetch_role", {"name": "foo"}),
        (
            "write_static_role",
            {"name": "foo", "connection": "bar", "username": "baz", "rotation_period": 42},
        ),
        (
            "write_role",
            {"name": "foo", "connection": "bar", "creation_statements": "thou shall exist"},
        ),
        ("delete_role", {"name": "foo"}),
        ("get_creds", {"name": "foo", "cache": False}),
        ("rotate_static_role", {"name": "foo"}),
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
        (None, None, True),
        (None, {"password_policy": "yolo"}, True),
        (None, {"password_police": "??"}, False),
        (None, {"key_bits": 1}, False),
        ("password", {"password_policy": "yolo"}, True),
        ("password", {"password_alice": "257"}, False),
        ("password", {"key_bits": 1}, False),
        ("rsa_private_key", {"key_bits": 1, "format": "red"}, True),
        ("rsa_private_key", {"key_fits": 0}, False),
        ("rsa_private_key", {"password_policy": "yolo"}, False),
        ("unknown", {"something": "else"}, True),
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
