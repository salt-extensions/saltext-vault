import logging
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_ssh
from saltext.vault.utils import vault


@pytest.fixture
def configure_loader_modules():
    return {
        vault_ssh: {
            "__grains__": {"id": "test-minion"},
            "__salt__": {
                "file.file_exists": MagicMock(return_value=False),
                "ssh_pki.get_public_key": MagicMock(return_value="ssh-ed25519 yay"),
            },
        }
    }


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", return_value=True, autospec=True) as _query:
        yield _query


@pytest.mark.parametrize(
    "func,kwargs",
    (
        ("read_role", {"name": "foo"}),
        ("write_role_otp", {"name": "foo", "default_user": "bar"}),
        ("write_role_ca", {"name": "foo", "allow_user_certificates": True}),
        ("delete_role", {"name": "foo"}),
        ("list_roles", {}),
        ("list_roles_ip", {"address": "10.1.0.1"}),
        ("list_roles_zeroaddr", {}),
        ("write_zeroaddr_roles", {"roles": ["foo"]}),
        ("delete_zeroaddr_roles", {}),
        ("get_creds", {"name": "foo", "address": "10.1.0.1"}),
        ("create_ca", {}),
        ("destroy_ca", {}),
        ("read_ca", {}),
        ("sign_key", {"name": "foo", "public_key": "ssh-ed25519 yay"}),
        ("generate_key_cert", {"name": "foo"}),
        (
            "create_certificate",
            {"signing_policy": "foo", "cert_type": "user", "public_key": "ssh-ed25519 yay"},
        ),
        ("get_signing_policy", {"signing_policy": "foo"}),
    ),
)
def test_func_converts_errors(func, kwargs, query):
    query.side_effect = vault.VaultException("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_ssh, func)(**kwargs)


def test_create_certificate_requires_signing_policy(query):
    with pytest.raises(SaltInvocationError, match="Need 'signing_policy' specified"):
        vault_ssh.create_certificate(public_key="ssh-ed25519 yay", cert_type="user")
    query.assert_not_called()


@pytest.mark.parametrize("allow", (False, True))
def test_create_certificate_requires_determinable_cert_type(query, allow):
    """
    When cert_type is not passed and the role either disallows or allows
    both user and host certificates, it cannot be inferred.
    """
    query.return_value = {
        "data": {
            "key_type": "ca",
            "allow_user_certificates": allow,
            "allow_host_certificates": allow,
        }
    }
    with pytest.raises(SaltInvocationError, match="Could not determine missing `cert_type`"):
        vault_ssh.create_certificate(signing_policy="foo", public_key="ssh-ed25519 yay")


def test_create_certificate_ignores_incompatible_params(query, caplog):
    query.side_effect = ({"data": {"key_type": "ca"}}, {"data": {"signed_key": "yay"}})
    ignored = {
        "signing_private_key": "key",
        "signing_private_key_passphrase": "hunter2",
        "serial_number": 42,
        "not_before": "20240101000000Z",
        "not_after": "20260101000000Z",
        "copypath": "/etc/ssh/certs",
        "path": "/etc/ssh/cert.pub",
        "overwrite": True,
        "raw": True,
    }
    with caplog.at_level(logging.WARNING):
        res = vault_ssh.create_certificate(
            signing_policy="foo",
            cert_type="user",
            public_key="ssh-ed25519 yay",
            valid_principals=["foo"],
            **ignored,
        )
    assert res == "yay"
    for param in ignored:
        assert f"Ignoring '{param}'" in caplog.text
    payload = query.call_args[1]["payload"]
    assert not set(payload) & set(ignored)


def test_write_role_ca_requires_cert_type(query):
    with pytest.raises(
        SaltInvocationError, match="Either allow_user_certificates or allow_host_certificates"
    ):
        vault_ssh.write_role_ca("foo")
    query.assert_not_called()


@pytest.mark.parametrize(
    "param", ("default_critical_options", "default_extensions", "allowed_user_key_lengths")
)
def test_write_role_ca_validates_mapping_params(query, param):
    with pytest.raises(SaltInvocationError, match=f"'{param}' must be specified as a mapping"):
        vault_ssh.write_role_ca("foo", allow_user_certificates=True, **{param: ["no-mapping"]})
    query.assert_not_called()


def test_get_signing_policy_default_extensions_template_render_failure(query, caplog):
    """
    When rendering default extension templates fails, e.g. because the
    token is not allowed to read its associated entity, the default
    extensions should be reported as empty instead of crashing.
    """
    query.side_effect = (
        {
            "data": {
                "key_type": "ca",
                "allow_user_certificates": True,
                "allowed_users": "*",
                "default_extensions_template": True,
                "default_extensions": {
                    "login@example.com": "{{identity.entity.metadata.user}}",
                },
            }
        },
        {"data": {"public_key": "ssh-ed25519 cakey"}},
    )
    with patch(
        "saltext.vault.utils.vault.render_identity_template", autospec=True
    ) as render_identity_template:
        render_identity_template.side_effect = vault.VaultPermissionDeniedError("permission denied")
        with caplog.at_level(logging.ERROR):
            policy = vault_ssh.get_signing_policy("foo")
    assert policy["default_extensions"] == {}
    assert "Failed rendering default extensions template" in caplog.text
    assert policy["signing_public_key"] == "ssh-ed25519 cakey"


def test_get_file_or_data_non_path_data():
    """
    Data that cannot be interpreted as a path at all should be
    returned as-is without file system access.
    """
    data = b"ssh-ed25519 yay"
    assert vault_ssh._get_file_or_data(data) is data
    vault_ssh.__salt__["file.file_exists"].assert_not_called()  # type: ignore


@pytest.mark.parametrize("err", (OSError, TypeError, ValueError))
def test_get_file_or_data_swallows_file_check_errors(err):
    """
    Errors during the check whether the data represents an existing file
    (e.g. file name too long) should result in the data being returned as-is.
    """
    data = "ssh-ed25519 " + "a" * 4096
    file_exists = MagicMock(side_effect=err("booh"))
    with patch.dict(vault_ssh.__salt__, {"file.file_exists": file_exists}):
        assert vault_ssh._get_file_or_data(data) is data
    file_exists.assert_called_once_with(data)


@pytest.fixture
def query_raw():
    with patch("saltext.vault.utils.vault.query_raw", autospec=True) as _query_raw:
        res = MagicMock()
        res.status_code = 200
        res.text = "ssh-rsa unauthd"
        _query_raw.return_value = res
        yield _query_raw


def test_read_ca_authenticated(query, query_raw):
    """
    Ensure the authenticated endpoint is preferred when accessible
    """
    query.return_value = {"data": {"public_key": "ssh-rsa authd"}}
    assert vault_ssh.read_ca() == "ssh-rsa authd"
    query_raw.assert_not_called()


def test_read_ca_unauthenticated_fallback(query, query_raw):
    """
    Ensure permission errors on the authenticated endpoint cause a
    fallback to the unauthenticated one
    """
    query.side_effect = vault.VaultPermissionDeniedError("permission denied")
    assert vault_ssh.read_ca() == "ssh-rsa unauthd"
    query_raw.assert_called_once()
    assert query_raw.call_args[0][1] == "ssh/public_key"
    assert query_raw.call_args[1]["is_unauthd"] is True


def test_read_ca_unauthenticated_fallback_converts_errors(query, query_raw):
    """
    Ensure exceptions during the unauthenticated request are converted
    """
    query.side_effect = vault.VaultPermissionDeniedError("permission denied")
    query_raw.side_effect = vault.VaultServerError("internal error")
    with pytest.raises(CommandExecutionError, match="VaultServerError: internal error"):
        vault_ssh.read_ca()


@pytest.mark.parametrize(
    "status_code,json_effect,match",
    (
        (400, {"errors": ["keys haven't been configured yet"]}, "keys haven't been configured yet"),
        (404, {"errors": ["missing mount"]}, "VaultNotFoundError: missing mount"),
        # empty error list means unconfigured keys
        (404, {"errors": []}, "keys haven't been configured yet"),
        # unparsable/unexpected error responses are treated the same
        (404, {"unexpected": "schema"}, "keys haven't been configured yet"),
        (404, ValueError("not json"), "keys haven't been configured yet"),
    ),
)
def test_read_ca_unauthenticated_fallback_not_found(
    query, query_raw, status_code, json_effect, match
):
    """
    Ensure that 400/404 responses to the unauthenticated query are reported
    as not found, with a fallback message when errors are empty/unparsable
    """
    query.side_effect = vault.VaultPermissionDeniedError("permission denied")
    query_raw.return_value.status_code = status_code
    if isinstance(json_effect, Exception):
        query_raw.return_value.json.side_effect = json_effect
    else:
        query_raw.return_value.json.return_value = json_effect
    with pytest.raises(CommandExecutionError, match=match):
        vault_ssh.read_ca()


def test_read_ca_unauthenticated_fallback_unexpected_status(query, query_raw):
    """
    Ensure unexpected response statuses to the unauthenticated query
    are reported with their body
    """
    query.side_effect = vault.VaultPermissionDeniedError("permission denied")
    query_raw.return_value.status_code = 502
    query_raw.return_value.text = "bad gateway"
    with pytest.raises(CommandExecutionError, match="Unexpected response status 502.*bad gateway"):
        vault_ssh.read_ca()


def test_list_roles_ip_no_roles(query):
    query.side_effect = vault.VaultInvocationError("Missing roles")
    assert vault_ssh.list_roles_ip("10.1.0.1") == []


def test_list_roles_ip_converts_invocation_errors(query):
    query.side_effect = vault.VaultInvocationError("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        vault_ssh.list_roles_ip("10.1.0.1")
