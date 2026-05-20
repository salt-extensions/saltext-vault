from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

import saltext.vault.utils.vault as vaultutil
from saltext.vault.modules import vault_pki


@pytest.fixture
def configure_loader_modules():
    return {
        vault_pki: {
            "__grains__": {"id": "test-minion"},
            "__opts__": {},
            "__context__": {},
        }
    }


@pytest.fixture
def data():
    return {"foo": "bar"}


@pytest.fixture
def data_role():
    return {
        "dummy": {
            "data": {
                "allow_any_name": True,
            }
        },
        "no-subddomains": {
            "data": {
                "allow_subdomains": False,
            }
        },
        "no-serverflag": {
            "data": {
                "server_flag": True,
            }
        },
    }


@pytest.fixture
def data_roles_list():
    return {"data": {"keys": ["foo"]}}


@pytest.fixture
def role_not_found(query):
    query.side_effect = vaultutil.VaultNotFoundError
    yield query


@pytest.fixture
def list_roles(data_roles_list):
    with patch("saltext.vault.utils.vault.query", autospec=True) as _list:
        _list.return_value = data_roles_list
        yield _list


@pytest.fixture
def read_role(data_role, role_name):
    with patch("saltext.vault.utils.vault.query", autospec=True) as _data:
        _data.return_value = data_role[role_name]
        yield _data


# @pytest.fixture
# def delete_role():
#     with patch("saltext.vault.utils.vault.query", autospec=True) as delete_role:
#         yield delete_role


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", autospec=True) as _query:
        yield _query


@pytest.mark.usefixtures("list_roles")
@pytest.mark.parametrize(
    "expected",
    [["foo"]],
)
def test_list_roles(expected):
    res = vault_pki.list_roles()
    assert res == expected


@pytest.mark.usefixtures("read_role")
@pytest.mark.parametrize(
    "role_name, expected",
    [
        ("dummy", {"allow_any_name": True}),
        ("no-subddomains", {"allow_subdomains": False}),
        ("no-serverflag", {"server_flag": True}),
    ],
)
def test_read_role(role_name, expected):
    ret = vault_pki.read_role(role_name)
    assert ret == expected


@pytest.mark.parametrize("issuer", [None, "default", "someother"])
def test_write_role_payload(query, issuer):
    args = {
        "ttl": "300h",
        "max_ttl": "360h",
        "server_flag": True,
        "allow_subdomains": False,
        "allowed_domains": ["example.com", "saltproject.io"],
        "client_flag": True,
        "allow_localhost": True,
        "require_cn": False,
    }

    assert vault_pki.write_role("role", mount="mount", issuer_ref=issuer, **args) is True
    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == "mount/roles/role"
    expected_payload = args.copy()
    if issuer is not None:
        expected_payload["issuer_ref"] = issuer
    assert payload == expected_payload


def test_delete_role_payload(query):
    assert vault_pki.delete_role("role", mount="mount") is True
    endpoint = query.call_args[0][1]
    assert endpoint == "mount/roles/role"


@pytest.mark.usefixtures("role_not_found")
def test_write_role_raises_err():
    with pytest.raises(CommandExecutionError, match=".*VaultNotFoundError.*"):
        vault_pki.write_role("some/path")


@pytest.mark.usefixtures("role_not_found")
def test_delete_role_return_false_if_not_found():
    ret = vault_pki.delete_role("some/path")
    assert not ret


@pytest.mark.usefixtures("role_not_found")
def test_read_role_return_none_if_not_found():
    ret = vault_pki.read_role("some/path")
    assert ret is None


@pytest.mark.usefixtures("role_not_found")
def test_list_roles_return_empty_array_if_not_found():
    ret = vault_pki.list_roles("some/path")
    assert ret == []


@pytest.mark.parametrize(
    "common_name,root_type,args",
    [
        (
            "root_ca",
            "exported",
            {
                "issuer_name": "root-ca",
                "key-name": "root-ca-key",
                "max_path_length": 4,
                "key_bits": 384,
                "key_type": "ec",
            },
        ),
        (
            "root_ca",
            "internal",
            {
                "key_bits": 384,
                "key_type": "ec",
            },
        ),
        ("root_ca", "internal", {}),
    ],
)
def test_generate_root_payload(query, common_name, root_type, args):
    vault_pki.generate_root(common_name=common_name, type=root_type, mount="mount", **args)

    endpoint = query.call_args[0][1]
    payload = query.call_args[1]["payload"]
    assert endpoint == f"mount/root/generate/{root_type}"
    expected_payload = payload.copy()
    expected_payload["common_name"] = common_name
    assert payload == expected_payload


def test_generate_root_raise_err_with_default_name():
    with pytest.raises(SaltInvocationError):
        vault_pki.generate_root("my root", issuer_name="default")

    with pytest.raises(SaltInvocationError):
        vault_pki.generate_root("my root", key_name="default")


def test_read_certificate_full_returns_certificate(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    query.return_value = {"data": {"certificate": certificate}}

    ret = vault_pki.read_certificate_full("00:11:22", mount="mount")

    assert ret == {"certificate": certificate}
    endpoint = query.call_args_list[0][0][1]
    assert endpoint == "mount/cert/00:11:22"


def test_read_certificate_full_fallback_ca_chain(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    issuer = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"
    root = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
    query.side_effect = [
        {"data": {"certificate": certificate}},
        {"data": {"certificate": issuer, "ca_chain": [issuer, root]}},
    ]

    ret = vault_pki.read_certificate_full("00:11:22", mount="mount")

    assert ret == {"certificate": certificate, "ca_chain": [issuer, root]}
    assert query.call_args_list[0][0][1] == "mount/cert/00:11:22"
    assert query.call_args_list[1][0][1] == "mount/issuer/default"


def test_read_certificate_full_fallback_uses_issuer_id(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    issuer = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"
    query.side_effect = [
        {"data": {"certificate": certificate, "issuer_id": "abc-123"}},
        {"data": {"certificate": issuer, "ca_chain": [issuer]}},
    ]

    ret = vault_pki.read_certificate_full("00:11:22", mount="mount")

    assert ret["ca_chain"] == [issuer]
    assert query.call_args_list[1][0][1] == "mount/issuer/abc-123"


def test_read_certificate_full_fallback_issuer_missing(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    query.side_effect = [
        {"data": {"certificate": certificate}},
        vaultutil.VaultNotFoundError(),
    ]

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret == {"certificate": certificate}


def test_read_certificate_full_with_chain(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    issuer = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"
    root = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
    query.return_value = {"data": {"certificate": certificate, "ca_chain": [issuer, root]}}

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret == {"certificate": certificate, "ca_chain": [issuer, root]}


def test_read_certificate_full_with_chain_returns_existing_bundle(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    issuer = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"
    root = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
    bundle = f"{certificate}{issuer}{root}"
    query.return_value = {"data": {"certificate": bundle, "ca_chain": [issuer, root]}}

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret == {"certificate": bundle, "ca_chain": [issuer, root]}


def test_read_certificate_full_with_private_key(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    private_key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
    query.return_value = {"data": {"certificate": certificate, "private_key": private_key}}

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret == {"certificate": certificate, "private_key": private_key}


def test_read_certificate_full_with_chain_and_private_key(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    issuer = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"
    root = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
    private_key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
    query.return_value = {
        "data": {
            "certificate": certificate,
            "ca_chain": [issuer, root],
            "private_key": private_key,
        }
    }

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret == {
        "certificate": certificate,
        "ca_chain": [issuer, root],
        "private_key": private_key,
    }


@pytest.mark.parametrize(
    "args", [{"serial": "00:11:22:33:44:55", "certificate": "-----BEGIN CERTIFICATE..."}, {}]
)
def test_revoke_certificate_raise_err(args):
    with pytest.raises(SaltInvocationError):
        vault_pki.revoke_certificate(**args)
