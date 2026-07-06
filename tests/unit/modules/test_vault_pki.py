import datetime
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
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


def _gen_cert(
    subject_cn,
    subject_key,
    issuer_cn,
    issuer_key,
    ca=True,
    not_before=None,
    not_after=None,
    ski_of=None,
):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - datetime.timedelta(days=30))
        .not_valid_after(not_after or now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key((ski_of or subject_key).public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def pki():
    """
    Real certificates for issuer resolution tests. ``int_a``/``int_b`` are
    cross-signed: the same intermediate key, certified by two different roots,
    hence identical SubjectKeyIdentifiers.
    """
    root_a_key = ec.generate_private_key(ec.SECP256R1())
    root_b_key = ec.generate_private_key(ec.SECP256R1())
    int_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    forged_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return {
        "root_a": _gen_cert("Root A", root_a_key, "Root A", root_a_key),
        "root_b": _gen_cert("Root B", root_b_key, "Root B", root_b_key),
        "int_a": _gen_cert("Intermediate", int_key, "Root A", root_a_key),
        "int_b": _gen_cert("Intermediate", int_key, "Root B", root_b_key),
        "int_a_expired": _gen_cert(
            "Intermediate",
            int_key,
            "Root A",
            root_a_key,
            not_before=now - datetime.timedelta(days=700),
            not_after=now - datetime.timedelta(days=1),
        ),
        # carries the true intermediate's SKI, but wraps a different key
        "int_forged_ski": _gen_cert(
            "Intermediate", forged_key, "Root A", root_a_key, ski_of=int_key
        ),
        "leaf": _gen_cert("leaf.example.com", leaf_key, "Intermediate", int_key, ca=False),
    }


def _issuer_entry(cert, parent=None, revoked=False):
    entry = {"certificate": cert, "ca_chain": [cert] + ([parent] if parent else [])}
    if revoked:
        entry["revoked"] = True
    return entry


def _mock_pki_query(cert_data, issuers=None, default=None):
    issuers = issuers or {}

    def query(_method, endpoint, *_args, **_kwargs):
        if endpoint.startswith("pki/cert/"):
            return {"data": cert_data}
        if endpoint == "pki/issuers":
            return {"data": {"key_info": {issuer_id: {} for issuer_id in issuers}}}
        if endpoint.startswith("pki/issuer/"):
            ref = endpoint.rsplit("/", 1)[-1]
            if ref == "default":
                ref = default
            if ref not in issuers:
                raise vaultutil.VaultNotFoundError()
            return {"data": {"issuer_id": ref, **issuers[ref]}}
        raise AssertionError(f"unexpected endpoint: {endpoint}")

    return query


def test_read_certificate_full_resolves_issuer_via_aki(query, pki):
    # a stale ca_chain in the certificate read response is replaced with the
    # resolved issuer's chain and a missing trailing newline is restored
    cert_data = {"certificate": pki["leaf"].rstrip("\n"), "ca_chain": ["stale"]}
    query.side_effect = _mock_pki_query(
        cert_data,
        issuers={
            "root-a": _issuer_entry(pki["root_a"]),
            "int-a": _issuer_entry(pki["int_a"], pki["root_a"]),
        },
    )

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret["certificate"] == pki["leaf"]
    assert ret["ca_chain"] == [pki["int_a"], pki["root_a"]]
    assert query.call_args_list[0][0][1] == "pki/cert/00:11:22"


def test_read_certificate_full_prefers_issuer_id(query):
    certificate = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    issuer = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n"
    query.side_effect = [
        {"data": {"certificate": certificate, "issuer_id": "abc-123"}},
        {"data": {"certificate": issuer, "ca_chain": [issuer]}},
    ]

    ret = vault_pki.read_certificate_full("00:11:22", mount="mount")

    assert ret["ca_chain"] == [issuer]
    assert query.call_args_list[1][0][1] == "mount/issuer/abc-123"


def test_read_certificate_full_fallback_issuer_missing(query, pki):
    query.side_effect = [
        {"data": {"certificate": pki["leaf"], "issuer_id": "abc-123"}},
        vaultutil.VaultNotFoundError(),
    ]

    with pytest.raises(CommandExecutionError, match="Failed to lookup issuer.*"):
        vault_pki.read_certificate_full("00:11:22")


def test_read_certificate_full_issuer_undeterminable(query, pki):
    # no configured issuer matches the leaf's AKI: no fallback to default
    query.side_effect = _mock_pki_query(
        {"certificate": pki["leaf"]},
        issuers={"root-b": _issuer_entry(pki["root_b"])},
    )

    with pytest.raises(CommandExecutionError, match="Failed to determine cert issuer"):
        vault_pki.read_certificate_full("00:11:22")


def test_read_certificate_full_cross_signed_prefers_unrevoked(query, pki):
    # both cross-signed entries match the leaf's AKI, but one is revoked;
    # the valid sibling must win, even when the revoked one is the default
    query.side_effect = _mock_pki_query(
        {"certificate": pki["leaf"]},
        issuers={
            "int-a": _issuer_entry(pki["int_a"], pki["root_a"], revoked=True),
            "int-b": _issuer_entry(pki["int_b"], pki["root_b"]),
        },
        default="int-a",
    )

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret["ca_chain"] == [pki["int_b"], pki["root_b"]]


def test_read_certificate_full_cross_signed_prefers_unexpired(query, pki):
    query.side_effect = _mock_pki_query(
        {"certificate": pki["leaf"]},
        issuers={
            "int-a": _issuer_entry(pki["int_a_expired"], pki["root_a"]),
            "int-b": _issuer_entry(pki["int_b"], pki["root_b"]),
        },
        default="int-a",
    )

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret["ca_chain"] == [pki["int_b"], pki["root_b"]]


@pytest.mark.parametrize("default", ["int-a", "int-b"])
def test_read_certificate_full_cross_signed_tie_break_via_default_issuer(query, pki, default):
    query.side_effect = _mock_pki_query(
        {"certificate": pki["leaf"]},
        issuers={
            "int-a": _issuer_entry(pki["int_a"], pki["root_a"]),
            "int-b": _issuer_entry(pki["int_b"], pki["root_b"]),
        },
        default=default,
    )

    ret = vault_pki.read_certificate_full("00:11:22")

    expected_root = pki["root_a"] if default == "int-a" else pki["root_b"]
    assert ret["ca_chain"][1] == expected_root


def test_read_certificate_full_all_candidates_revoked_still_returns_chain(query, pki):
    # revoked issuers are only deprioritized, never filtered to nothing
    query.side_effect = _mock_pki_query(
        {"certificate": pki["leaf"]},
        issuers={
            "int-a": _issuer_entry(pki["int_a_expired"], pki["root_a"], revoked=True),
            "int-b": _issuer_entry(pki["int_b"], pki["root_b"], revoked=True),
        },
        default="int-a",
    )

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret["ca_chain"] == [pki["int_b"], pki["root_b"]]


def test_read_certificate_full_forged_ski_is_rejected(query, pki):
    # SKI matching alone is insufficient: an issuer carrying the true
    # intermediate's SKI but a different key must fail signature verification
    query.side_effect = _mock_pki_query(
        {"certificate": pki["leaf"]},
        issuers={
            "int-forged": _issuer_entry(pki["int_forged_ski"], pki["root_a"]),
            "int-b": _issuer_entry(pki["int_b"], pki["root_b"]),
        },
        default="int-forged",
    )

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret["ca_chain"] == [pki["int_b"], pki["root_b"]]


def test_read_certificate_full_returns_existing_bundle(query, pki):
    bundle = pki["leaf"] + pki["int_a"] + pki["root_a"]
    query.side_effect = [
        {"data": {"certificate": bundle, "issuer_id": "int-a"}},
        {"data": {"certificate": pki["int_a"], "ca_chain": [pki["int_a"], pki["root_a"]]}},
    ]

    ret = vault_pki.read_certificate_full("00:11:22")

    assert ret["certificate"] == bundle
    assert ret["ca_chain"] == [pki["int_a"], pki["root_a"]]


@pytest.mark.parametrize(
    "args", [{"serial": "00:11:22:33:44:55", "certificate": "-----BEGIN CERTIFICATE..."}, {}]
)
def test_revoke_certificate_raise_err(args):
    with pytest.raises(SaltInvocationError):
        vault_pki.revoke_certificate(**args)
