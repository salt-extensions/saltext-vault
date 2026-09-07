import datetime
import typing

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault import pki

if typing.TYPE_CHECKING:
    from typing_extensions import Self


class CAFixture:
    def __init__(self, common_name: str, issuer: "Self | None" = None):
        self.common_name = common_name
        self.private_key: pki.Privkey = None  # type: ignore
        self.certificate: x509.Certificate = None  # type: ignore
        self.issuer = issuer

    def generate(self, *, days_valid=30, pathlen=2):
        one_day = datetime.timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
                ]
            )
        )
        if self.issuer is not None:
            issuer_name = self.issuer.certificate.subject
        else:
            issuer_name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
                ]
            )
        builder = builder.issuer_name(issuer_name)

        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * days_valid))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=(pathlen - int(bool(self.issuer))) if pathlen is not None else None,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                crl_sign=True,
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=False,
                data_encipherment=False,
                decipher_only=False,
                encipher_only=False,
                key_agreement=False,
                key_encipherment=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(f"{self.common_name}.{'intermediate' if self.issuer else 'root'}.ca")]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            False,
        )
        if self.issuer is not None:
            key_identifier = self.issuer.certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.digest
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=key_identifier,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None,
                ),
                False,
            )
            signing_private_key = self.issuer.private_key
        else:
            signing_private_key = private_key
        certificate = builder.sign(
            private_key=signing_private_key,
            algorithm=hashes.SHA256(),
        )
        self.private_key = private_key
        self.certificate = certificate


class CertificateFixture:
    def __init__(self, common_name, ca: CAFixture):
        self.common_name = common_name
        self.ca = ca
        self.private_key = None
        self.certificate = None

    def generate(self, alt_names=None):
        one_day = datetime.timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
                ]
            )
        )

        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 1))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        if alt_names is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in alt_names]),
                critical=False,
            )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        certificate = builder.sign(
            private_key=self.ca.private_key,
            algorithm=hashes.SHA256(),
        )

        self.private_key = private_key
        self.certificate = certificate


class PKIInfra:
    certs = {}

    def __init__(self, name):
        root = CAFixture(f"{name} root CA")
        root.generate()
        sub = CAFixture(f"{name} int CA", root)
        sub.generate()
        self.certs = {}
        self.ca = sub

    def issue_certificate(self, common_name, alt_names=None):
        if common_name not in self.certs:
            cert = CertificateFixture(f"{common_name} leaf", self.ca)
            cert.generate(alt_names)
            self.certs[common_name] = cert
        return self.certs[common_name]


class PKIInfraFactory:
    pki_infra = {}

    @classmethod
    def instance(cls, name):
        if name not in cls.pki_infra:
            inst = PKIInfra(name=name)
            cls.pki_infra[name] = inst
        return cls.pki_infra[name]


@pytest.fixture(scope="module")
def existing_ca():
    instance = PKIInfraFactory.instance("existing")
    instance.issue_certificate("acme.com")

    return instance


@pytest.fixture(scope="module")
def existing_ca_with_alt_names():
    instance = PKIInfraFactory.instance("existing")
    instance.issue_certificate("acme.org", alt_names=["acme.com"])
    return instance


@pytest.fixture(scope="module")
def new_ca():
    instance = PKIInfraFactory.instance("new")
    instance.issue_certificate("acme.com")

    return instance


@pytest.fixture
def existing_pki(existing_ca):  # pylint: disable=unused-argument
    instance = PKIInfraFactory.instance("existing")
    cert_obj = instance.issue_certificate("acme.com")

    return (
        cert_obj.certificate,
        cert_obj.private_key,
        [cert_obj.ca.certificate, cert_obj.ca.issuer.certificate],
    )


@pytest.fixture
def new_pki():
    instance = PKIInfraFactory.instance("new")
    cert_obj = instance.issue_certificate("acme.com")

    return (
        cert_obj.certificate,
        cert_obj.private_key,
        [cert_obj.ca.certificate, cert_obj.ca.issuer.certificate],
    )


def test_compare_ca_chain_with_new(existing_pki, new_pki):
    _, _, chain = existing_pki
    _, _, new_chain = new_pki
    assert pki._compare_ca_chain(chain, new_chain) is False


def test_compare_ca_chain_with_same(existing_pki):
    _, _, chain = existing_pki
    assert pki._compare_ca_chain(chain, chain) is True


def test_compare_ca_chain_with_same_unordered(existing_pki):
    _, _, chain = existing_pki
    other_chain = list(reversed(chain))
    assert pki._compare_ca_chain(chain, other_chain, unordered=True) is True


def test_compare_ca_chain_with_same_diff_len(existing_pki):
    _, _, chain = existing_pki
    assert pki._compare_ca_chain(chain, chain + chain) is False


@pytest.mark.parametrize(
    "sans,expected",
    [
        (
            ["dns:foo.example.com", "DNS:bar.example.com", "ip:198.51.100.1"],
            {"DNS": ["foo.example.com", "bar.example.com"], "IP": ["198.51.100.1"]},
        ),
        (
            {"dns": ["foo.example.com"], "email": "user@example.com"},
            {"DNS": ["foo.example.com"], "EMAIL": ["user@example.com"]},
        ),
        (
            ["1.3.6.1.4.1.311.20.2.3:user@example.com"],
            {"1.3.6.1.4.1.311.20.2.3": ["user@example.com"]},
        ),
    ],
)
def test_norm_sans(sans, expected):
    """
    Ensure both list and dict inputs are normalized into a dict of lists
    with uppercase (or OID) keys
    """
    assert pki.norm_sans(sans) == expected


@pytest.mark.parametrize("sans", [["foo:bar"], {"foo": "bar"}])
def test_norm_sans_invalid_type(sans):
    """
    Ensure SAN types that are neither known nor a valid OID are rejected
    """
    with pytest.raises(SaltInvocationError, match="Invalid SAN type 'FOO'"):
        pki.norm_sans(sans)


def test_norm_sans_invalid_format():
    """
    Ensure list items without a type prefix are rejected
    """
    with pytest.raises(CommandExecutionError, match="SAN is not in correct format"):
        pki.norm_sans(["missing-type-prefix"])
