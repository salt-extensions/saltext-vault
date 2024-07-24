import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault import pki


class TestCA:
    def __init__(self, common_name):
        self.common_name = common_name
        self.private_key = None
        self.certificate = None

    def generate(self):
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
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
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
            x509.SubjectAlternativeName([x509.DNSName("cryptography.io")]), critical=False
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )
        self.private_key = private_key
        self.certificate = certificate


class TestCertificate:
    def __init__(self, common_name, ca: TestCA):
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


class TestPKIInfra:
    certs = {}

    def __init__(self, name):
        ca = TestCA(name)
        ca.generate()
        self.certs = {}
        self.ca = ca

    def issue_certificate(self, common_name, alt_names=None):
        if common_name not in self.certs:
            cert = TestCertificate(f"{common_name}", self.ca)
            cert.generate(alt_names)
            self.certs[common_name] = cert
        return self.certs[common_name]


class TestPKIFactory:
    pki_infra = {}

    @classmethod
    def instance(cls, name):
        if name not in cls.pki_infra:
            inst = TestPKIInfra(name=f"{name} CA")
            cls.pki_infra[name] = inst
        return cls.pki_infra[name]


@pytest.fixture(scope="module")
def existing_ca():
    instance = TestPKIFactory.instance("existing")
    instance.issue_certificate("acme.com")

    return instance


@pytest.fixture(scope="module")
def existing_ca_with_alt_names():
    instance = TestPKIFactory.instance("existing")
    instance.issue_certificate("acme.org", alt_names=["acme.com"])
    return instance


@pytest.fixture(scope="module")
def new_ca():
    instance = TestPKIFactory.instance("new")
    instance.issue_certificate("acme.com")

    return instance


@pytest.fixture
def existing_pki(existing_ca):  # pylint: disable=unused-argument
    instance = TestPKIFactory.instance("existing")
    cert_obj = instance.issue_certificate("acme.com")

    return cert_obj.certificate, cert_obj.private_key, [cert_obj.ca.certificate]


@pytest.fixture
def new_pki():
    instance = TestPKIFactory.instance("new")
    cert_obj = instance.issue_certificate("acme.com")

    return cert_obj.certificate, cert_obj.private_key, [cert_obj.ca.certificate]


@pytest.mark.parametrize(
    "inpt,expected",
    [
        (60, "3C"),
        (4508375982735402, "10:04:58:14:F7:00:2A"),
        (123456789011, "1C:BE:99:1A:13"),
    ],
)
def test_dec2hex(inpt, expected):
    assert pki.dec2hex(inpt) == expected


@pytest.mark.parametrize(
    "inpt,match",
    [
        (-60, ".*non-negative"),
        ("00:11:22:33:44:55:66:77:88:99", ".*input must be integer.*"),
    ],
)
def test_dec2hex_raise_err(inpt, match):
    with pytest.raises(SaltInvocationError, match=match):
        pki.dec2hex(inpt)


def test_compare_ca_chain_with_new(existing_pki, new_pki):
    _, _, chain = existing_pki
    _, _, new_chain = new_pki
    assert pki.compare_ca_chain(chain, new_chain) is False


def test_compare_ca_chain_with_same(existing_pki):
    _, _, chain = existing_pki
    assert pki.compare_ca_chain(chain, chain) is True


def test_compare_ca_chain_with_same_diff_len(existing_pki):
    _, _, chain = existing_pki
    assert pki.compare_ca_chain(chain, chain + chain) is False
