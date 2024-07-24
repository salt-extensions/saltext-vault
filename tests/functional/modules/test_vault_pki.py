from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from salt.utils.x509 import generate_rsa_privkey
from salt.utils.x509 import load_cert

from saltext.vault.utils.vault.pki import dec2hex
from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_list
from tests.support.vault import vault_list_detailed
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.slow_test,
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.usefixtures("vault_container_version"),
]


@pytest.fixture(scope="module")
def minion_config_overrides(vault_port):
    return {
        "features": {
            "x509_v2": True,
        },
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "cache": {
                "backend": "disk",  # ensure a persistent cache is available for get_creds
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
    }


@pytest.fixture
def testrole():
    return {"ttl": 3600, "max_ttl": 86400, "allow_any_name": True, "issuer_ref": "testissuer"}


@pytest.fixture
def testissuer():
    return {"issuer_name": "testissuer", "common_name": "Test Issuer CA"}


@pytest.fixture
def testissuer2():
    return {"issuer_name": "testissuer2", "common_name": "Test Issuer CA 2"}


@pytest.fixture(scope="module")
def private_key():
    pk = generate_rsa_privkey(2048)
    pk_bytes = pk.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pk_bytes.decode()


@pytest.fixture(scope="module", autouse=True)
def pki_engine(vault_container_version):  # pylint: disable=unused-argument
    assert vault_enable_secret_engine("pki")
    yield
    assert vault_disable_secret_engine("pki")


@pytest.fixture(params=[["testrole"]])
def roles_setup(request):  # pylint: disable=unused-argument
    try:
        for role_name in request.param:
            role_args = request.getfixturevalue(role_name)
            vault_write(f"pki/roles/{role_name}", **role_args)
            assert role_name in vault_list("pki/roles")
        yield
    finally:
        for role_name in request.param:
            if role_name in vault_list("pki/roles"):
                vault_delete(f"pki/roles/{role_name}")
                assert role_name not in vault_list("pki/roles")


@pytest.fixture
def root_issuer_setup():
    root_ca_args = {"issuer_name": "test-issuer-root", "common_name": "Test Issuer Root CA"}

    vault_write("pki/root/generate/internal", **root_ca_args)
    assert vault_read(f"pki/issuer/{root_ca_args['issuer_name']}")


@pytest.fixture(params=[["testissuer"]])
def issuers_setup(request, root_issuer_setup):  # pylint: disable=unused-argument
    try:
        for issuer_name in request.param:
            issuer_args = request.getfixturevalue(issuer_name)

            csr_resp = vault_write("pki/intermediate/generate/internal", **issuer_args)["data"]
            sign_resp = vault_write(
                "/pki/root/sign-intermediate", csr=csr_resp["csr"], **issuer_args
            )["data"]
            resp = vault_write(
                "/pki/intermediate/set-signed", certificate=sign_resp["certificate"]
            )["data"]
            for issuer in resp["imported_issuers"]:
                vault_write(f"/pki/issuer/{issuer}", **issuer_args)
                assert vault_read(f"pki/issuer/{issuer_name}")
        yield
    finally:
        all_issuers = vault_list_detailed("pki/issuers")
        issuers_names = []
        if len(all_issuers) > 0:
            issuers_names = [v["issuer_name"] for k, v in all_issuers["key_info"].items()]
        for issuer_name in request.param:
            if issuer_name in issuers_names:
                vault_delete(f"pki/issuer/{issuer_name}")


@pytest.fixture
def vault_pki(modules):
    try:
        yield modules.vault_pki
    finally:
        if "testrole" in vault_list("pki/roles"):
            vault_delete("pki/roles/testrole")
            assert "testrole" not in vault_list("pki/roles")

        vault_delete("pki/issuer/test-issuer-root")


@pytest.fixture
def generated_root():
    yield
    vault_delete("pki/issuer/generated-root")


@pytest.mark.usefixtures("roles_setup")
def test_list_roles(vault_pki):
    ret = vault_pki.list_roles()
    assert ret == ["testrole"]


def test_list_empty_roles(vault_pki):
    ret = vault_pki.list_roles()
    assert ret == []


@pytest.mark.usefixtures("roles_setup")
def test_delete_role(vault_pki):
    ret = vault_pki.delete_role("testrole")
    assert ret
    assert "testrole" not in vault_list("pki/roles")


def test_write_role(vault_pki):
    assert vault_pki.write_role("testrole2", ttl="360h") is True
    assert "testrole2" in vault_list("pki/roles")


@pytest.mark.usefixtures("roles_setup")
def test_update_role(vault_pki):
    assert vault_pki.write_role("testrole", ttl="4h", max_ttl="24h") is True
    assert vault_read("pki/roles/testrole")["data"]["ttl"] == 14400  # 4 hours in seconds


@pytest.mark.usefixtures("issuers_setup")
def test_list_issuers(vault_pki):
    ret = [info["issuer_name"] for info in vault_pki.list_issuers().values()]
    assert set(ret) == {"test-issuer-root", "testissuer"}


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer(vault_pki):
    ret = vault_pki.read_issuer("testissuer")
    assert ret["issuer_name"] == "testissuer"
    assert "ca_chain" in ret
    assert "certificate" in ret


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_issue_certificate(vault_pki):
    # Certificate expiration is always in UTC, so we need to compare with UTC.
    run_time = datetime.now(tz=timezone.utc)

    ret = vault_pki.issue_certificate(
        role_name="testrole",
        common_name="test.example.com",
        ttl="2h",
        alt_names=["DNS:test2.example.com"],
    )
    assert "certificate" in ret
    certificate = load_cert(ret["certificate"])

    assert certificate.issuer.rfc4514_string() == "CN=Test Issuer CA"

    assert certificate.subject.rfc4514_string() == "CN=test.example.com"
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_sans = san.value.get_values_for_type(x509.DNSName)
    assert certificate.not_valid_after_utc - run_time > timedelta(hours=1)
    assert "test2.example.com" in dns_sans
    assert "test.example.com" in dns_sans


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_sign_certificate_with_private_key(vault_pki, private_key):
    # Certificate expiration is always in UTC, so we need to compare with UTC.
    run_time = datetime.now(tz=timezone.utc)

    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        alt_names=["dns:test2.example.com"],
    )
    assert "certificate" in ret
    certificate = load_cert(ret["certificate"])

    assert certificate.issuer.rfc4514_string() == "CN=Test Issuer CA"

    assert certificate.subject.rfc4514_string() == "CN=test.example.com"
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_sans = san.value.get_values_for_type(x509.DNSName)
    assert certificate.not_valid_after_utc - run_time > timedelta(hours=1)
    assert "test2.example.com" in dns_sans
    assert "test.example.com" in dns_sans


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_sign_certificate_with_sign_verbatim(vault_pki, private_key):
    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        sign_verbatim=True,
        alt_names=["dns:test2.example.com"],
        L="Boston",
        C="US",
    )
    assert "certificate" in ret
    certificate = load_cert(ret["certificate"])
    assert certificate.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "US"
    assert certificate.subject.get_attributes_for_oid(x509.OID_LOCALITY_NAME)[0].value == "Boston"


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("issuers_setup", [["testissuer", "testissuer2"]], indirect=True)
def test_sign_certificate_with_alternative_issuer(vault_pki, private_key):
    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        sign_verbatim=True,
        issuer_ref="testissuer2",
        alt_names=["dns:test2.example.com"],
        L="Boston",
        C="US",
    )
    assert "certificate" in ret
    certificate = load_cert(ret["certificate"])
    assert certificate.issuer.rfc4514_string() == "CN=Test Issuer CA 2"


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_sign_certificate_with_der_encoding(vault_pki, private_key):
    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        encoding="der",
        alt_names=["dns:test2.example.com"],
    )

    assert "certificate" in ret
    _, encoding, _, _ = load_cert(ret["certificate"], get_encoding=True)
    assert encoding.lower() == "der"


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer_certificate(vault_pki):
    ret = vault_pki.read_issuer_certificate("testissuer")

    certificate = load_cert(ret)

    assert certificate.subject.rfc4514_string() == "CN=Test Issuer CA"


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer_certificate_with_chain(vault_pki):
    ret = vault_pki.read_issuer_certificate("testissuer", include_chain=True)

    certificate, chain = load_cert(ret, load_chain=True)

    assert certificate.subject.rfc4514_string() == "CN=Test Issuer CA"
    assert len(chain) == 1

    assert chain[0].subject.rfc4514_string() == "CN=Test Issuer Root CA"


@pytest.mark.usefixtures("issuers_setup")
def test_delete_issuer(vault_pki):
    ret = [info["issuer_name"] for info in vault_pki.list_issuers().values()]
    assert "testissuer" in ret

    ret = vault_pki.delete_issuer("testissuer")
    assert ret

    ret = [info["issuer_name"] for info in vault_pki.list_issuers().values()]
    assert "testissuer" not in ret


@pytest.mark.usefixtures("issuers_setup")
def test_delete_issuer_with_private_key(vault_pki):
    ret = vault_pki.read_issuer("testissuer")
    assert ret["key_id"]
    private_key_id = ret["key_id"]

    ret = vault_pki.delete_issuer("testissuer", include_key=True)
    assert ret

    ret = [info["issuer_name"] for info in vault_pki.list_issuers().values()]
    assert "testissuer" not in ret

    keys = vault_list("pki/keys")
    assert private_key_id not in keys


@pytest.mark.usefixtures("issuers_setup")
def test_update_issuer(vault_pki):
    ret = vault_pki.update_issuer(
        "testissuer",
        aia_urls=["http://aia.example.com/ca.list"],
    )
    assert ret

    # Now update OCSP endpoints.
    ret = vault_pki.update_issuer(
        "testissuer",
        ocsp_servers=["http://ocsp.example.com"],
    )

    # Now update CRL endpoints.
    ret = vault_pki.update_issuer(
        "testissuer",
        crl_endpoints=["http://crl.example.com/ca.crl"],
    )

    ret = vault_pki.read_issuer("testissuer")
    assert "http://crl.example.com/ca.crl" in ret["crl_distribution_points"]
    assert "http://aia.example.com/ca.list" in ret["issuing_certificates"]
    assert "http://ocsp.example.com" in ret["ocsp_servers"]


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer_crl(vault_pki):
    ret_complete = vault_pki.read_issuer_crl("testissuer")

    crl_complete = x509.load_pem_x509_crl(ret_complete.encode())
    assert crl_complete.issuer.rfc4514_string() == "CN=Test Issuer CA"
    ret_delta = vault_pki.read_issuer_crl("testissuer", delta=True)
    crl_delta = x509.load_pem_x509_crl(ret_delta.encode())
    assert crl_delta.issuer.rfc4514_string() == "CN=Test Issuer CA"
    assert ret_delta != ret_complete


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_revoke_certificate(vault_pki, private_key):
    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
    )
    assert "certificate" in ret
    certificate = load_cert(ret["certificate"])

    serial = dec2hex(certificate.serial_number)

    ret = vault_pki.revoke_certificate(serial=serial)
    assert ret

    revoked_certs = [serial.upper() for serial in vault_pki.list_revoked_certificates()]
    assert serial in revoked_certs


@pytest.mark.usefixtures("issuers_setup")
def test_get_default_issuer(vault_pki):
    before = vault_pki.get_default_issuer()
    assert before

    # Now, delete default issuer
    vault_pki.delete_issuer(before)

    after = vault_pki.get_default_issuer()
    assert after is None


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.parametrize("issuers_setup", [["testissuer", "testissuer2"]], indirect=True)
def test_set_default_issuer(vault_pki):
    before = vault_pki.get_default_issuer()

    assert before
    ret = vault_pki.set_default_issuer(name="testissuer2")
    assert ret

    after = vault_pki.get_default_issuer()
    assert after != before


@pytest.mark.usefixtures("generated_root")
def test_generate_root(vault_pki):
    ret = vault_pki.list_issuers()
    assert ret == []

    ret = vault_pki.generate_root(
        common_name="generated root",
        issuer_name="generated-root",
    )

    assert "certificate" in ret

    certificate = load_cert(ret["certificate"])
    assert certificate.subject.rfc4514_string() == "CN=generated root"

    ret = vault_pki.list_issuers()
    assert len(ret) == 1


@pytest.mark.usefixtures("generated_root")
def test_generate_root_exported(vault_pki):
    ret = vault_pki.list_issuers()
    assert ret == []

    ret = vault_pki.generate_root(
        common_name="generated root",
        issuer_name="generated-root",
        type="exported",
    )

    assert "certificate" in ret
    assert "private_key" in ret


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_list_certificates(vault_pki, private_key):
    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
    )
    assert "certificate" in ret
    certificate = load_cert(ret["certificate"])

    serial = dec2hex(certificate.serial_number)

    all_certs = [serial.upper() for serial in vault_pki.list_certificates()]

    assert serial in all_certs


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_read_certificate(vault_pki, private_key):
    ret = vault_pki.sign_certificate(
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
    )
    assert "certificate" in ret

    signed_certificate = load_cert(ret["certificate"])
    serial = dec2hex(signed_certificate.serial_number)
    ret = vault_pki.read_certificate(serial)
    read_certificate = load_cert(ret)
    assert read_certificate.serial_number == signed_certificate.serial_number
