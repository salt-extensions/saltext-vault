import json
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
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.usefixtures("vault_container_version"),
    pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True),
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "ssh_minion_opts": {
            "features": {
                "x509_v2": True,
            },
        },
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "pki_admin",
                ]
            },
        },
    }


@pytest.fixture(scope="module")
def _check_cryptography(salt_ssh_cli):
    # Cannot use `pip.list` since it fails in the test suite as well
    # with missing `pkg_resources`.
    ret = salt_ssh_cli.run("--raw", "python3 -m pip list --format=json")
    assert ret.returncode == 0
    assert isinstance(ret.data, dict)
    res = json.loads(ret.data["stdout"])
    for pkg in res:
        if pkg["name"] == "cryptography":
            version = tuple(int(x) for x in pkg["version"].split("."))
            break
    else:
        pytest.skip("The host Python does not have cryptography")
    if version < (3, 1):
        # 3.1 introduces cryptography.hazmat.primitives.serialization.pkcs7,
        # before that there is an ImportError in salt.utils.x509.
        pytest.skip(
            "The x509_v2 modules require at least cryptography v3.1 on the host. "
            f"Installed: {'.'.join(str(x) for x in version)}"
        )
    return version


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
def private_key(tmp_path_factory):
    pk = generate_rsa_privkey(2048)
    pk_bytes = pk.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    data = pk_bytes.decode()
    with pytest.helpers.temp_file("pk.pem", data, tmp_path_factory.mktemp("pki_wrapper")) as pk:
        yield str(pk)


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


@pytest.fixture(autouse=True)
def _cleanup():
    try:
        yield
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
def test_list_roles(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.list_roles")
    assert ret.returncode == 0
    assert ret.data == ["testrole"]


@pytest.mark.usefixtures("roles_setup")
def test_delete_role(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.delete_role", "testrole")
    assert ret.returncode == 0
    assert ret.data
    assert "testrole" not in vault_list("pki/roles")


def test_write_role(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.write_role", "testrole2", ttl="360h")
    assert ret.returncode == 0
    assert ret.data is True
    assert "testrole2" in vault_list("pki/roles")


@pytest.mark.usefixtures("roles_setup")
def test_update_role(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.write_role", "testrole", ttl="4h", max_ttl="24h")
    assert ret.returncode == 0
    assert ret.data is True
    assert vault_read("pki/roles/testrole")["data"]["ttl"] == 14400  # 4 hours in seconds


@pytest.mark.usefixtures("issuers_setup")
def test_list_issuers(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    data = [info["issuer_name"] for info in ret.data.values()]
    assert set(data) == {"test-issuer-root", "testissuer"}


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.read_issuer", "testissuer")
    assert ret.returncode == 0
    assert ret.data["issuer_name"] == "testissuer"
    assert "ca_chain" in ret.data
    assert "certificate" in ret.data


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_issue_certificate(salt_ssh_cli):
    # Certificate expiration is always in UTC, so we need to compare with UTC.
    run_time = datetime.now(tz=timezone.utc)

    ret = salt_ssh_cli.run(
        "vault_pki.issue_certificate",
        role_name="testrole",
        common_name="test.example.com",
        ttl="2h",
        alt_names=["DNS:test2.example.com"],
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    certificate = load_cert(ret.data["certificate"])

    assert certificate.issuer.rfc4514_string() == "CN=Test Issuer CA"

    assert certificate.subject.rfc4514_string() == "CN=test.example.com"
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_sans = san.value.get_values_for_type(x509.DNSName)
    assert certificate.not_valid_after_utc - run_time > timedelta(hours=1)
    assert "test2.example.com" in dns_sans
    assert "test.example.com" in dns_sans


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_sign_certificate_with_private_key(salt_ssh_cli, private_key):
    # Certificate expiration is always in UTC, so we need to compare with UTC.
    run_time = datetime.now(tz=timezone.utc)

    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        alt_names=["dns:test2.example.com"],
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    certificate = load_cert(ret.data["certificate"])

    assert certificate.issuer.rfc4514_string() == "CN=Test Issuer CA"

    assert certificate.subject.rfc4514_string() == "CN=test.example.com"
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_sans = san.value.get_values_for_type(x509.DNSName)
    assert certificate.not_valid_after_utc - run_time > timedelta(hours=1)
    assert "test2.example.com" in dns_sans
    assert "test.example.com" in dns_sans


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_sign_certificate_with_sign_verbatim(salt_ssh_cli, private_key):
    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        sign_verbatim=True,
        alt_names=["dns:test2.example.com"],
        L="Boston",
        C="US",
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    certificate = load_cert(ret.data["certificate"])
    assert certificate.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)[0].value == "US"
    assert certificate.subject.get_attributes_for_oid(x509.OID_LOCALITY_NAME)[0].value == "Boston"


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("issuers_setup", [["testissuer", "testissuer2"]], indirect=True)
def test_sign_certificate_with_alternative_issuer(salt_ssh_cli, private_key):
    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
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
    assert ret.returncode == 0
    assert "certificate" in ret.data
    certificate = load_cert(ret.data["certificate"])
    assert certificate.issuer.rfc4514_string() == "CN=Test Issuer CA 2"


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_sign_certificate_with_der_encoding(salt_ssh_cli, private_key):
    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
        ttl="2h",
        encoding="der",
        alt_names=["dns:test2.example.com"],
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    _, encoding, _, _ = load_cert(ret.data["certificate"], get_encoding=True)
    assert encoding.lower() == "der"


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer_certificate(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.read_issuer_certificate", "testissuer")
    assert ret.returncode == 0

    certificate = load_cert(ret.data)
    assert certificate.subject.rfc4514_string() == "CN=Test Issuer CA"


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer_certificate_with_chain(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.read_issuer_certificate", "testissuer", include_chain=True)
    assert ret.returncode == 0

    certificate, chain = load_cert(ret.data, load_chain=True)

    assert certificate.subject.rfc4514_string() == "CN=Test Issuer CA"
    assert len(chain) == 1

    assert chain[0].subject.rfc4514_string() == "CN=Test Issuer Root CA"


@pytest.mark.usefixtures("issuers_setup")
def test_delete_issuer(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    data = [info["issuer_name"] for info in ret.data.values()]
    assert "testissuer" in data

    ret = salt_ssh_cli.run("vault_pki.delete_issuer", "testissuer")
    assert ret.returncode == 0
    assert ret.data

    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    data = [info["issuer_name"] for info in ret.data.values()]
    assert "testissuer" not in data


@pytest.mark.usefixtures("issuers_setup")
def test_delete_issuer_with_private_key(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.read_issuer", "testissuer")
    assert ret.returncode == 0
    assert ret.data["key_id"]
    private_key_id = ret.data["key_id"]

    ret = salt_ssh_cli.run("vault_pki.delete_issuer", "testissuer", include_key=True)
    assert ret.returncode == 0
    assert ret.data

    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    data = [info["issuer_name"] for info in ret.data.values()]
    assert "testissuer" not in data

    keys = vault_list("pki/keys")
    assert private_key_id not in keys


@pytest.mark.usefixtures("issuers_setup")
def test_update_issuer(salt_ssh_cli):
    ret = salt_ssh_cli.run(
        "vault_pki.update_issuer",
        "testissuer",
        aia_urls=["http://aia.example.com/ca.list"],
    )
    assert ret.returncode == 0
    assert ret.data

    # Now update OCSP endpoints.
    ret = salt_ssh_cli.run(
        "vault_pki.update_issuer",
        "testissuer",
        ocsp_servers=["http://ocsp.example.com"],
    )
    assert ret.returncode == 0

    # Now update CRL endpoints.
    ret = salt_ssh_cli.run(
        "vault_pki.update_issuer",
        "testissuer",
        crl_endpoints=["http://crl.example.com/ca.crl"],
    )
    assert ret.returncode == 0

    ret = salt_ssh_cli.run("vault_pki.read_issuer", "testissuer")
    assert ret.returncode == 0

    assert "http://crl.example.com/ca.crl" in ret.data["crl_distribution_points"]
    assert "http://aia.example.com/ca.list" in ret.data["issuing_certificates"]
    assert "http://ocsp.example.com" in ret.data["ocsp_servers"]


@pytest.mark.usefixtures("issuers_setup")
def test_read_issuer_crl(salt_ssh_cli):
    ret_complete = salt_ssh_cli.run("vault_pki.read_issuer_crl", "testissuer")
    assert ret_complete.returncode == 0

    crl_complete = x509.load_pem_x509_crl(ret_complete.data.encode())
    assert crl_complete.issuer.rfc4514_string() == "CN=Test Issuer CA"
    ret_delta = salt_ssh_cli.run("vault_pki.read_issuer_crl", "testissuer", delta=True)
    assert ret_delta.returncode == 0
    crl_delta = x509.load_pem_x509_crl(ret_delta.data.encode())
    assert crl_delta.issuer.rfc4514_string() == "CN=Test Issuer CA"
    assert ret_delta != ret_complete


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_revoke_certificate(salt_ssh_cli, private_key):
    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    certificate = load_cert(ret.data["certificate"])

    serial = dec2hex(certificate.serial_number)

    ret = salt_ssh_cli.run("vault_pki.revoke_certificate", serial=serial)
    assert ret.returncode == 0
    assert ret.data

    ret = salt_ssh_cli.run("vault_pki.list_revoked_certificates")
    assert ret.returncode == 0
    revoked_certs = [serial.upper() for serial in ret.data]
    assert serial in revoked_certs


@pytest.mark.usefixtures("issuers_setup")
def test_get_default_issuer(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.get_default_issuer")
    assert ret.returncode == 0
    before = ret.data
    assert before

    # Now, delete default issuer
    ret = salt_ssh_cli.run("vault_pki.delete_issuer", before)
    assert ret.returncode == 0

    ret = salt_ssh_cli.run("vault_pki.get_default_issuer")
    assert ret.returncode == 0
    assert ret.data is None


@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.parametrize("issuers_setup", [["testissuer", "testissuer2"]], indirect=True)
def test_set_default_issuer(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.get_default_issuer")
    assert ret.returncode == 0
    before = ret.data
    assert before

    ret = salt_ssh_cli.run("vault_pki.set_default_issuer", name="testissuer2")
    assert ret.returncode == 0
    assert ret.data

    ret = salt_ssh_cli.run("vault_pki.get_default_issuer")
    assert ret.returncode == 0
    assert ret.data != before


@pytest.mark.usefixtures("generated_root")
def test_generate_root(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    assert ret.data == []

    ret = salt_ssh_cli.run(
        "vault_pki.generate_root",
        common_name="generated root",
        issuer_name="generated-root",
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data

    certificate = load_cert(ret.data["certificate"])
    assert certificate.subject.rfc4514_string() == "CN=generated root"

    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    assert len(ret.data) == 1


@pytest.mark.usefixtures("generated_root")
def test_generate_root_exported(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault_pki.list_issuers")
    assert ret.returncode == 0
    assert ret.data == []

    ret = salt_ssh_cli.run(
        "vault_pki.generate_root",
        common_name="generated root",
        issuer_name="generated-root",
        type="exported",
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    assert "private_key" in ret.data


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_list_certificates(salt_ssh_cli, private_key):
    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    certificate = load_cert(ret.data["certificate"])

    serial = dec2hex(certificate.serial_number)
    ret = salt_ssh_cli.run("vault_pki.list_certificates")
    assert ret.returncode == 0

    all_certs = [serial.upper() for serial in ret.data]
    assert serial in all_certs


@pytest.mark.usefixtures("_check_cryptography")
@pytest.mark.usefixtures("issuers_setup")
@pytest.mark.usefixtures("roles_setup")
def test_read_certificate(salt_ssh_cli, private_key):
    ret = salt_ssh_cli.run(
        "vault_pki.sign_certificate",
        "testrole",
        common_name="test.example.com",
        private_key=private_key,
    )
    assert ret.returncode == 0
    assert "certificate" in ret.data
    signed_certificate = load_cert(ret.data["certificate"])

    serial = dec2hex(signed_certificate.serial_number)
    ret = salt_ssh_cli.run("vault_pki.read_certificate", serial)
    assert ret.returncode == 0

    read_certificate = load_cert(ret.data)
    assert read_certificate.serial_number == signed_certificate.serial_number
