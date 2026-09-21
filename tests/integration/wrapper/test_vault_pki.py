import pytest
from salt.utils.x509 import load_cert

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_pki import private_key as private_key_text
from tests.common.fixtures.vault_pki import roles_setup
from tests.functional.modules.test_vault_pki import clean_pki
from tests.functional.modules.test_vault_pki import cluster_config
from tests.functional.modules.test_vault_pki import empty_pki_mount
from tests.functional.modules.test_vault_pki import generated_root
from tests.functional.modules.test_vault_pki import issuers_setup
from tests.functional.modules.test_vault_pki import local_ca
from tests.functional.modules.test_vault_pki import root_issuer_setup
from tests.functional.modules.test_vault_pki import test_delete_issuer
from tests.functional.modules.test_vault_pki import test_delete_role
from tests.functional.modules.test_vault_pki import test_generate_intermediate
from tests.functional.modules.test_vault_pki import test_generate_intermediate_csr
from tests.functional.modules.test_vault_pki import test_generate_key
from tests.functional.modules.test_vault_pki import test_generate_root
from tests.functional.modules.test_vault_pki import test_generate_root_exported
from tests.functional.modules.test_vault_pki import test_get_default_issuer
from tests.functional.modules.test_vault_pki import test_get_issuer_id
from tests.functional.modules.test_vault_pki import test_get_key_id
from tests.functional.modules.test_vault_pki import test_import_issuer_with_private_key
from tests.functional.modules.test_vault_pki import test_issue_certificate
from tests.functional.modules.test_vault_pki import test_list_certificates
from tests.functional.modules.test_vault_pki import test_list_issuers
from tests.functional.modules.test_vault_pki import test_list_keys
from tests.functional.modules.test_vault_pki import test_list_roles
from tests.functional.modules.test_vault_pki import test_read_certificate
from tests.functional.modules.test_vault_pki import test_read_certificate_full
from tests.functional.modules.test_vault_pki import test_read_cluster_config
from tests.functional.modules.test_vault_pki import test_read_issuer
from tests.functional.modules.test_vault_pki import test_read_issuer_certificate
from tests.functional.modules.test_vault_pki import test_read_issuer_certificate_with_chain
from tests.functional.modules.test_vault_pki import test_read_issuer_crl
from tests.functional.modules.test_vault_pki import test_revoke_certificate
from tests.functional.modules.test_vault_pki import test_set_default_issuer
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_alternative_issuer
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_csr
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_der_encoding
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_private_key
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_sign_verbatim
from tests.functional.modules.test_vault_pki import test_update_issuer
from tests.functional.modules.test_vault_pki import test_update_role
from tests.functional.modules.test_vault_pki import test_write_cluster_config
from tests.functional.modules.test_vault_pki import test_write_role
from tests.functional.modules.test_vault_pki import test_write_urls
from tests.functional.modules.test_vault_pki import testissuer
from tests.functional.modules.test_vault_pki import testissuer2
from tests.functional.modules.test_vault_pki import testkey
from tests.functional.modules.test_vault_pki import testrole

# pylint: enable=unused-import
from tests.support.helpers import CliFuncProxy
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_write

pytestmark = genmarks(
    internal_logic_only=True,
    mounts="pki",
    policies=True,
    # 3.1 introduces cryptography.hazmat.primitives.serialization.pkcs7,
    # before that there is an ImportError in salt.utils.x509.
    _check_cryptography="3.1",
)


@pytest.fixture(scope="module")
def master_config_overrides(salt_version):
    opts = {
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "pki_admin",
                ]
            },
        },
    }
    if salt_version[0] < 3008:
        opts["ssh_minion_opts"] = {"features": {"x509_v2": True}}
    return opts


@pytest.fixture
def vault_pki(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    try:
        yield CliFuncProxy(salt_ssh_cli).vault_pki
    finally:
        if "testrole" in vault_list("pki/roles"):
            vault_delete("pki/roles/testrole")
            assert "testrole" not in vault_list("pki/roles")
        vault_delete("pki/issuer/test-issuer-root")


@pytest.fixture(scope="module")
def private_key(private_key_text, tmp_path_factory):
    with pytest.helpers.temp_file(  # type: ignore
        "pk.pem", private_key_text, tmp_path_factory.mktemp("pki_wrapper")
    ) as pk:
        yield str(pk)


@pytest.mark.usefixtures("clean_pki")
def test_import_issuer_intermediate(vault_pki, salt_call_cli, local_ca):
    csr_resp = vault_write(
        "pki/intermediate/generate/internal", common_name="Test Imported Intermediate CA"
    )["data"]
    with (
        pytest.helpers.temp_file(  # ty: ignore[unresolved-attribute]
            "csr", contents=csr_resp["csr"]
        ) as csr_file,
        pytest.helpers.temp_file(  # ty: ignore[unresolved-attribute]
            "signing_cert", contents=local_ca["cert"]
        ) as signing_cert_file,
        pytest.helpers.temp_file(  # ty: ignore[unresolved-attribute]
            "signing_pk", contents=local_ca["key"]
        ) as signing_key_file,
    ):
        res = salt_call_cli.run(
            "x509.create_certificate",
            csr=str(csr_file),
            signing_private_key=str(signing_key_file),
            signing_cert=str(signing_cert_file),
            CN="Test Imported Intermediate CA",
            basicConstraints="critical, CA:true",
            keyUsage="critical, cRLSign, keyCertSign",
            # Vault refuses to build CRLs for issuers without a SKI
            subjectKeyIdentifier="hash",
            authorityKeyIdentifier="keyid:always,issuer",
            days_valid=7,
        )
    assert res.returncode == 0
    assert "-----BEGIN" in res.data
    cert = res.data
    with pytest.helpers.temp_file("cert", contents=cert) as cert_file:  # type: ignore
        # File needed for wrapper test
        ret = vault_pki.import_issuer_intermediate(str(cert_file))
    assert ret["imported_issuers"]
    issuer = vault_pki.read_issuer(ret["imported_issuers"][0])
    assert issuer["key_id"] == csr_resp["key_id"]
    certificate = load_cert(issuer["certificate"])
    assert certificate.subject.rfc4514_string() == "CN=Test Imported Intermediate CA"
