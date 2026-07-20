import json

import pytest
from cryptography.hazmat.primitives import serialization
from salt.utils.x509 import generate_rsa_privkey

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_pki import generated_root
from tests.functional.modules.test_vault_pki import issuers_setup
from tests.functional.modules.test_vault_pki import roles_setup
from tests.functional.modules.test_vault_pki import root_issuer_setup
from tests.functional.modules.test_vault_pki import test_delete_issuer
from tests.functional.modules.test_vault_pki import test_delete_role
from tests.functional.modules.test_vault_pki import test_generate_root
from tests.functional.modules.test_vault_pki import test_generate_root_exported
from tests.functional.modules.test_vault_pki import test_get_default_issuer
from tests.functional.modules.test_vault_pki import test_issue_certificate
from tests.functional.modules.test_vault_pki import test_list_certificates
from tests.functional.modules.test_vault_pki import test_list_issuers
from tests.functional.modules.test_vault_pki import test_list_roles
from tests.functional.modules.test_vault_pki import test_read_certificate
from tests.functional.modules.test_vault_pki import test_read_certificate_full
from tests.functional.modules.test_vault_pki import test_read_issuer
from tests.functional.modules.test_vault_pki import test_read_issuer_certificate
from tests.functional.modules.test_vault_pki import test_read_issuer_certificate_with_chain
from tests.functional.modules.test_vault_pki import test_read_issuer_crl
from tests.functional.modules.test_vault_pki import test_revoke_certificate
from tests.functional.modules.test_vault_pki import test_set_default_issuer
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_alternative_issuer
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_der_encoding
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_private_key
from tests.functional.modules.test_vault_pki import test_sign_certificate_with_sign_verbatim
from tests.functional.modules.test_vault_pki import test_update_issuer
from tests.functional.modules.test_vault_pki import test_update_role
from tests.functional.modules.test_vault_pki import test_write_role
from tests.functional.modules.test_vault_pki import testissuer
from tests.functional.modules.test_vault_pki import testissuer2
from tests.functional.modules.test_vault_pki import testrole

# pylint: enable=unused-import
from tests.support.helpers import WrapperFuncProxy
from tests.support.vault import vault_delete
from tests.support.vault import vault_list

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies"),
    pytest.mark.parametrize("secret_mounts", ("pki",), indirect=True),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


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


@pytest.fixture(scope="module", autouse=True)
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
def vault_pki(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    try:
        yield WrapperFuncProxy("vault_pki", salt_ssh_cli)
    finally:
        if "testrole" in vault_list("pki/roles"):
            vault_delete("pki/roles/testrole")
            assert "testrole" not in vault_list("pki/roles")
        vault_delete("pki/issuer/test-issuer-root")


@pytest.fixture(scope="module")
def private_key(tmp_path_factory):
    pk = generate_rsa_privkey(2048)
    pk_bytes = pk.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    data = pk_bytes.decode()
    with pytest.helpers.temp_file(  # type: ignore
        "pk.pem", data, tmp_path_factory.mktemp("pki_wrapper")
    ) as pk:
        yield str(pk)
