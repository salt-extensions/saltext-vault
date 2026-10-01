import pytest

from tests.common import gen_master_opts
from tests.common import gen_minion_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_pki import ca2_cert
from tests.common.fixtures.vault_pki import ca2_key
from tests.common.fixtures.vault_pki import ca_cert
from tests.common.fixtures.vault_pki import ca_key
from tests.common.fixtures.vault_pki import ca_sub_cert
from tests.common.fixtures.vault_pki import ca_sub_key
from tests.common.fixtures.vault_pki import clean_pki_issuers
from tests.common.fixtures.vault_pki import clean_pki_roles
from tests.common.fixtures.vault_pki import cluster_config_set
from tests.common.fixtures.vault_pki import fresh_pki_mount
from tests.common.fixtures.vault_pki import issuer_setup
from tests.common.fixtures.vault_pki import issuer_setup_additional
from tests.common.fixtures.vault_pki import issuer_setup_sub
from tests.common.fixtures.vault_pki import private_key
from tests.common.fixtures.vault_pki import roles_setup
from tests.common.fixtures.vault_pki import testrole
from tests.functional.modules.test_vault_pki import local_ca
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
from tests.functional.modules.test_vault_pki import test_import_issuer_intermediate
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
from tests.functional.modules.test_vault_pki import test_sign_intermediate
from tests.functional.modules.test_vault_pki import test_update_issuer
from tests.functional.modules.test_vault_pki import test_update_role
from tests.functional.modules.test_vault_pki import test_write_cluster_config
from tests.functional.modules.test_vault_pki import test_write_role
from tests.functional.modules.test_vault_pki import test_write_urls
from tests.functional.modules.test_vault_pki import testkey

# pylint: enable=unused-import

pytestmark = genmarks(internal_logic=True, mounts="pki")


@pytest.fixture(scope="module")
def master_config_overrides():
    # The runner loads the x509_v2 execution module on the master
    # for CSR/certificate encoding, which needs to be enabled on Salt <3008.
    return gen_master_opts(x509v2=True)


@pytest.fixture(scope="module")
def minion_config_overrides():
    # test_import_issuer_intermediate signs via the x509 execution module
    return gen_minion_opts(x509v2=True)


@pytest.fixture
def vault_pki(runners):
    return runners.vault_pki
