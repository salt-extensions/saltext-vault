import pytest

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_ssh import ca_priv
from tests.common.fixtures.vault_ssh import ca_priv_file
from tests.common.fixtures.vault_ssh import ca_pub
from tests.common.fixtures.vault_ssh import ca_setup
from tests.common.fixtures.vault_ssh import clean_ssh_issuer
from tests.common.fixtures.vault_ssh import ec_priv
from tests.common.fixtures.vault_ssh import ec_priv_file
from tests.common.fixtures.vault_ssh import ec_pub
from tests.common.fixtures.vault_ssh import hostrole
from tests.common.fixtures.vault_ssh import iprole
from tests.common.fixtures.vault_ssh import roles_setup
from tests.common.fixtures.vault_ssh import temp_rolename
from tests.common.fixtures.vault_ssh import userrole
from tests.functional.modules.vault_ssh.test_vault_ssh import test_create_ca
from tests.functional.modules.vault_ssh.test_vault_ssh import test_create_ca_key_spec
from tests.functional.modules.vault_ssh.test_vault_ssh import test_create_ca_with_keys
from tests.functional.modules.vault_ssh.test_vault_ssh import test_delete_role
from tests.functional.modules.vault_ssh.test_vault_ssh import test_destroy_ca
from tests.functional.modules.vault_ssh.test_vault_ssh import test_generate_key_cert_host
from tests.functional.modules.vault_ssh.test_vault_ssh import test_generate_key_cert_user
from tests.functional.modules.vault_ssh.test_vault_ssh import test_list_roles
from tests.functional.modules.vault_ssh.test_vault_ssh import test_list_roles_ip
from tests.functional.modules.vault_ssh.test_vault_ssh import test_read_ca
from tests.functional.modules.vault_ssh.test_vault_ssh import test_read_role
from tests.functional.modules.vault_ssh.test_vault_ssh import test_sign_key_host
from tests.functional.modules.vault_ssh.test_vault_ssh import test_sign_key_user
from tests.functional.modules.vault_ssh.test_vault_ssh import test_write_role_ca
from tests.functional.modules.vault_ssh.test_vault_ssh import test_write_role_otp
from tests.functional.modules.vault_ssh.test_vault_ssh import test_zeroaddress_roles

# pylint: enable=unused-import

pytestmark = genmarks(internal_logic=True, mounts="ssh")


@pytest.fixture
def vault_ssh(runners, secret_mounts):  # pylint: disable=unused-argument
    return runners.vault_ssh
