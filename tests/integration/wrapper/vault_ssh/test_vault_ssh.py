import pytest

from tests.common import CliFuncProxy
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_ssh import clean_ssh_issuer
from tests.common.fixtures.vault_ssh import temp_rolename
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

pytestmark = genmarks(internal_logic_only=True, mounts="ssh", policies=True)


@pytest.fixture
def vault_ssh(salt_ssh_cli, secret_mounts):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault_ssh
