import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.vault_ssh.test_vault_ssh import _temp_ca
from tests.functional.modules.vault_ssh.test_vault_ssh import _temp_role
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
from tests.support.helpers import WrapperFuncProxy

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies"),
    pytest.mark.parametrize("secret_mounts", ("ssh",), indirect=True),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture
def vault_ssh(salt_ssh_cli, secret_mounts):  # pylint: disable=unused-argument
    return WrapperFuncProxy("vault_ssh", salt_ssh_cli)
