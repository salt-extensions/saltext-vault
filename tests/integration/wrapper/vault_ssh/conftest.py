import pytest

# pylint: disable=unused-import
from tests.functional.modules.vault_ssh.conftest import ca_priv
from tests.functional.modules.vault_ssh.conftest import ca_priv_file
from tests.functional.modules.vault_ssh.conftest import ca_pub
from tests.functional.modules.vault_ssh.conftest import ca_setup
from tests.functional.modules.vault_ssh.conftest import ec_priv
from tests.functional.modules.vault_ssh.conftest import ec_priv_file
from tests.functional.modules.vault_ssh.conftest import ec_pub
from tests.functional.modules.vault_ssh.conftest import hostrole
from tests.functional.modules.vault_ssh.conftest import iprole
from tests.functional.modules.vault_ssh.conftest import roles_setup
from tests.functional.modules.vault_ssh.conftest import userrole

# pylint: enable=unused-import

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "ssh_admin",
                ]
            },
        },
    }
