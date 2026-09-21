import pytest

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_ssh import ca_priv
from tests.common.fixtures.vault_ssh import ca_priv_file
from tests.common.fixtures.vault_ssh import ca_pub
from tests.common.fixtures.vault_ssh import ca_setup
from tests.common.fixtures.vault_ssh import ec_priv
from tests.common.fixtures.vault_ssh import ec_priv_file
from tests.common.fixtures.vault_ssh import ec_pub
from tests.common.fixtures.vault_ssh import hostrole
from tests.common.fixtures.vault_ssh import iprole
from tests.common.fixtures.vault_ssh import roles_setup
from tests.common.fixtures.vault_ssh import userrole

# pylint: enable=unused-import

pytestmark = genmarks()


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
