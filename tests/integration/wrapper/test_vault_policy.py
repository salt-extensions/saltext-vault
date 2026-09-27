import pytest

from tests.common import CliFuncProxy
from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_policy import clean_policies
from tests.common.fixtures.vault_policy import temp_policy
from tests.common.fixtures.vault_policy import temp_policy_rules
from tests.functional.modules.test_vault_policy import test_delete
from tests.functional.modules.test_vault_policy import test_fetch
from tests.functional.modules.test_vault_policy import test_list
from tests.functional.modules.test_vault_policy import test_write

# pylint: enable=unused-import

pytestmark = genmarks(
    "clean_policies",
    internal_logic=True,
    mounts=True,
    policies=True,
)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk", policies="policy_admin")


@pytest.fixture(scope="module")
def vault_policy(salt_ssh_cli, vault_policies):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault_policy
