import pytest

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

pytestmark = genmarks(internal_logic=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk")


@pytest.fixture
def vault_policy(runners, container, clean_policies):  # pylint: disable=unused-argument
    return runners.vault_policy
