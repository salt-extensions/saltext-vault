import pytest

from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_plugin import _auth_plugin
from tests.common.fixtures.vault_plugin import _db_plugin
from tests.common.fixtures.vault_plugin import _secret_plugin
from tests.common.fixtures.vault_plugin import auth_plugin
from tests.common.fixtures.vault_plugin import clean_plugins
from tests.common.fixtures.vault_plugin import db_plugin
from tests.common.fixtures.vault_plugin import plugins_pinned
from tests.common.fixtures.vault_plugin import plugins_registered
from tests.common.fixtures.vault_plugin import secret_plugin
from tests.functional.modules.test_vault_plugin import test_get_config_with_version
from tests.functional.modules.test_vault_plugin import test_get_config_without_version
from tests.functional.modules.test_vault_plugin import test_get_config_without_version_but_pin
from tests.functional.modules.test_vault_plugin import test_list
from tests.functional.modules.test_vault_plugin import test_list_detailed
from tests.functional.modules.test_vault_plugin import test_list_includes_custom_versioned
from tests.functional.modules.test_vault_plugin import test_list_pins
from tests.functional.modules.test_vault_plugin import test_list_versions
from tests.functional.modules.test_vault_plugin import test_pin
from tests.functional.modules.test_vault_plugin import test_pinned_version
from tests.functional.modules.test_vault_plugin import test_plugin_deregister
from tests.functional.modules.test_vault_plugin import test_plugin_register
from tests.functional.modules.test_vault_plugin import test_reload
from tests.functional.modules.test_vault_plugin import test_reload_mounts
from tests.functional.modules.test_vault_plugin import test_reload_named
from tests.functional.modules.test_vault_plugin import test_unpin

# pylint: enable=unused-import

pytestmark = genmarks(internal_logic=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(backend="disk")


@pytest.fixture
def vault_plugin(runners, container, clean_plugins):  # pylint: disable=unused-argument
    return runners.vault_plugin
