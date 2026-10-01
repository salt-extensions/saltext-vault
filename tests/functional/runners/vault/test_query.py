import pytest

from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.functional.modules.vault.test_query import test_query_post

# pylint: enable=unused-import


pytestmark = genmarks(internal_logic=True)


@pytest.fixture
def vault(modules, vault_secrets):  # pylint: disable=unused-argument
    return modules.vault


def test_get_server_config(vault, master):
    res = vault.get_server_config()
    assert "url" in res
    assert "url_alts" in res
    assert "namespace" in res
    assert "verify" in res
    for conf, val in res.items():
        default = None
        if conf == "url_alts":
            default = [master.config["vault"]["server"]["url"]]
        assert val == master.config["vault"]["server"].get(conf, default)
