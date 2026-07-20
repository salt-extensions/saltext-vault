import pytest
from saltfactories.utils import random_string

from saltext.vault.utils import vault
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
]


@pytest.fixture
def fresh_auth_mount():
    name = random_string("fresh-mount", uppercase=False)
    vault_enable_auth_method("approle", name)
    try:
        yield name
    finally:
        vault_disable_auth_method(name)


@pytest.fixture
def approle_api(minion_opts):
    return vault.get_approle_api(minion_opts, {}, force_local=True)


def test_approle_api_list_empty_mount(approle_api, fresh_auth_mount):
    assert approle_api.list_approles(mount=fresh_auth_mount) == []
