import logging

import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "pillar_base", "secret_mounts"),
    pytest.mark.parametrize(
        "secret_mounts",
        [[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
        indirect=True,
    ),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture
def config(modules):
    return modules.config


@pytest.fixture(scope="module")
def minion_config_overrides(secret_mounts):  # pylint: disable=unused-argument
    opts = {}
    for mount in ("secret", "secret-v1"):
        # This needs to be written before the minion opts are loaded since sdb in opts is resolved during startup
        vault_write_secret(f"{mount}/config_get_test/test_config_get_opts", foo="baz")
        opts[f"test_vault_sdb_opts_{mount}"] = (
            f"sdb://sdbvault/{mount}/config_get_test/test_config_get_opts/foo"
        )
    return opts


def test_config_get_opts(config, secret_mount):
    # The minion loads sdb:// opts during startup. At this point, it's already resolved
    ret = config.get(f"test_vault_sdb_opts_{secret_mount}")
    assert ret == "baz"


@pytest.fixture(scope="module")
def pillar_defaults(secret_mounts):  # pylint: disable=unused-argument
    pillars = {}
    for mount in ("secret", "secret-v1"):
        # sdb:// from pillar is resolved during the lookup, but let's write it here anyways
        vault_write_secret(f"{mount}/config_get_test/test_config_get_pillar", foo="baz")
        pillars[f"test_vault_sdb_pillar_{mount}"] = (
            f"sdb://sdbvault/{mount}/config_get_test/test_config_get_pillar/foo"
        )

    return {"sdb_test": pillars}


def test_config_get_pillar(config, secret_mount):
    ret = config.get(f"test_vault_sdb_pillar_{secret_mount}")
    assert ret == "baz"
