import pytest

from tests.common.fixtures.vault import clean_kv_mount  # pylint: disable=unused-import
from tests.common.fixtures.vault import kv_mount  # pylint: disable=unused-import


@pytest.fixture
def vault(loaders, secret_mounts):  # pylint: disable=unused-argument
    return loaders.sdb.vault
