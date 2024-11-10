import pytest

from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_write_secret


@pytest.fixture(scope="class")
def vault_testing_values(vault_container_version):  # pylint: disable=unused-argument
    vault_write_secret("secret/path/foo", success="yeehaaw")
    try:
        yield
    finally:
        vault_delete_secret("secret/path/foo")
