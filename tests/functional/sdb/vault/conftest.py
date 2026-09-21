import pytest

from tests.common.fixtures.vault import secret_mount  # pylint: disable=unused-import
from tests.support.vault import vault_delete_secret


@pytest.fixture
def _cleanup():
    try:
        yield
    finally:
        for mount in ("secret", "secret-v1"):
            vault_delete_secret(mount, metadata=True, recursive=True)
