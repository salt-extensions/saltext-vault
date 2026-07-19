import pytest

from tests.support.vault import vault_delete_secret


@pytest.fixture(params=("secret", "secret-v1"))
def secret_mount(request):
    return request.param


@pytest.fixture
def _cleanup():
    try:
        yield
    finally:
        for mount in ("secret", "secret-v1"):
            vault_delete_secret(mount, metadata=True, recursive=True)
