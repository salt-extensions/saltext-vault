import pytest


@pytest.fixture(params=("secret", "secret-v1"))
def secret_mount(request):
    return request.param
