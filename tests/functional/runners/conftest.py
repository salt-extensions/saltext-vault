import pytest


@pytest.fixture(scope="module")
def runners(master_loaders):  # pragma: no cover
    return master_loaders.runners
