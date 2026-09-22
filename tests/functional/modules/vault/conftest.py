import pytest


@pytest.fixture
def vault(modules, vault_secrets):  # pylint: disable=unused-argument
    return modules.vault
