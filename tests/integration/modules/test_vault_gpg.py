import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_gpg import _cached_bin
from tests.functional.modules.test_vault_gpg import existing_key
from tests.functional.modules.test_vault_gpg import gpg_mount
from tests.functional.modules.test_vault_gpg import gpg_plugin

# pylint: enable=unused-import

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "gpg_sign_fallback",  # this fails to sign on the general API and should use the algo-specific ones
                ],
            },
        }
    }


def test_sign_fallback(salt_call_cli, gpg_mount, existing_key):
    salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    res = salt_call_cli.run(
        "vault_gpg.sign", existing_key, "Boop", encoding="ascii-armor", mount=gpg_mount
    )
    assert res.returncode == 0
    assert res.data
    assert isinstance(res.data, str)
    assert res.data.startswith("-----BEGIN PGP SIGNATURE")
