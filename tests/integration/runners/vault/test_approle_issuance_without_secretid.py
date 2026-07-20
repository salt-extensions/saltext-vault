import logging

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures(
        "container", "master_approle_mount", "secret_mounts", "vault_policies", "vault_secrets"
    ),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides(master_approle_mount):  # pylint: disable=unused-argument
    return {
        "vault": {
            "cache": {
                "backend": "file",
            },
            "issue": {
                "type": "approle",
                "approle": {
                    "params": {
                        "bind_secret_id": False,
                        # "at least one constraint should be enabled on the role"
                        # this should be quite secure :)
                        "token_bound_cidrs": ["0.0.0.0/0"],
                        "token_explicit_max_ttl": 1800,
                        "token_num_uses": 0,
                    }
                },
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "salt_minion_{minion}",
                ],
            },
        },
    }


@pytest.mark.usefixtures("conn_cache_absent")
def test_minion_can_authenticate(salt_call_cli, caplog):
    """
    Test that the minion can run queries against Vault.
    The master impersonating the minion is already tested in the fixture setup
    (ext_pillar).
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
    assert "Minion AppRole does not require a secret ID" not in caplog.text
