import logging

import pytest
from saltfactories.utils import random_string

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_secrets"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_defaults(vault_port):
    # Need to override the config defaults, otherwise the old config is merged on top of the new one,
    # which defeats the purpose of these tests.
    return {
        "peer_run": {
            ".*": [
                "vault.generate_token",
            ]
        },
        "sdbvault": {
            "driver": "vault",
        },
        "vault": {
            "auth": {
                "allow_minion_override": True,
                "token": "testsecret",
                "token_backend": "file",
                "ttl": 90,
                "uses": 3,
            },
            "policies": [
                "salt_minion",
                "salt_minion_{minion}",
            ],
            "url": f"http://127.0.0.1:{vault_port}",
        },
    }


@pytest.mark.usefixtures("conn_cache_absent")
def test_minion_can_authenticate(salt_call_cli, caplog):
    """
    Test that the minion can authenticate, even if the master peer_run
    configuration has not been updated.
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
    assert "does the peer runner publish configuration include `vault.get_config`" in caplog.text
    assert "Peer runner return was empty." not in caplog.text
    assert "Falling back to vault.generate_token." in caplog.text
    assert "Detected minion fallback to old vault.generate_token peer run function" in caplog.text


@pytest.mark.usefixtures("conn_cache_absent")
def test_token_is_configured_as_expected(salt_call_cli, minion):
    """
    Test that issued tokens have the expected parameters.
    """
    ret = salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data["data"]["explicit_max_ttl"] == 90
    assert ret.data["data"]["num_uses"] == 2  # one use is consumed by the lookup
    assert set(ret.data["data"]["policies"]) == {
        "default",
        "salt_minion",
        f"salt_minion_{minion.id}",
    }


@pytest.fixture(scope="module")
def overriding_minion(master, issue_overrides):
    assert master.is_running()
    factory = master.salt_minion_daemon(
        random_string("overriding-minion", uppercase=False),
        defaults={"open_mode": True, "grains": {}},
        overrides={"vault": issue_overrides},
    )
    with factory.started():
        # Sync All
        salt_call_cli = factory.salt_call_cli()
        ret = salt_call_cli.run("saltutil.sync_all", _timeout=120)
        assert ret.returncode == 0, ret
        yield factory


@pytest.fixture(scope="module")
def issue_overrides():
    return {"auth": {"uses": 5, "ttl": 180}}


@pytest.mark.usefixtures("conn_cache_absent")
def test_issue_param_overrides_work(overriding_minion):
    """
    Test that minion overrides of issue params work for the old configuration.
    """
    ret = overriding_minion.salt_call_cli().run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data["data"]["explicit_max_ttl"] == 180
    assert ret.data["data"]["num_uses"] == 4  # one use is consumed by the lookup
