"""
Ensure that when the master (peer run) returns a wrapped response whose
creation path is unexpected (indicating potential tampering in transit),
the minion raises a ``VaultUnwrapException`` and delivers a security event
to the master.

The regular ``vault.generate_secret_id`` runner function is overridden with
a custom runner module that wraps an unrelated request, so the returned
wrapping token's creation path does not match the expected one.
"""

import re
import time
from textwrap import dedent

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures(
        "container",
        "master_approle_mount",
        "secret_mounts",
        "vault_policies",
        "vault_secrets",
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
            },
            "policies": {
                "assign": [
                    "salt_minion",
                ],
            },
        },
    }


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/path/foo": {"success": "yeehaaw"},
    }


@pytest.fixture
def fake_runner(master, salt_run_cli):
    # Custom runner module that overrides ``vault.generate_secret_id`` to return
    # a wrapped response with an unexpected creation path (``sys/wrapping/wrap``
    # instead of ``auth/<mount>/role/<name>/secret-id``).
    runner_mod = dedent("""\
    from saltext.vault.utils import vault
    from saltext.vault.runners import vault as vault_runner
    from saltext.vault.utils.functools import namespaced_function

    _g = globals()
    for attr in dir(vault_runner):
        res = getattr(vault_runner, attr)
        if callable(res) and not isinstance(res, type):
            _g[attr] = namespaced_function(res, _g)

    def generate_secret_id(minion_id, signature, impersonated_by_master=False, issue_params=None):
        client, config = vault.get_authd_client(
            __opts__, __context__, force_local=True, get_config=True
        )
        wrapped = client.post("sys/wrapping/wrap", {"foo": "bar"}, wrap="180s")
        ret = {
            "server": config["server"],
            "data": {},
            "misc_data": {"secret_id_num_uses": 0},
        }
        ret.update(wrapped.serialize_for_minion())
        return ret
    """)
    try:
        with master.state_tree.base.temp_file("_runners/vault.py", runner_mod):
            ret = salt_run_cli.run("saltutil.sync_runners")
            assert ret.returncode == 0
            assert "runners.vault" in ret.data
            yield
    finally:
        salt_run_cli.run("saltutil.sync_runners")


@pytest.fixture
def approle_synced(salt_run_cli, minion):
    ret = salt_run_cli.run("vault.sync_approles", minion.id)
    assert ret.returncode == 0
    assert ret.data is True
    return ret


@pytest.mark.usefixtures("approle_synced", "fake_runner")
def test_unwrap_error_fires_security_event(
    salt_call_cli, event_listener, master, minion, master_approle_mount, salt_version
):
    """
    When the wrapping token returned by the master has an unexpected creation
    path, building an authenticated client should fail and fire a security
    event that is delivered to the master.
    """
    start_time = time.time()
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode != 0
    assert "indicates tampering" in ret.stderr

    if salt_version[0] < 3008:
        # Look for minion fire_event event. For some reason, the event is not triggered
        # on the master/does not reach the event_listener when testing 3006
        event_pattern = (minion.id, "fire_master")
        matched = event_listener.wait_for_events([event_pattern], after_time=start_time, timeout=10)
        assert matched.found_all_events
        event = next(iter(matched.matches))
        actual_event = event.data
        assert actual_event["tag"] == "vault/security/unwrapping/error"
        payload = actual_event["data"]
    else:
        # Look for the master event we're actually expecting
        event_pattern = (master.id, "vault/security/unwrapping/error")
        matched = event_listener.wait_for_events([event_pattern], after_time=start_time, timeout=10)
        assert matched.found_all_events
        event = next(iter(matched.matches))
        payload = event.data["data"]

    assert payload["func"] == "vault.generate_secret_id"
    assert payload["actual"] == "sys/wrapping/wrap"
    assert payload["url"] == master.config["vault"]["server"]["url"]
    assert payload["namespace"] == master.config["vault"]["server"].get("namespace")
    assert payload["verify"] == master.config["vault"]["server"].get("verify")
    expected = re.escape(f"auth/{master_approle_mount}/role/{minion.id}/secret-id")
    assert expected in payload["expected"]
