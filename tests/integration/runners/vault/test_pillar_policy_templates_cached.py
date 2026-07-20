import json
import logging

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "pillar_base", "secret_mounts", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "ext_pillar": [{"vault": "secret/path/foo"}],
        "vault": {
            "issue": {
                "token": {
                    "params": {
                        # otherwise the tests might fail because of
                        # cached tokens
                        "num_uses": 1,
                    },
                },
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "salt_minion_{minion}",
                    "salt_role_{pillar[roles]}",
                    "salt_unsafe_{grains[foo]}",
                    "extpillar_this_will_not_always_be_absent_{pillar[vault_sourced]}",
                ],
                "cache_time": 0,
            },
        },
        "minion_data_cache": True,
    }


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {"grains": {"foo": "bar"}}


@pytest.fixture(scope="module")
def vault_pillar_defaults(vault_policies):  # pylint: disable=unused-argument
    return {"secret/path/foo": {"vault_sourced": "fail"}}


@pytest.fixture(scope="module")
def pillar_defaults():
    return {"roles": {"roles": ["minion", "web"]}}


@pytest.fixture(autouse=True)
def minion_data_cache_outdated(
    pillar_base, salt_run_cli, master, minion, salt_version
):  # pylint: disable=unused-argument
    if salt_version[0] >= 3008:
        cbank = "pillar"
        ckey = minion.id
    else:
        cbank = f"minions/{minion.id}"
        ckey = "data"
    cached = salt_run_cli.run("cache.fetch", cbank, ckey)
    assert cached.returncode == 0
    assert cached.data
    if salt_version[0] >= 3008:
        pillar_data = cached.data
    else:
        assert "pillar" in cached.data
        assert "grains" in cached.data
        pillar_data = cached.data["pillar"]
    assert "roles" in pillar_data
    assert pillar_data["roles"] == ["minion", "web"]
    assert "vault_sourced" in pillar_data

    new_roles = {"roles": ["minion", "web", "fresh"]}
    with master.pillar_tree.base.temp_file("roles.sls", json.dumps(new_roles)):
        yield


def test_show_policies_cached_data_no_pillar_refresh(salt_run_cli, minion):
    """
    Test that pillar data from cache is used when it is available
    """
    ret = salt_run_cli.run("vault.show_policies", minion.id, expire=0)
    assert ret.data == [
        "salt_minion",
        f"salt_minion_{minion.id.lower()}",
        "salt_role_minion",
        "salt_role_web",
        "salt_unsafe_bar",
        "extpillar_this_will_not_always_be_absent_fail",
    ]


def test_show_policies_refresh_pillar(salt_run_cli, minion):
    """
    Test that pillar data is always refreshed when requested.
    """
    ret = salt_run_cli.run(
        "vault.show_policies",
        minion.id,
        refresh_pillar=True,
        expire=0,
    )
    assert ret.data == [
        "salt_minion",
        f"salt_minion_{minion.id.lower()}",
        "salt_role_minion",
        "salt_role_web",
        "salt_role_fresh",
        "salt_unsafe_bar",
    ]
