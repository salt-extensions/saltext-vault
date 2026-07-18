import logging

import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "pillar_base"),
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
                        # cached tokens (should not, because by default,
                        # the cache is valid for one session only)
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
                    "extpillar_this_should_always_be_absent_{pillar[vault_sourced]}",
                    "sdb_this_should_always_be_absent_{pillar[vault_sourced_sdb]}",
                    "exe_this_should_always_be_absent_{pillar[vault_sourced_exe]}",
                ],
                "cache_time": 0,
            },
        },
        "minion_data_cache": False,
    }


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {"grains": {"foo": "bar"}}


@pytest.fixture(scope="module")
def vault_pillar_defaults():
    return {"secret/path/foo": {"vault_sourced": "fail"}}


@pytest.fixture(scope="module")
def pillar_defaults():
    return False, {"roles": {"roles": ["minion", "web"]}}


@pytest.fixture(autouse=True)
def minion_data_cache_absent(salt_run_cli, minion, salt_version):
    if salt_version[0] >= 3008:
        cbank = "pillar"
        ckey = minion.id
    else:
        cbank = f"minions/{minion.id}"
        ckey = "data"
    cached = salt_run_cli.run("cache.fetch", cbank, ckey)
    assert cached.returncode == 0
    if cached.data:
        ret = salt_run_cli.run("cache.flush", cbank, ckey)
        assert ret.returncode == 0
    cached = salt_run_cli.run("cache.fetch", cbank, ckey)
    assert cached.returncode == 0
    assert not cached.data


def test_show_policies(salt_run_cli, minion):
    """
    Test that pillar data is refreshed correctly before rendering policies when necessary.
    This test includes the prevention of loop exceptions by the ext_pillar module
    This refresh does not include grains and pillar data targeted by these grains (unsafe anyways!).
    """
    ret = salt_run_cli.run("vault.show_policies", minion.id, expire=0)
    assert ret.data == [
        "salt_minion",
        f"salt_minion_{minion.id.lower()}",
        "salt_role_minion",
        "salt_role_web",
    ]
    assert "Pillar render error: Failed to load ext_pillar vault" not in ret.stderr


def test_show_policies_uncached_data_no_pillar_refresh(salt_run_cli, minion):
    """
    Test that the pillar is not refreshed when explicitly disabled
    """
    ret = salt_run_cli.run("vault.show_policies", minion.id, refresh_pillar=False, expire=0)
    assert ret.data == ["salt_minion", f"salt_minion_{minion.id.lower()}"]


@pytest.mark.usefixtures("pillar_override")
@pytest.mark.parametrize(
    "pillar_override",
    (
        {
            "exe_loop": {
                "vault_sourced_exe": "{{ salt['vault.read_secret']('secret/path/foo', 'vault_sourced') }}",
            }
        },
    ),
    indirect=True,
)
def test_policy_compilation_prevents_loop_for_execution_module(
    salt_run_cli,
    minion,
):
    """
    Test that the runner prevents a recursive cycle from happening
    """
    ret = salt_run_cli.run("vault.show_policies", minion.id, refresh_pillar=True, expire=0)
    assert ret.data == [
        "salt_minion",
        f"salt_minion_{minion.id.lower()}",
        "salt_role_minion",
        "salt_role_web",
    ]
    assert "Pillar render error: Rendering SLS 'exe_loop' failed" in ret.stderr
    assert "Cyclic dependency detected while refreshing pillar" in ret.stderr
    assert "RecursionError" not in ret.stderr


@pytest.mark.usefixtures("pillar_override")
@pytest.mark.parametrize(
    "pillar_override",
    (
        {
            "sdb_loop": {
                "vault_sourced_sdb": "{{ salt['sdb.get']('sdb://sdbvault/secret/path/foo/vault_sourced') }}",
            }
        },
    ),
    indirect=True,
)
def test_policy_compilation_prevents_loop_for_sdb_module(
    salt_run_cli,
    minion,
):
    """
    Test that the runner prevents a recursive cycle from happening
    """
    ret = salt_run_cli.run("vault.show_policies", minion.id, refresh_pillar=True, expire=0)
    assert ret.data == [
        "salt_minion",
        f"salt_minion_{minion.id.lower()}",
        "salt_role_minion",
        "salt_role_web",
    ]
    assert "Pillar render error: Rendering SLS 'sdb_loop' failed" in ret.stderr
    assert "Cyclic dependency detected while refreshing pillar" in ret.stderr
    assert "RecursionError" not in ret.stderr
