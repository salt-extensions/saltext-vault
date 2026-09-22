import copy
from contextlib import ExitStack

import pytest

from tests.common import CliFuncProxy
from tests.common.helpers import _pillar_files
from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_write_secret


@pytest.fixture(scope="module")
def master(master):  # pragma: no cover
    with master.started():
        yield master


@pytest.fixture(scope="module")
def minion(minion):  # pragma: no cover
    with minion.started():
        yield minion


@pytest.fixture
def salt_run_cli(master):  # pragma: no cover
    return master.salt_run_cli()


@pytest.fixture
def salt_cli(master):  # pragma: no cover
    return master.salt_cli()


@pytest.fixture
def salt_call_cli(minion):  # pragma: no cover
    return minion.salt_call_cli()


@pytest.fixture(scope="module")
def salt_ssh_cli(
    master, salt_ssh_roster_file, sshd_config_dir, known_hosts_file
):  # pylint: disable=unused-argument; pragma: no cover
    return master.salt_ssh_cli(
        timeout=180,
        roster_file=salt_ssh_roster_file,
        target_host="localhost",
        client_key=str(sshd_config_dir / "client_key"),
    )


@pytest.fixture(scope="module")
def vault_pillar_defaults():
    """
    When using the pillar_base fixture, set secret values early,
    before the pillar is first refreshed. Ensures Vault-sourced pillars are present
    in the initial minion data cache without having to refresh it multiple times.
    """
    return {}


@pytest.fixture(scope="module")
def pillar_base(pillar_defaults, minion, master, _vault_pillar_data):
    """
    Module-scoped fixture to create pillars.
    """
    files, refresh = _pillar_files(pillar_defaults, minion.id)
    with ExitStack() as stack:
        for pillar, contents in files:
            stack.enter_context(master.pillar_tree.base.temp_file(pillar, contents))
        if refresh:
            ret = minion.salt_call_cli().run("saltutil.refresh_pillar", wait=True)
            assert ret.returncode == 0
            assert ret.data is True
        yield


@pytest.fixture
def pillar_override(master, minion, request, pillar_defaults):
    """
    Function-scoped fixture to override pillars. Restored after function has run.
    """
    files, refresh = _pillar_files(pillar_defaults, minion.id, request)
    moved = []
    try:
        with ExitStack() as stack:
            for pillar, contents in files:
                path = master.pillar_tree.base.write_path / pillar
                #
                if path.exists():
                    num = 0
                    while path.with_suffix(f".{num}").exists():
                        num += 1
                    tgt = path.with_suffix(f".{num}")
                    path.rename(tgt)
                    moved.append((path, tgt))
                stack.enter_context(master.pillar_tree.base.temp_file(pillar, contents))
            if refresh:
                ret = minion.salt_call_cli().run("saltutil.refresh_pillar", wait=True)
                assert ret.returncode == 0
                assert ret.data is True
            yield
    finally:
        for orig, bak in moved:
            bak.rename(orig)
        if refresh:
            ret = minion.salt_call_cli().run("saltutil.refresh_pillar", wait=True)
            assert ret.returncode == 0
            assert ret.data is True


@pytest.fixture(scope="module")
def _vault_pillar_data(vault_pillar_defaults, secret_mounts):  # pylint: disable=unused-argument
    pillar_data = copy.deepcopy(vault_pillar_defaults)
    for path, data in pillar_data.items():
        vault_write_secret(path, **data)
    try:
        yield
    finally:
        for path in pillar_data:
            vault_delete_secret(path, metadata=True)


@pytest.fixture(scope="module")
def modules(minion):
    """
    Facilitate fixture reuse between functional and integration tests.
    """
    return CliFuncProxy(minion.salt_call_cli())


@pytest.fixture(scope="module")
def states(minion):
    """
    Facilitate fixture reuse between functional and integration tests.
    """
    return CliFuncProxy(minion.salt_call_cli(), states=True)
