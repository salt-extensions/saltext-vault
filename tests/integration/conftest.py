import pytest


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
