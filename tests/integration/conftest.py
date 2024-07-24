import pytest


@pytest.fixture(scope="module")
def master(master):
    with master.started():
        yield master


@pytest.fixture(scope="module")
def minion(minion):
    with minion.started():
        yield minion


@pytest.fixture
def salt_run_cli(master):
    return master.salt_run_cli()


@pytest.fixture
def salt_cli(master):
    return master.salt_cli()


@pytest.fixture
def salt_call_cli(minion):
    return minion.salt_call_cli()


@pytest.fixture(scope="module")
def salt_ssh_cli(
    master, salt_ssh_roster_file, sshd_config_dir, known_hosts_file
):  # pylint: disable=unused-argument
    return master.salt_ssh_cli(
        timeout=180,
        roster_file=salt_ssh_roster_file,
        target_host="localhost",
        client_key=str(sshd_config_dir / "client_key"),
    )
