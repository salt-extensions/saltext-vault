import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import salt.utils.path
import salt.utils.platform
from pytestshellutils.utils import ports
from pytestshellutils.utils.processes import ProcessResult
from saltfactories.utils import random_string

from saltext.vault import PACKAGE_ROOT
from tests.support.helpers import PatchedEnviron
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_write_policy_file

try:
    import pwd
except ImportError:  # pragma: no cover
    import salt.utils.win_functions

# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)


# This swallows all logging to stdout.
# To show select logs, set --log-cli-level=<level>
for handler in logging.root.handlers[:]:  # pragma: no cover
    logging.root.removeHandler(handler)
    handler.close()

log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def salt_factories_config():  # pragma: no cover
    """
    Return a dictionary with the keyword arguments for FactoriesManager
    """
    return {
        "code_dir": str(PACKAGE_ROOT),
        "inject_sitecustomize": "COVERAGE_PROCESS_START" in os.environ,
        "start_timeout": 120 if os.environ.get("CI") else 60,
    }


@pytest.fixture(scope="module")
def master_config_defaults(vault_port):  # pragma: no cover
    """
    This default configuration ensures the master issues authentication
    credentials with the correct policies. By default, it will issue
    tokens with an unlimited number of uses.
    """
    return {
        "peer_run": {
            ".*": [
                "vault.get_config",
                "vault.generate_new_token",
                "vault.generate_secret_id",
            ]
        },
        "sdbvault": {
            "driver": "vault",
        },
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "issue": {
                "token": {
                    "params": {
                        "num_uses": 0,
                    }
                }
            },
            "policies": {
                "assign": [
                    "salt_minion",
                ]
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
    }


@pytest.fixture(scope="module")
def master_config_overrides():  # pragma: no cover
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {}


@pytest.fixture(scope="module")
def master(salt_factories, master_config_defaults, master_config_overrides):  # pragma: no cover
    return salt_factories.salt_master_daemon(
        random_string("master-"), defaults=master_config_defaults, overrides=master_config_overrides
    )


@pytest.fixture(scope="module")
def minion_config_defaults(vault_port):  # pragma: no cover
    """
    The default minion configuration ensures that the minion works in --local
    mode and that the ``sdbvault`` SDB configuration is present.
    The vault configuration will not be used when not in masterless mode
    without overriding ``vault:config_location`` to ``local``.
    """
    return {
        "sdbvault": {
            "driver": "vault",
        },
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
    }


@pytest.fixture(scope="module")
def minion_config_overrides():  # pragma: no cover
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {}


@pytest.fixture(scope="module")
def minion(master, minion_config_defaults, minion_config_overrides):  # pragma: no cover
    return master.salt_minion_daemon(
        random_string("minion-"), defaults=minion_config_defaults, overrides=minion_config_overrides
    )


@pytest.fixture(scope="session")
def current_user():  # pragma: no cover
    """
    Get the user associated with the current process.
    """
    if salt.utils.platform.is_windows():
        return salt.utils.win_functions.get_current_user(with_domain=False)
    return pwd.getpwuid(os.getuid())[0]


@pytest.fixture(scope="module")
def sshd_server(salt_factories, sshd_config_dir):  # pragma: no cover
    sshd_config_dict = {
        "Protocol": "2",
        # Turn strict modes off so that we can operate in /tmp
        "StrictModes": "no",
        # Logging
        "SyslogFacility": "AUTH",
        "LogLevel": "INFO",
        # Authentication:
        "LoginGraceTime": "120",
        "PermitRootLogin": "without-password",
        "PubkeyAuthentication": "yes",
        # Don't read the user's ~/.rhosts and ~/.shosts files
        "IgnoreRhosts": "yes",
        "HostbasedAuthentication": "no",
        # To enable empty passwords, change to yes (NOT RECOMMENDED)
        "PermitEmptyPasswords": "no",
        # Change to yes to enable challenge-response passwords (beware issues with
        # some PAM modules and threads)
        "ChallengeResponseAuthentication": "no",
        # Change to no to disable tunnelled clear text passwords
        "PasswordAuthentication": "no",
        "X11Forwarding": "no",
        "X11DisplayOffset": "10",
        "PrintMotd": "no",
        "PrintLastLog": "yes",
        "TCPKeepAlive": "yes",
        "AcceptEnv": "LANG LC_*",
        "UsePAM": "yes",
    }
    sftp_server_paths = [
        # Common
        "/usr/lib/openssh/sftp-server",
        # CentOS Stream 9
        "/usr/libexec/openssh/sftp-server",
        # Arch Linux
        "/usr/lib/ssh/sftp-server",
        # Photon OS 5
        "/usr/libexec/sftp-server",
    ]
    sftp_server_path = None
    for path in sftp_server_paths:
        if Path(path).exists():
            sftp_server_path = path
    if sftp_server_path is None:
        pytest.fail(f"Failed to find 'sftp-server'. Searched: {sftp_server_paths}")
    else:
        sshd_config_dict["Subsystem"] = f"sftp {sftp_server_path}"
    factory = salt_factories.get_sshd_daemon(
        sshd_config_dict=sshd_config_dict,
        config_dir=sshd_config_dir,
    )
    with factory.started():
        yield factory


@pytest.fixture(scope="module")
def known_hosts_file(sshd_server, master, salt_factories):  # pragma: no cover
    with (
        pytest.helpers.temp_file(
            "ssh-known-hosts",
            "\n".join(sshd_server.get_host_keys()),
            salt_factories.tmp_root_dir,
        ) as known_hosts_file,
        pytest.helpers.temp_file(
            "master.d/ssh-known-hosts.conf",
            f"known_hosts_file: {known_hosts_file}",
            master.config_dir,
        ),
    ):
        yield known_hosts_file


@pytest.fixture(scope="module")
def salt_ssh_roster_file(
    sshd_server, master, known_hosts_file, current_user
):  # pylint: disable=unused-argument; pragma: no cover
    roster_contents = f"""
    localhost:
      host: 127.0.0.1
      port: {sshd_server.listen_port}
      user: {current_user}
    """
    if salt.utils.platform.is_darwin():
        roster_contents += "  set_path: $PATH:/usr/local/bin/\n"

    with pytest.helpers.temp_file("roster", roster_contents, master.config_dir) as roster_file:
        yield roster_file


@pytest.fixture(scope="session")
def sshd_config_dir(salt_factories):  # pragma: no cover
    config_dir = salt_factories.get_root_dir_for_daemon("sshd")
    try:
        yield config_dir
    finally:
        shutil.rmtree(str(config_dir), ignore_errors=True)


@pytest.fixture(scope="session")
def vault_port():
    return ports.get_unused_localhost_port()


@pytest.fixture(scope="module")
def vault_environ(vault_port):
    with PatchedEnviron(VAULT_ADDR=f"http://127.0.0.1:{vault_port}"):
        yield


def _vault_container_version_id(value):
    return f"vault=={value}"


@pytest.fixture(
    scope="module",
    params=["1.14.8", "latest"],
    ids=_vault_container_version_id,
)
def vault_container_version(
    request, salt_factories, vault_port, vault_environ
):  # pylint: disable=unused-argument
    vault_version = request.param
    vault_binary = salt.utils.path.which("vault")
    config = {
        "backend": {"file": {"path": "/vault/file"}},
        "default_lease_ttl": "168h",
        "max_lease_ttl": "720h",
    }

    factory = salt_factories.get_container(
        "vault",
        f"hashicorp/vault:{vault_version}",
        check_ports=[vault_port],
        container_run_kwargs={
            "ports": {"8200/tcp": vault_port},
            "environment": {
                "VAULT_DEV_ROOT_TOKEN_ID": "testsecret",
                "VAULT_LOCAL_CONFIG": json.dumps(config),
            },
            "cap_add": "IPC_LOCK",
        },
        pull_before_start=True,
        skip_on_pull_failure=True,
        skip_if_docker_client_not_connectable=True,
    )
    with factory.started() as factory:
        attempts = 0
        while attempts < 3:
            attempts += 1
            time.sleep(1)
            proc = subprocess.run(
                [vault_binary, "login", "token=testsecret"],
                check=False,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                break
            ret = ProcessResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                cmdline=proc.args,
            )
            log.debug("Failed to authenticate against vault:\n%s", ret)
            time.sleep(4)
        else:
            pytest.fail("Failed to login to vault")

        vault_write_policy_file("salt_master")
        vault_write_policy_file("salt_minion")
        vault_write_policy_file("database_admin")
        vault_write_policy_file("policy_admin")
        vault_write_policy_file("pki_admin")
        vault_write_policy_file("ssh_admin")

        vault_enable_auth_method("approle", ["-path=salt-minions"])
        vault_enable_secret_engine("kv", ["-version=1", "-path=secret-v1"])
        vault_enable_secret_engine("kv", ["-version=2", "-path=salt"])
        yield vault_version


@pytest.fixture(scope="session")
def container_host_ref():
    # For Podman, there is `host.containers.internal`, which works even rootless.
    # This env var is set by nox.
    # `host.docker.internal` exists, but does not work in CI for some reason.
    # There, return the default IP address of the host on the default network (hardcoded).
    return os.environ.get("CONTAINER_HOST_REF", "172.17.0.1")
