import json
import logging
import os
import subprocess
import time

import pytest
import salt.utils.path
from pytestshellutils.utils import ports
from pytestshellutils.utils.processes import ProcessResult
from saltfactories.utils import random_string

from saltext.vault import PACKAGE_ROOT
from tests.support.helpers import PatchedEnviron
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_write_policy_file

# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)


# This swallows all logging to stdout.
# To show select logs, set --log-cli-level=<level>
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
    handler.close()

log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def salt_factories_config():
    """
    Return a dictionary with the keyword arguments for FactoriesManager
    """
    return {
        "code_dir": str(PACKAGE_ROOT),
        "inject_sitecustomize": "COVERAGE_PROCESS_START" in os.environ,
        "start_timeout": 120 if os.environ.get("CI") else 60,
    }


@pytest.fixture(scope="module")
def master_config_defaults(vault_port):
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
def master_config_overrides():
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {}


@pytest.fixture(scope="module")
def master(salt_factories, master_config_defaults, master_config_overrides):
    return salt_factories.salt_master_daemon(
        random_string("master-"), defaults=master_config_defaults, overrides=master_config_overrides
    )


@pytest.fixture(scope="module")
def minion_config_defaults(vault_port):
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
def minion_config_overrides():
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {}


@pytest.fixture(scope="module")
def minion(master, minion_config_defaults, minion_config_overrides):
    return master.salt_minion_daemon(
        random_string("minion-"), defaults=minion_config_defaults, overrides=minion_config_overrides
    )


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
