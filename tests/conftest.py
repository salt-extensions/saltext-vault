import os
import sys
import json
import time
import subprocess
import logging

import pytest
import salt.config
from pytestshellutils.utils import ports
from saltext.saltext_vault import PACKAGE_ROOT
from saltfactories.utils import random_string  # pylint: disable=wrong-import-order
from tests.support.helpers import PatchedEnviron
from pytestshellutils.utils.processes import ProcessResult
from tests.support.pytest.vault import vault_write_policy_file
from tests.support.pytest.vault import vault_enable_secret_engine
from tests.support.pytest.vault import vault_enable_auth_method

log = logging.getLogger(__name__)

@pytest.fixture(scope="session")
def salt_factories_config():
    """
    Return a dictionary with the keyworkd arguments for FactoriesManager
    """
    return {
        "code_dir": str(PACKAGE_ROOT),
        "start_timeout": 120 if os.environ.get("CI") else 60,
    }


@pytest.fixture(scope="package")
def master(salt_factories):
    return salt_factories.salt_master_daemon(random_string("master-"))


@pytest.fixture(scope="package")
def minion(master):
    return master.salt_minion_daemon(random_string("minion-"))


@pytest.fixture(scope="session")
def integration_files_dir(salt_factories):
    """
    Fixture which returns the salt integration files directory path.
    Creates the directory if it does not yet exist.
    """
    dirname = salt_factories.root_dir / "integration-files"
    dirname.mkdir(exist_ok=True)
    return dirname


@pytest.fixture(scope="session")
def state_tree_root_dir(integration_files_dir):
    """
    Fixture which returns the salt state tree root directory path.
    Creates the directory if it does not yet exist.
    """
    dirname = integration_files_dir / "state-tree"
    dirname.mkdir(exist_ok=True)
    return dirname


@pytest.fixture(scope="session")
def base_env_state_tree_root_dir(state_tree_root_dir):
    """
    Fixture which returns the salt base environment state tree directory path.
    Creates the directory if it does not yet exist.
    """
    dirname = state_tree_root_dir / "base"
    dirname.mkdir(exist_ok=True)
    return dirname


@pytest.fixture
def minion_opts(tmp_path):
    """
    Default minion configuration with relative temporary paths to not require root permissions.
    """
    root_dir = tmp_path / "minion"
    opts = salt.config.DEFAULT_MINION_OPTS.copy()
    opts["__role"] = "minion"
    opts["root_dir"] = str(root_dir)
    for name in ("cachedir", "pki_dir", "sock_dir", "conf_dir"):
        dirpath = root_dir / name
        dirpath.mkdir(parents=True)
        opts[name] = str(dirpath)
    opts["log_file"] = "logs/minion.log"
    return opts


@pytest.fixture
def master_opts(tmp_path):
    """
    Default master configuration with relative temporary paths to not require root permissions.
    """
    root_dir = tmp_path / "master"
    opts = salt.config.DEFAULT_MASTER_OPTS.copy()
    opts["__role"] = "master"
    opts["root_dir"] = str(root_dir)
    for name in ("cachedir", "pki_dir", "sock_dir", "conf_dir"):
        dirpath = root_dir / name
        dirpath.mkdir(parents=True)
        opts[name] = str(dirpath)
    opts["log_file"] = "logs/master.log"
    return opts


@pytest.fixture
def perm_denied_error_log():
    if sys.platform.startswith("win32"):
        perm_denied_error_log = (
            "Unable to create directory "
            "C:\\ProgramData\\Salt Project\\Salt\\srv\\salt\\minion.  "
            "Check that the salt user has the correct permissions."
        )
    else:
        perm_denied_error_log = (
            "Unable to create directory /srv/salt/minion.  "
            "Check that the salt user has the correct permissions."
        )
    return perm_denied_error_log


@pytest.fixture(scope="session")
def vault_port():
    return ports.get_unused_localhost_port()

@pytest.fixture(scope="module")
def vault_environ(vault_port):
    with PatchedEnviron(VAULT_ADDR=f"http://127.0.0.1:{vault_port}"):
        yield


def vault_container_version_id(value):
    return f"vault=={value}"


@pytest.fixture(
    scope="module",
    params=["1.3.7", "latest"],
    ids=vault_container_version_id,
)
def vault_container_version(request, salt_factories, vault_port, vault_environ):
    vault_version = request.param
    vault_binary = salt.utils.path.which("vault")
    config = {
        "backend": {"file": {"path": "/vault/file"}},
        "default_lease_ttl": "168h",
        "max_lease_ttl": "720h",
    }

    factory = salt_factories.get_container(
        "vault",
        f"ghcr.io/saltstack/salt-ci-containers/vault:{vault_version}",
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

        if vault_version in ["latest", "1.14"]:
            vault_write_policy_file("salt_minion")
        else:
            vault_write_policy_file("salt_minion", "salt_minion_old")

        
        vault_enable_secret_engine("kv-v2")
        vault_enable_auth_method("approle", ["-path=salt-minions"])
        vault_enable_secret_engine("kv", ["-version=2", "-path=salt"])

        yield vault_version
