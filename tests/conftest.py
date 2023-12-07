import logging
import os
import sys

import pytest
from pytestshellutils.utils import ports
from saltext.vault import PACKAGE_ROOT
from saltfactories.utils import random_string  # pylint: disable=wrong-import-order


# Reset the root logger to its default level(because salt changed it)
logging.root.setLevel(logging.WARNING)


# This swallows all logging to stdout.
# To show select logs, set --log-cli-level=<level>
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
    handler.close()


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
