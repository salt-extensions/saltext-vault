import fnmatch
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import salt.utils.path
import salt.utils.platform
from pytestshellutils.utils import ports
from pytestshellutils.utils.processes import ProcessResult
from salt.version import __version_info__ as SALT_VERSION
from saltfactories.utils import random_string

from saltext.vault import PACKAGE_ROOT
from tests.support.files_mapping import CHANGED_FILES_MAP
from tests.support.files_mapping import REPO_ROOT
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
    credentials with the correct policies. By default, it issues
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
        random_string("master-", uppercase=False),
        defaults=master_config_defaults,
        overrides=master_config_overrides,
    )


@pytest.fixture(scope="module")
def minion_config_defaults(vault_port):  # pragma: no cover
    """
    The default minion configuration ensures that the minion works in --local
    mode and that the ``sdbvault`` SDB configuration is present.
    The vault configuration is not used when not in masterless mode
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
        random_string("minion-", uppercase=False),
        defaults=minion_config_defaults,
        overrides=minion_config_overrides,
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
        pytest.helpers.temp_file(  # type: ignore
            "ssh-known-hosts",
            "\n".join(sshd_server.get_host_keys()),
            salt_factories.tmp_root_dir,
        ) as known_hosts_file,
        pytest.helpers.temp_file(  # type: ignore
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

    with pytest.helpers.temp_file("roster", roster_contents, master.config_dir) as roster_file:  # type: ignore
        yield roster_file


@pytest.fixture(scope="session")
def sshd_config_dir(salt_factories):  # pragma: no cover
    config_dir = salt_factories.get_root_dir_for_daemon("sshd")
    try:
        yield config_dir
    finally:
        shutil.rmtree(str(config_dir), ignore_errors=True)


@pytest.fixture(scope="session")
def salt_version():
    """
    Get the version of the current Salt installation.
    Note that this only reports the version of the Salt installed in the test venv,
    which is the usual case. It does not account for integration test-specific features
    of pytest-salt-factories.
    """
    # Just report the installed version. To do this properly in integration tests,
    # we would have to use a minion and run grains.get saltversioninfo, but that requires
    # instantiating a master and minion specifically for this fixture or dropping the scope
    # to "module", which would mean it could not be used for any fixtures that need to run
    # before daemons are initialized.
    if os.environ.get("SALT_REQUIREMENT") == "salt==master":
        return (SALT_VERSION[0] + 1, 0)
    return tuple(SALT_VERSION)


@pytest.fixture(scope="session")
def vault_port():
    return ports.get_unused_localhost_port()


@pytest.fixture(scope="module")
def vault_environ(vault_port):
    with PatchedEnviron(VAULT_ADDR=f"http://127.0.0.1:{vault_port}"):
        yield


@pytest.fixture(scope="module")
def vault_plugins(tmp_path_factory):
    vault_plugin_path = tmp_path_factory.mktemp("vault-plugins")
    # The container process runs unprivileged (e.g. uid 100) and must be able
    # to lstat plugin files in this bind-mounted dir.
    vault_plugin_path.chmod(0o755)
    try:
        yield vault_plugin_path
    finally:
        shutil.rmtree(str(vault_plugin_path), ignore_errors=True)


@pytest.fixture(scope="module")
def vault_config():
    return {"plugin_directory": "/mnt/plugins"}


CONTAINER_TARGETS = os.environ.get(
    "TESTING_CONTAINER", "hashicorp/vault:latest,openbao/openbao:latest"
).split(",")


@pytest.fixture(
    scope="module",
    params=CONTAINER_TARGETS,
)
def container(
    request, salt_factories, vault_port, vault_environ, vault_plugins, vault_config
):  # pylint: disable=unused-argument
    vault_binary = salt.utils.path.which("vault")

    if "openbao" in request.param:
        env = {
            "BAO_DEV_ROOT_TOKEN_ID": "testsecret",
            "BAO_LOCAL_CONFIG": json.dumps(vault_config),
        }
    else:
        env = {
            "VAULT_DEV_ROOT_TOKEN_ID": "testsecret",
            "SKIP_SETCAP": "1",
            "VAULT_LOCAL_CONFIG": json.dumps(vault_config),
        }

    factory = salt_factories.get_container(
        "vault",
        request.param,
        check_ports=[vault_port],
        container_run_kwargs={
            "cap_add": ["IPC_LOCK"],
            "ports": {"8200/tcp": vault_port},
            "environment": env,
            "volumes": {
                str(vault_plugins): {
                    "bind": vault_config.get("plugin_directory", "/mnt/plugins"),
                    "mode": "z",
                }
            },
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
                stdout=proc.stdout,  # type: ignore
                stderr=proc.stderr,  # type: ignore
                cmdline=proc.args,
                data=None,
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
        vault_write_policy_file("approle_admin")
        vault_write_policy_file("plugin_admin")

        vault_enable_auth_method("approle", ["-path=salt-minions"])
        vault_enable_secret_engine("kv", ["-version=1", "-path=secret-v1"])
        vault_enable_secret_engine("kv", ["-version=2", "-path=salt"])
        yield request.param


@pytest.fixture(scope="session")
def container_host_ref():
    # For Podman, there is `host.containers.internal`, which works even rootless.
    # This env var is set by nox.
    # `host.docker.internal` exists, but does not work in CI for some reason.
    # There, return the default IP address of the host on the default network (hardcoded).
    return os.environ.get("CONTAINER_HOST_REF", "172.17.0.1")


def pytest_addoption(parser):
    test_selection_group = parser.getgroup("Tests Selection")
    test_selection_group.addoption(
        "--changed-files",
        dest="changed_files",
        action="store_true",
        default=False,
        help=("Only run tests that are likely to be affected by changed files"),
    )

    custom_exit = parser.getgroup("Custom Exit Code")
    custom_exit.addoption(
        "--allow-empty-runs",
        action="store_true",
        default=False,
        help="Do not exit with > 0 if no tests are collected in a run",
    )


@pytest.hookimpl(trylast=True, wrapper=True)
def pytest_collection_modifyitems(config, items):
    yield
    if not config.getoption("--changed-files"):
        return

    terminal_reporter = config.pluginmanager.getplugin("terminalreporter")
    terminal_reporter.ensure_newline()
    terminal_reporter.section("Changed Files Test Selection (--changed)", sep=">")

    if os.environ.get("CI"):
        if changed_files := os.environ.get("CHANGED_FILES"):
            try:
                changed = json.loads(changed_files)
            except json.JSONDecodeError as err:
                terminal_reporter.write_line(
                    f"Failed to parse CHANGED_FILES env var as JSON: {err}", bold=True, red=True
                )
                return
        elif not (changed_files_path := REPO_ROOT / "changed_files.txt").exists():
            terminal_reporter.write_line(
                f"CHANGED_FILES env var not set, missing file at {changed_files_path}",
                bold=True,
                red=True,
            )
            return
        else:
            try:
                changed = json.loads(changed_files_path.read_text())
            except json.JSONDecodeError as err:
                terminal_reporter.write_line(
                    f"Failed to parse file contents of {changed_files_path} as JSON: {err}",
                    bold=True,
                    red=True,
                )
                return
            except OSError as err:
                terminal_reporter.write_line(
                    f"Failed to read file contents of {changed_files_path}: {err}",
                    bold=True,
                    red=True,
                )
                return
    else:
        try:
            modified = subprocess.check_output(["git", "diff", "-z", "--name-only"], text=True)
        except subprocess.CalledProcessError as err:
            terminal_reporter.write_line(
                f"Failed to get changed files from git: {err}", bold=True, red=True
            )
            terminal_reporter.write_line(err.stderr)
            return
        try:
            created = subprocess.check_output(
                ["git", "ls-files", "-z", "--others", "--exclude-standard"], text=True
            )
        except subprocess.CalledProcessError as err:
            terminal_reporter.write_line(
                f"Failed to get unstaged files from git: {err}", bold=True, red=True
            )
            terminal_reporter.write_line(err.stderr)
            return
        changed = (modified.rstrip("\0").split("\0") if modified else []) + (
            created.rstrip("\0").split("\0") if created else []
        )

    selected_test_globs = set()

    for file in (Path(f) for f in changed):
        for ptrn, maps in CHANGED_FILES_MAP:
            if not isinstance(ptrn, str):
                if str(file) in ptrn:
                    selected_test_globs.update(maps)
                    break
            elif match := re.match(ptrn, str(file)):
                gdict = match.groupdict(default="")
                selected_test_globs.update(glob.format(**gdict) for glob in maps)
                break
        else:
            if file.suffix == ".py":
                terminal_reporter.write_line(f"No rule for changed file '{file}', skipping")
        if "*" in selected_test_globs:
            terminal_reporter.write_line(f"Changed file '{file}' needs full test run")
            return

    selected_mods = set()
    deselected_mods = set()
    selected = []
    deselected = []

    for item in items:
        itempath = Path(str(item.fspath)).resolve().relative_to(REPO_ROOT)
        if itempath in selected_mods:
            selected.append(item)
        elif itempath in deselected_mods:
            deselected.append(item)
        elif any(fnmatch.fnmatch(itempath, ptrn) for ptrn in selected_test_globs):
            selected.append(item)
            selected_mods.add(itempath)
        else:
            deselected.append(item)
            deselected_mods.add(itempath)

    items[:] = selected
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        terminal_reporter.write_line(
            f"Deselected {len(deselected_mods)} mods with {len(deselected)} items"
        )
        if os.environ.get("CI"):
            terminal_reporter.write_line("Deselected mods:", bold=True)
            for mod in sorted(deselected_mods):
                terminal_reporter.write_line(f"  * {mod}")

    else:
        terminal_reporter.write_line("Nothing was deselected")
    terminal_reporter.section("Changed Files Test Selection End (--changed)", sep="<")


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if session.config.getoption("--allow-empty-runs"):
        if exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
            session.exitstatus = pytest.ExitCode.OK
