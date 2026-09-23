import copy
import logging
import os
import shutil
from pathlib import Path

import pytest
import salt.utils.path
import salt.utils.platform
from pytestshellutils.utils import ports
from saltfactories.utils import random_string

from saltext.vault import PACKAGE_ROOT
from tests.common import DEFAULT_ROOT_TOKEN
from tests.common import SALT_VERSION
from tests.common import PatchedEnviron
from tests.common.containers import CONTAINER_TARGETS
from tests.common.containers import ContainerImage
from tests.common.containers import VaultContainer
from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_write_policy_file
from tests.support.vault import vault_write_secret

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

# Hooks whose changes should not require a full test run live in this
# plugin module instead of this conftest (which triggers one when changed).
pytest_plugins = ("tests.support.pytest_hooks",)


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
                "token": DEFAULT_ROOT_TOKEN,
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
                "token": DEFAULT_ROOT_TOKEN,
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
    return SALT_VERSION


@pytest.fixture(scope="session")
def vault_port():
    return ports.get_unused_localhost_port()


@pytest.fixture(scope="session")
def vault_environ(vault_port):
    with PatchedEnviron(VAULT_ADDR=f"http://127.0.0.1:{vault_port}"):
        yield


@pytest.fixture(scope="session")
def vault_plugins(tmp_path_factory):
    vault_plugin_path = tmp_path_factory.mktemp("vault-plugins")
    # The container process runs unprivileged (e.g. uid 100) and must be able
    # to lstat plugin files in this bind-mounted dir.
    vault_plugin_path.chmod(0o755)
    try:
        yield vault_plugin_path
    finally:
        shutil.rmtree(str(vault_plugin_path), ignore_errors=True)


@pytest.fixture(scope="session")
def vault_config():
    return {"plugin_directory": "/mnt/plugins"}


@pytest.fixture(
    scope="session",
    params=CONTAINER_TARGETS,
)
def container(
    request, salt_factories, vault_port, vault_environ, vault_plugins, vault_config
):  # pylint: disable=unused-argument
    if isinstance(request.param, ContainerImage):
        image = request.param
    else:
        image = ContainerImage.from_str(request.param)

    vault_setup = VaultContainer(
        image=image,
        port=vault_port,
        plugins=vault_plugins,
        root_token=DEFAULT_ROOT_TOKEN,
        vault_config=vault_config,
    )
    container = vault_setup.configure(salt_factories)
    with container.started():
        yield vault_setup


@pytest.fixture(scope="module", params=((("kv", "secret", "-version=2"),),))
def secret_mounts(request, container):  # pylint: disable=unused-argument
    mounts = []

    def _cleanup():
        for path in mounts:
            vault_disable_secret_engine(path)

    params = request.param
    if isinstance(params, str):
        params = [params]
    try:
        for mount in params:
            if isinstance(mount, str):
                engine, path, options = mount, mount, ()
            else:
                try:
                    engine, path, options = mount[0], mount[1], mount[2]
                except IndexError:
                    engine, path, options = mount[0], mount[1], ()
            vault_enable_secret_engine(engine, path=path, options=options)
            mounts.append(path)
    except Exception:  # pylint: disable=broad-except
        _cleanup()
    try:
        yield tuple(mounts)
    finally:
        _cleanup()


@pytest.fixture(scope="module")
def pillar_defaults():
    """
    When using the pillar_base fixture, set pillar values for the default minion.
    Expects a mapping of sls file name (without .sls suffix) to data it should
    contain. The top file is created automatically, if not set.

    By default, ensures the pillar is refreshed on the minion.
    Return a tuple of False, {...} to not refresh it.
    """
    return {}


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    """
    Set vault KV secrets by requiring the `vault_secrets` fixture and redefining
    this fixture inside your module.
    """
    return {}


@pytest.fixture(scope="module")
def vault_secrets(
    secret_mounts, vault_secrets_defaults, container
):  # pylint: disable=unused-argument
    secrets_data = copy.deepcopy(vault_secrets_defaults)
    for path, data in secrets_data.items():
        vault_write_secret(path, **data)
    # Don't need to cleanup, mounts are removed


@pytest.fixture(scope="module")
def master_approle_mount(request, container):  # pylint: disable=unused-argument
    mount = getattr(request, "param", "salt-minions")
    assert vault_enable_auth_method("approle", mount)
    try:
        yield mount
    finally:
        assert vault_disable_auth_method(mount)


@pytest.fixture(scope="module", params=[()])
def vault_policies(container, master_config_overrides, request):  # pylint: disable=unused-argument
    policies = request.param
    if not policies:
        policies = [
            policy
            for policy in master_config_overrides.get("vault", {})
            .get("policies", {})
            .get("assign", ["salt_minion"])
            if "{" not in policy
        ]
    elif isinstance(policies, str):
        policies = [policies]
    else:
        policies = list(policies)
    for policy_file in policies:
        vault_write_policy_file(policy_file)

    try:
        yield tuple(policies)
    finally:
        for policy_file in policies:
            vault_delete_policy(policy_file)


@pytest.fixture(scope="session")
def container_host_ref():
    # For Podman, there is `host.containers.internal`, which works even rootless.
    # This env var is set by nox.
    # `host.docker.internal` exists, but does not work in CI for some reason.
    # There, return the default IP address of the host on the default network (hardcoded).
    return os.environ.get("CONTAINER_HOST_REF", "172.17.0.1")


def _mounts_id(val):
    if isinstance(val, str):
        val = (val,)
    return ",".join(mount if isinstance(mount, str) else mount[1] for mount in val)


def _policies_id(val):
    if not val:
        return "dflt"
    if isinstance(val, str):
        return val
    return ",".join(val)


def pytest_make_parametrize_id(config, val, argname):  # pylint: disable=unused-argument
    if argname == "container":
        image = val if isinstance(val, ContainerImage) else ContainerImage.from_str(val)
        return f"cnt={image.display.replace('openbao', 'bao')}"
    if argname == "mysql_container":
        return f"mysql={val}"
    if argname == "secret_mounts":
        return f"mnt={_mounts_id(val)}"
    if argname == "vault_policies":
        return f"pol={_policies_id(val)}"
    if argname == "testmode":
        return f"mode={'test' if val else 'apply'}"
    if argname == "roles_setup":
        # A sequence of role fixture names or a mapping of name -> arg overrides
        return f"roles={','.join(val)}"
    if isinstance(val, bool) or val is None:
        return f"{argname.lstrip('_')}={val}"
    return None
