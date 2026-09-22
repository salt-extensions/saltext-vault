import json
import logging
import os
import subprocess
import time
import typing
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from typing import Literal
from typing import TypeAlias

import pytest
from pytestshellutils.utils.processes import ProcessResult
from salt.utils.path import which
from saltfactories.utils import random_string

import tests.support.vault
from tests.common import CONTAINER_TARGETS
from tests.common import DEFAULT_ROOT_TOKEN

if typing.TYPE_CHECKING:
    from pathlib import Path

    from saltfactories.daemons.container import Container as SFContainer
    from saltfactories.manager import FactoriesManager

try:
    from docker.errors import APIError
except ImportError:
    # This file is also imported from the root conftest, so don't hard-require docker.
    APIError = Exception  # type: ignore

log = logging.getLogger(__name__)

require_vault_bin = pytest.mark.skip_if_binaries_missing("vault")
no_container_parametrization = pytest.mark.parametrize(
    "container", (CONTAINER_TARGETS[0],), indirect=True
)


FIXTURE_KWARGS = {
    "vault_secrets": "secrets",
    "secret_mounts": "mounts",
    "pillar_base": "pillar",
    "vault_policies": "policies",
}

Mount: TypeAlias = str | tuple[str, str] | tuple[str, str, str]


def genmarks(
    *fixtures,
    internal_logic_only: bool = False,
    pillar: bool = False,
    policies: Literal[True] | str | Sequence[str] | Sequence[Sequence[str]] | None = None,
    mounts: Literal[True] | str | Sequence[Mount] | Sequence[Sequence[Mount]] | None = None,
    secrets: bool = False,
    **parametrizations,
):
    """
    Generate whole-module ``pytestmark`` contents for functional/integration tests.
    Also ensures the ``docker`` library is available, otherwise skips the tests.

    internal_logic_only
        Set this to true to avoid running the test module with multiple containers.
        Should only be used when the tests don't depend on the API (because they test internal logic only).

    pillar
        Enable the ``pillar_base`` fixture. You can then define a module-scoped ``pillar_defaults``
        fixture that gets applied. A functional-scoped ``pillar_override`` fixture additionally
        allows to override that pillar for specific tests.

    policies
        Ensure specific policies are present in Vault.
        Set this to true to auto-derive the necessary policies from the master config.
        Set this to a name or a sequence of names to ensure they are present.

    secret_mounts
        Ensure specific secret engine mounts are present.
        Set this to true to enable one KVv2 mount at ``secrets``.
        Set this to a string (e. g. ``pki``) to enable the same-named secret engine
        at its default mount location (also ``pki``).
        Can also be a sequence, where the first item is the name of the secret engine,
        the second item is the mount name, and the optional third item a string or
        sequence of strings of options to pass to the mount command.

    vault_secrets
        Ensure specific secrets are present on all KV (!) mounts defined in ``secret_mounts``.
        Define the values that should be written in a module-scoped ``vault_secrets_defaults`` fixture
        that returns a mapping of "<vault path>" to a dictionary of secret data.

    variadic args
        Pass arbitrary additional ``usefixtures``.

    variadic kwargs
        Pass arbitrary ``parametrize`` definitions. Keys are fixture names,
        values their parameters. If fixtures are not in ``usefixtures`` already,
        they are added automatically. All parametrizations are created with ``indirect=True``.
    """
    pytest.importorskip("docker")
    marks = [require_vault_bin]
    usefixtures = ["container"] + list(fixtures)
    parametrize = []

    if pillar:
        usefixtures.append("pillar_base")

    if mounts:
        usefixtures.append("secret_mounts")
        if mounts is not True:
            parametrize.append(
                pytest.mark.parametrize(
                    "secret_mounts",
                    (mounts,) if isinstance(mounts, str) else mounts,
                    indirect=True,
                )
            )

    if secrets:
        usefixtures.append("vault_secrets")

    if policies:
        usefixtures.append("vault_policies")
        if policies is not True:
            parametrize.append(
                pytest.mark.parametrize(
                    "vault_policies",
                    (policies,) if isinstance(policies, str) else policies,
                    indirect=True,
                )
            )

    for fixture, params in parametrizations.items():
        if fixture in FIXTURE_KWARGS:
            raise TypeError(f"`{fixture}` is configured via the `{FIXTURE_KWARGS[fixture]}` kwarg")
        if fixture not in usefixtures:
            usefixtures.append(fixture)
        if isinstance(params, str) or not isinstance(params, Sequence):
            params = (params,)
        parametrize.append(pytest.mark.parametrize(fixture, params, indirect=True))

    marks.append(pytest.mark.usefixtures(*usefixtures))
    marks.extend(parametrize)
    if internal_logic_only:
        marks.append(no_container_parametrization)

    return marks


@dataclass(kw_only=True, slots=True)
class ContainerImage:
    name: str
    tag: str

    @classmethod
    def from_str(cls, image: str) -> "ContainerImage":
        try:
            name, tag = image.rsplit(":", maxsplit=1)
        except ValueError:
            name, tag = image, "latest"
        return cls(name=name, tag=tag)

    def __str__(self):
        return f"{self.name}:{self.tag}"


@dataclass(kw_only=True, slots=True)
class Container:
    image: ContainerImage
    container: "SFContainer | None" = field(init=False, default=None)
    container_id: str | None = None
    port: int | None = None

    def __post_init__(self):
        if self.container_id is None:
            self.container_id = self._default_container_id()

    def configure(self, salt_factories: "FactoriesManager"):
        container = self._configure(salt_factories)
        container.before_start(self.before_start, container)
        container.after_start(self.after_start, container)
        container.before_terminate(self.before_terminate, container)
        container.container_start_check(self._start_check(), container)
        return container

    def _configure(self, salt_factories: "FactoriesManager"):
        """
        Configure a container instance based on the config represented
        by this class: ``return salt_factories.get_container(...)``.
        You must override this method in child classes.
        """
        raise NotImplementedError

    def check_status(self, container: "SFContainer"):  # pylint: disable=unused-argument
        """
        Check the status of the container.
        Called several times until it returns True or the timeout is reached.
        You should override this method in child classes.
        """
        return True

    def _default_port(self):
        """
        Return the default port of the server. Used when ``port`` is not set
        explicitly during instantiation.
        You really should override this in base classes.
        """
        raise NotImplementedError

    def _default_proto(self):
        """
        Return the default proto of the server. Used when ``port`` is not set
        explicitly during instantiation.
        """
        return "tcp"

    def before_start(self, container: "SFContainer"):
        """
        Randomize the container name before (re)starts. This is useful if the
        container has to be restarted and the old container, under the same
        name, was left running, but in a bad shape.
        """
        container.name = random_string(f"{container.name.rsplit('-', 1)[0]}-")
        container.display_name = None

    def after_start(self, container: "SFContainer"):
        """
        After the container has started, save the container instance as an
        attribute on this object and discover the host port if it has not
        been set explicitly until now.
        """
        self.container = container
        if self.port is None:
            self.port = container.get_host_port_binding(
                self._default_port(), protocol=self._default_proto(), ipv6=False
            )

    def before_terminate(self, container: "SFContainer"):  # pylint: disable=unused-argument
        """
        Before terminating the container, unset the attribute on this object.
        """
        self.container = None

    def _start_check(self):
        def _inner(timeout_at, container):
            sleeptime = 0.5
            while time.time() <= timeout_at:
                try:
                    if not container.is_running():
                        log.warning("%s is no longer running", container)
                        return False
                    if self.check_status(container):
                        break
                except APIError:  # pylint: disable=broad-except
                    log.exception("Failed to run start check")
                time.sleep(sleeptime)
                sleeptime = min(sleeptime * 2, 5)
            else:
                return False
            return True

        return _inner

    def _default_container_id(self):
        return random_string(
            "{}-{}-".format(  # pylint: disable=consider-using-f-string
                self.image.name.replace("/", "-"),
                self.image.tag,
            )
        )

    def __str__(self):
        return str(self.image)

    def __repr__(self):
        return (
            f"{type(self).__name__}(id={self.container_id}, image={self.image}, port={self.port})"
        )


@dataclass(kw_only=True, slots=True, repr=False)
class VaultContainer(Container):
    plugins: "Path | None" = None
    root_token: str = DEFAULT_ROOT_TOKEN
    vault_config: Mapping[str, typing.Any] | None = None
    _vault_binary: str = field(init=False)

    @property
    def addr(self) -> str:
        if self.port is None:
            raise RuntimeError("Container has not started yet or port has not been set somehow")
        return f"http://127.0.0.1:{self.port}"

    def is_openbao(self) -> bool:
        return "openbao" in self.image.name

    def is_latest(self) -> bool:
        return self.image.tag == "latest"

    def is_vault_latest(self) -> bool:
        return not self.is_openbao() and self.is_latest()

    def after_start(self, container: "SFContainer"):
        # super() is broken in slots dataclasses on Python < 3.12 (gh-90562),
        # and pyupgrade rewrites the explicit two-arg form back to it.
        Container.after_start(self, container)

        # Get rid of default mount so we can ensure state does not leak between test modules.
        tests.support.vault.vault_disable_secret_engine(
            "secret", vault_addr=self.addr, vault_token=self.root_token
        )

    def __post_init__(self):
        # super() is broken in slots dataclasses on Python < 3.12 (gh-90562),
        # and pyupgrade rewrites the explicit two-arg form back to it.
        Container.__post_init__(self)
        if (vault_binary := which("vault")) is None:
            raise RuntimeError("Missing `vault` binary in PATH")
        self._vault_binary = vault_binary

    def _configure(
        self,
        salt_factories: "FactoriesManager",
    ) -> "SFContainer":
        if self.is_openbao():
            env = {
                "BAO_DEV_ROOT_TOKEN_ID": self.root_token,
            }
            if self.vault_config:
                env["BAO_LOCAL_CONFIG"] = json.dumps(self.vault_config)
        else:
            env = {
                "VAULT_DEV_ROOT_TOKEN_ID": self.root_token,
                "SKIP_SETCAP": "1",
            }
            if self.vault_config:
                env["VAULT_LOCAL_CONFIG"] = json.dumps(self.vault_config)

        container_run_kwargs = {
            "cap_add": ["IPC_LOCK"],
            "ports": {"8200/tcp": self.port},
            "environment": env,
        }
        if self.plugins:
            container_run_kwargs["volumes"] = {
                str(self.plugins): {
                    "bind": (self.vault_config or {}).get("plugin_directory", "/mnt/plugins"),
                    "mode": "z",
                }
            }

        check_ports = [self.port] if self.port is not None else None
        container: "SFContainer" = salt_factories.get_container(
            self.container_id,
            str(self.image),
            check_ports=check_ports,
            container_run_kwargs=container_run_kwargs,
            pull_before_start=True,
            skip_on_pull_failure=True,
            skip_if_docker_client_not_connectable=True,
        )
        return container

    def _default_port(self) -> int:
        return 8200

    def check_status(self, container: "SFContainer"):  # pylint: disable=unused-argument
        # Override the (possibly patched) VAULT_ADDR to point at this specific
        # instance, but keep the rest of the environment - the Vault CLI
        # requires PATH/HOME for its token helper.
        env = os.environ.copy()
        env["VAULT_ADDR"] = self.addr
        env["VAULT_TOKEN"] = self.root_token
        proc = subprocess.run(
            [self._vault_binary, "token", "lookup"],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        if proc.returncode == 0:
            return True
        ret = ProcessResult(
            returncode=proc.returncode,
            stdout=proc.stdout,  # type: ignore
            stderr=proc.stderr,  # type: ignore
            cmdline=proc.args,
            data=None,
        )
        log.debug("Failed to authenticate against vault:\n%s", ret)
        return False
