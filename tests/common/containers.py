import json
import logging
import operator
import os
import re
import subprocess
import time
import typing
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from typing import ClassVar
from typing import Literal
from typing import TypeAlias

import pytest
from pytestshellutils.utils.processes import MatchString
from pytestshellutils.utils.processes import ProcessResult
from salt.utils.path import which
from saltfactories.utils import random_string

# Cyclic import. Don't reference attributes before mod init completion!
import tests.support.vault  # pylint: disable=cyclic-import
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

# All containers configured during this test run. When a run is aborted,
# the regular fixture/atexit cleanup regularly fails to remove the
# containers, so pytest_keyboard_interrupt force-terminates these.
_configured_containers: list["SFContainer"] = []
_run_aborted: bool = False  # pylint: disable=invalid-name


def run_aborted() -> bool:
    """
    Whether the test run was aborted (ctrl-c) and the testing containers
    have already been force-terminated.
    """
    return _run_aborted


def terminate_configured_containers():
    """
    Force cleanup of all containers configured during this test run.
    ``terminate()`` is idempotent, so any subsequent fixture teardown
    turns into a no-op.
    """
    global _run_aborted  # pylint: disable=global-statement
    _run_aborted = True
    for container in _configured_containers:
        try:
            container.terminate()
        except Exception:  # pylint: disable=broad-except
            log.warning("Failed to terminate container %s", container, exc_info=True)


# Regex for `name`, `name>=2` etc.
_SPEC_RE = re.compile(
    r"^(?P<name>[a-z][a-z0-9_-]*)\s*(?:(?P<op>>=|<=|>|<)\s*(?P<ver>\d+(?:\.\d+)*))?$"
)
# Regex for `>=2` etc.
_VERSION_SPEC_RE = re.compile(r"^(?P<op>>=|<=|>|<)?\s*(?P<ver>\d+(?:\.\d+)*)$")
_SPEC_OPS = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
}
_LOWER_BOUND_OPS = (">=", ">")


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = tuple(int(part) for part in version.split("."))
    # Strip trailing zeros to make tuple comparisons well-behaved
    # (e.g. min 1.15 vs tag 1.15.0 and vice versa).
    while parts and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def _parse_spec(
    spec: str, allowed_names: Sequence[str] | None
) -> tuple[str | None, str | None, tuple[int, ...] | None]:
    if allowed_names is None:
        match = isinstance(spec, str) and _VERSION_SPEC_RE.match(spec.strip())
        if not match:
            raise ValueError(f"Invalid container version spec: '{spec}'")
        return None, match["op"] or ">=", _version_tuple(match["ver"])
    match = isinstance(spec, str) and _SPEC_RE.match(spec.strip())
    if not match:
        raise ValueError(f"Invalid container spec: '{spec}'")
    if (name := match["name"]) not in allowed_names:
        raise ValueError(
            f"Unknown container name in spec '{spec}'. Allowed: {', '.join(allowed_names)}"
        )
    return name, match["op"], _version_tuple(match["ver"]) if match["ver"] else None


@dataclass(kw_only=True, slots=True)
class ContainerImage:
    name: str
    tag: str

    def matches(self, *specs: str, allowed_names: Sequence[str] | None = None) -> bool:
        """
        Whether this image satisfies at least one of the specs.

        With ``allowed_names``, specs are of the form ``<name>`` or
        ``<name><op><version>`` with ops ``>=``, ``>``, ``<=``, ``<``,
        e.g. ``vault>=1.20`` or ``openbao``. The image belongs to the
        first allowed name its image name contains.
        Without, specs are pure version constraints, where the op
        defaults to ``>=``, e.g. ``<2.1``, ``>=12.0`` or just ``12``.

        Non-numeric tags like ``latest`` are assumed to be the newest
        version: they satisfy lower bounds, but never upper bounds.
        Raises ValueError for invalid specs.
        """
        if not specs:
            raise ValueError("Need at least one container spec")
        container = None
        if allowed_names is not None:
            container = next((name for name in allowed_names if name in self.name), None)
        for spec in specs:
            spec_name, op, bound = _parse_spec(spec, allowed_names)
            if spec_name is not None and container != spec_name:
                continue
            if op is None or bound is None:
                return True
            try:
                version = _version_tuple(self.tag)
            except ValueError:
                # Non-numeric tags like `latest` are assumed to be the newest
                # version: they satisfy lower bounds, but never upper bounds.
                if op in _LOWER_BOUND_OPS:
                    return True
                continue
            if _SPEC_OPS[op](version, bound):
                return True
        return False

    @classmethod
    def from_str(cls, image: str) -> "ContainerImage":
        try:
            name, tag = image.rsplit(":", maxsplit=1)
        except ValueError:
            name, tag = image, "latest"
        if "/" not in name:
            if name.startswith("bao"):
                name = f"open{name}"
            if "openbao" in name:
                name = f"openbao/{name}"
            elif "vault" in name:
                name = f"hashicorp/{name}"
            else:
                raise RuntimeError(f"Unknown Vault container image name: {name}")
        return cls(name=name, tag=tag)

    @property
    def display(self) -> str:
        return f"{self.name.rsplit('/', maxsplit=1)[-1]}:{self.tag}"

    def __str__(self):
        return f"{self.name}:{self.tag}"


CONTAINER_TARGETS = tuple(
    ContainerImage.from_str(tgt)
    for tgt in os.environ.get(
        "TESTING_CONTAINER", "hashicorp/vault:latest,openbao/openbao:latest"
    ).split(",")
)

_container_targets_key: "pytest.StashKey[tuple[ContainerImage, ...]]" = pytest.StashKey()

CONTAINER_FLAGS = (("--vault", "hashicorp/vault"), ("--bao", "openbao/openbao"))


def container_targets(config: pytest.Config) -> tuple[ContainerImage, ...]:
    """
    The container images to test against. Derived from the --vault/--bao
    CLI flags. When absent, defaults to the TESTING_CONTAINER env var.
    """
    try:
        return config.stash[_container_targets_key]
    except KeyError:
        pass
    targets = {}
    for flag, image_name in CONTAINER_FLAGS:
        for tag in config.getoption(flag) or ():
            image = ContainerImage(name=image_name, tag=tag)
            targets[str(image)] = image
    resolved = tuple(targets.values()) or CONTAINER_TARGETS
    config.stash[_container_targets_key] = resolved
    return resolved


require_vault_bin = pytest.mark.skip_if_binaries_missing("vault")
# Only run the test against a single container image (the first target)
internal_logic_mark = pytest.mark.internal_logic_test


FIXTURE_KWARGS = {
    "vault_secrets": "secrets",
    "secret_mounts": "mounts",
    "pillar_base": "pillar",
    "vault_policies": "policies",
}

Mount: TypeAlias = str | tuple[str, str] | tuple[str, str, str]


def genmarks(
    *fixtures,
    internal_logic: bool = False,
    pillar: bool = False,
    policies: Literal[True] | str | Sequence[str] | Sequence[Sequence[str]] | None = None,
    mounts: Literal[True] | str | Sequence[Mount] | Sequence[Sequence[Mount]] | None = None,
    secrets: bool = False,
    **parametrizations,
):
    """
    Generate whole-module ``pytestmark`` contents for functional/integration tests.
    Also ensures the ``docker`` library is available, otherwise skips the tests.

    internal_logic
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
    if internal_logic:
        marks.append(internal_logic_mark)

    return marks


@dataclass(kw_only=True, slots=True)
class Container:
    # Container names that are valid in `matches` specs, e.g. to account
    # for forks. None means specs are pure version constraints.
    SPEC_NAMES: ClassVar[tuple[str, ...] | None] = None

    image: ContainerImage
    container: "SFContainer | None" = field(init=False, default=None)
    container_id: str | None = None
    port: int | None = None

    def __post_init__(self):
        if self.container_id is None:
            self.container_id = self._default_container_id()

    def matches(self, *specs: str) -> bool:
        """
        Whether the image satisfies at least one of the specs,
        e.g. ``container.matches("vault>=1.20", "openbao")``.
        See ``ContainerImage.matches`` for the spec format.
        """
        return self.image.matches(*specs, allowed_names=self.SPEC_NAMES)

    def configure(self, salt_factories: "FactoriesManager"):
        container = self._configure(salt_factories)
        container.before_start(self.before_start, container)
        container.after_start(self.after_start, container)
        container.before_terminate(self.before_terminate, container)
        container.container_start_check(self._start_check(), container)
        _configured_containers.append(container)
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
    SPEC_NAMES: ClassVar[tuple[str, ...] | None] = ("vault", "openbao")

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
            stdout=MatchString(proc.stdout),
            stderr=MatchString(proc.stderr),
            cmdline=proc.args,
            data=None,
        )
        log.debug("Failed to authenticate against vault:\n%s", ret)
        return False
