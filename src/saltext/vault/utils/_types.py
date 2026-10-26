# pylint: skip-file
import logging
import os
import sys
from collections.abc import Callable
from collections.abc import Iterator
from collections.abc import Mapping
from collections.abc import MutableMapping
from collections.abc import Sequence
from types import TracebackType
from typing import TYPE_CHECKING
from typing import Any
from typing import Literal
from typing import TypeAlias
from typing import TypedDict

if not (TYPE_CHECKING or "sphinx" in sys.modules or os.environ.get("COVERAGE_FILE")):
    raise ImportError(
        "This module provides static typing helpers exclusively and must not be "
        "imported during runtime. Only import it inside an `if typing.TYPE_CHECKING:` block."
    )

from salt.fileclient import Client
from salt.loader.context import NamedLoaderContext
from salt.utils.event import NamespacedEvent

__all__ = (
    "LoadedMod",
    "SaltLoader",
    "SaltLogLevel",
    "SaltLogLevelName",
    "SaltLogger",
    "SaltResource",
    "StateRet",
    "VirtualRet",
    "__active_provider_name__",
    "__context__",
    "__env__",
    "__events__",
    "__executors__",
    "__ext_pillar__",
    "__file_client__",
    "__grains__",
    "__instance_id__",
    "__jid__",
    "__jid_event__",
    "__low__",
    "__lowstate__",
    "__minion__",
    "__opts__",
    "__pillar__",
    "__proxy__",
    "__reg__",
    "__resource__",
    "__resource_funcs__",
    "__ret__",
    "__runner__",
    "__runners__",
    "__running__",
    "__salt__",
    "__salt_system_encoding__",
    "__sdb__",
    "__serializers__",
    "__states__",
    "__tag__",
    "__thorium__",
    "__user__",
)

VirtualRet: TypeAlias = str | bool | tuple[Literal[False], str]


class StateRet(TypedDict):
    """
    Dictionary returned by all state functions.

    name
        Name of the state.

    result
        Success indicator. Boolean. if ``__opts__["test"]`` is true, can be None
        if the state cannot determine whether the result would be false or true, e.g.
        when changes need to be applied or a necessary resource is missing, but might
        have been created by another state if the run had not been executed in test mode.

    comment
        String describing the result.

    changes
        Arbitrary dict of applied changes.
    """

    name: str
    result: bool | None
    comment: str
    changes: dict[str, Any]


SaltLogLevel: TypeAlias = Literal[0, 1, 5, 10, 15, 20, 30, 40, 50, 1000]
SaltLogLevelName: TypeAlias = Literal[
    "all", "garbage", "trace", "debug", "profile", "info", "warning", "error", "critical", "quiet"
]


class SaltLogger(logging.Logger):
    """
    Adds Salt-specific log levels to ``logging.Logger`` type.

    .. code-block:: python

        # Note the type: ignore comment, which silences invalid assignment warnings.
        log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore
    """

    def garbage(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def trace(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def debug(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def profile(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def info(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def warning(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def error(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...
    def critical(
        self,
        msg,
        *args,
        exc_info: (
            None
            | bool
            | tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | BaseException
        ) = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        exc_info_on_loglevel: SaltLogLevel | SaltLogLevelName | None = None,
    ): ...


class LoadedMod:
    """
    Type representing a specific module loaded by the Salt Loader.
    """

    def __getattr__(self, name: str) -> Callable[..., Any]:
        raise NotImplementedError


class SaltLoader(NamedLoaderContext, MutableMapping[str, Callable[..., Any]]):
    """
    Type representing a dict of modules loaded by the Salt Loader.

    At runtime, these objects are ``salt.loader.context.NamedLoaderContext`` instances.
    Its untyped mapping methods take precedence in the MRO, hence redeclare them here.
    ``get`` is left untyped because ty rejects any typed override of ``Mapping.get``,
    even one mirroring typeshed's signature exactly (as of ty 0.0.84).
    """

    def __getitem__(self, item: str) -> Callable[..., Any]:
        raise NotImplementedError

    def __setitem__(self, item: str, value: Callable[..., Any]) -> None: ...

    def __delitem__(self, item: str) -> None: ...

    def __getattr__(self, name: str) -> LoadedMod:
        raise NotImplementedError

    def __iter__(self) -> Iterator[str]:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError

    def __contains__(self, item: object) -> bool:
        raise NotImplementedError


class SaltResource(TypedDict):
    """
    The ``__resource__`` dunder, describing the resource currently
    being operated on. Available in resource modules on Salt 3008.0+.
    """

    type: str
    id: str


##################################################################################
#
# Typed dunders. Import them when type checking to solve static typing warnings.
# Do not import unconditionally — this module raises ImportError at runtime!
#
#   if typing.TYPE_CHECKING:
#       from saltext.foo.utils._types import __salt__
#
# Also ensure you only import the dunders that are actually available
# in the module type you're working on.
#
##################################################################################

# 1. Global configuration/data.
#    Always defined, may be empty
# -------------------------------
__context__: dict[str, Any]
"""Context dict for caching. Preserved across all module calls of a state run."""
__grains__: dict[str, Any]
"""
Minion grains/Resource grains (Resource override modules only).
Filled in for: Execution, Pillar, Renderer, Resource connection, Resource override, Returner, SSH Wrapper, State
"""
__opts__: dict[str, Any]
"""
All master/minion configuration options. For SSH Wrappers, additionally contains ``__master_opts__``.
Always filled in.
"""
__pillar__: dict[str, Any]
"""
Pillar data for the minion.
According to docs, filled in for: Execution, Renderer, Returner, SSH Wrapper, State
Likely filled in for many more that are loaded in a minion context, e.g. Matcher, Pillar, Resource override
"""
__salt_system_encoding__: str
"""Return value of sys.getdefaultencoding()."""

# 2. Job-specific globals.
# -------------------------------
__jid__: str
"""Job ID to run under. Defined in (?): Runner, Wheel"""
__jid_event__: NamespacedEvent
"""Send events with current run's tag as prefix. WeakRef. Defined in (?): Runner, Wheel"""
__tag__: str
"""Tag to run under. Defined in (?): Runner, Wheel"""

# 3. State run-specific globals
# -------------------------------
__env__: str
"""Fileserver ``saltenv``. Defined in: State"""
__instance_id__: str
"""
State class instance ID. Can differ in the same run when parallel states are used with spawning.
Defined in: State
"""
__low__: Mapping[str, Any]
"""Currently executing low chunk (immutable). Defined in: State"""
__lowstate__: Sequence[dict[str, Any]]
"""List of all chunks in the current state run (immutable). Defined in: State"""
__running__: Mapping[str, Mapping[str, Any]]
"""
Mapping of executed state ID to ret dict.
Can contain ``salt.utils.process.Process`` instances when parallel states are executed.
(immutable)
"""

# 4. Job-specific globals, including state runs.
# -------------------------------
__user__: str
"""
In Runner/Wheel (?): User running the command
In State: Configured minion user (``__opts__["user"]``)
"""

# 5. Loaders for module types.
#    Availability and contained module type varies.
# -------------------------------
__executors__: SaltLoader
"""Loader of Executor modules. Defined in: Executor"""
__ext_pillar__: SaltLoader
"""
Loader of Pillar modules.
Defined in: Pillar
Note: This is a FilterDictWrapper, suffixing all lookups with ``.ext_pillar``.
"""
__minion__: SaltLoader
"""Loader of regular Execution modules. Defined in: Resource override modules"""
__proxy__: SaltLoader
"""
Loader of Proxy modules.
Defined in: Beacon, Engine, Execution, Executor, Proxy, Renderer, Returner, State
"""
__resource_funcs__: SaltLoader
"""Loader of Resource connection modules. Defined in: Resource override modules"""
__ret__: SaltLoader
"""Loader of Returner modules. Defined in: Proxy"""
__runner__: SaltLoader
"""Loader of Runner modules (note the singular in the dunder name). Defined in: Roster, Thorium"""
__runners__: SaltLoader
"""Loader of Runner modules (note the plural in the dunder name). Defined in: Engine, Matcher (?)"""
__salt__: SaltLoader
"""
Loader of several module types, depending on the module type referencing it.

Usually: Loader of Execution modules.
Defined in: Auth, Beacon, Engine, Execution, Executor, Pillar, Proxy, Renderer, Returner, SDB, State, Thorium

Also defined in:

* Outputter (contains Outputter modules) (Note: This is a FilterDictWrapper, suffixing all lookups with ``.output``)
* Resource override (contains Resource override modules)
* Runner (contains Runner modules)
* SSH Wrapper (contains other SSH Wrappers, unknown lookups run on the remote via SSH)
"""
__sdb__: SaltLoader
"""Loader of SDB modules. Defined in: SDB"""
__serializers__: SaltLoader
"""Loader of Serializer modules. Defined in: State"""
__states__: SaltLoader
"""Loader of State modules. Defined in: State, Renderer (during state run only)"""
__thorium__: SaltLoader
"""Loader of Thorium modules. Defined in: Thorium"""

# 6. Other global objects.
#    Availability varies.
# -------------------------------
__active_provider_name__: str
"""The current cloud provider as ``<alias>:<driver>``. Defined in: Cloud"""
__events__: list[dict[str, Any]]
"""List of events since the last loop. Defined in: Thorium"""
__file_client__: Client
"""Fileserver client. Defined in: Execution, Matcher, Renderer, State, SSH Wrapper"""
__reg__: dict[str, Any]
"""Register returner data. Defined in: Thorium"""
__resource__: SaltResource
"""
The Resource ``type``/``id`` currently being operated on.
Defined in: Resource connection and override modules
"""
