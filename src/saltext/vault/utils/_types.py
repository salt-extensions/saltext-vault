# pylint: skip-file
import logging
from collections.abc import Callable
from collections.abc import Mapping
from types import TracebackType
from typing import Any
from typing import Literal
from typing import TypeAlias

SaltLogLevel: TypeAlias = (
    Literal[0]
    | Literal[1]
    | Literal[5]
    | Literal[10]
    | Literal[15]
    | Literal[20]
    | Literal[30]
    | Literal[40]
    | Literal[50]
    | Literal[1000]
)


SaltLogLevelName: TypeAlias = (
    Literal["all"]
    | Literal["garbage"]
    | Literal["trace"]
    | Literal["debug"]
    | Literal["profile"]
    | Literal["info"]
    | Literal["warning"]
    | Literal["error"]
    | Literal["critical"]
    | Literal["quiet"]
)


class SaltLogger(logging.Logger):
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


SaltContext: TypeAlias = dict[str, Any]
SaltFunctions: TypeAlias = dict[str, Callable[..., Any]]
SaltGrains: TypeAlias = dict[str, Any]
SaltLow: TypeAlias = dict[str, Any]
SaltOpts: TypeAlias = dict[str, Any]
SaltRunners: TypeAlias = dict[str, Callable[..., Any]]
SaltStates: TypeAlias = dict[str, Callable[..., Any]]
