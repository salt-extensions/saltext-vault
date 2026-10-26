from collections.abc import Callable
from collections.abc import Generator
from typing import TypeAlias
from typing import TypeVar

from saltfactories.utils.functional import StateResult

from saltext.vault.utils._types import LoadedMod
from saltext.vault.utils._types import SaltLoader

__all__ = ("LoadedMod", "SaltLoader", "Yielder")

T = TypeVar("T")
Yielder: TypeAlias = Generator[T, None, None]


class LoadedStateMod(LoadedMod):
    """
    State module, wrapped by saltfactories to return an object
    that allows easier assertions against the ret dict.
    """

    def __getattr__(self, name: str) -> Callable[..., StateResult]:
        raise NotImplementedError


class SaltLoadedStates(SaltLoader):
    """
    Functional test suite state loader from saltfactories.
    Wraps the return dict of state functions for easier assertions.
    """

    def __getitem__(self, item: str) -> Callable[..., StateResult]:
        raise NotImplementedError

    def __getattr__(self, name: str) -> LoadedStateMod:
        raise NotImplementedError
