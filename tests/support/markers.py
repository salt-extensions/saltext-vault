"""
General framework for custom pytest markers.

Add marker instances to the ``markers`` registry, which takes care of the
pytest specifics (marker registration, command-line flags, skipping and
test selection). The corresponding pytest hooks must dispatch to the
registry, see ``tests/support/pytest_hooks.py``.

Custom markers can be defined by subclassing ``Marker`` and overriding
any of its hook methods::

    class CustomMarker(Marker):
        def runtest_setup(self, item): ...

    markers.add(CustomMarker("custom", desc="..."))
"""

import contextlib
import typing
from collections.abc import Callable
from dataclasses import KW_ONLY
from dataclasses import dataclass
from dataclasses import field

import pytest

from tests.common.containers import ContainerImage

if typing.TYPE_CHECKING:
    from pathlib import Path


def apply_selection(
    config: pytest.Config,
    items: list[pytest.Item],
    predicate: Callable[[pytest.Item], bool],
) -> list[pytest.Item]:
    """
    Deselect all items that don't match the predicate, notifying pytest.
    Returns the deselected items for optional custom reporting.
    """
    selected = []
    deselected = []

    for item in items:
        if predicate(item):
            selected.append(item)
        else:
            deselected.append(item)

    if deselected:
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)
    return deselected


@contextlib.contextmanager
def reporter_section(config: pytest.Config, title: str):
    """
    Wrap output in terminal reporter sections of the given title
    (opening ``>``, closing ``<``). Yields the terminal reporter.
    The closing section is skipped when an exception propagates.
    """
    reporter = config.pluginmanager.getplugin("terminalreporter")
    reporter.ensure_newline()
    reporter.section(title, sep=">")
    yield reporter
    reporter.section(title, sep="<")


@dataclass
class Marker:
    """
    Base class for custom markers. Only takes care of registering the marker.
    Override at least one of the hook methods in subclasses.

    Subclasses can additionally define a ``collection_modifyitems_family`` hook,
    which is called once per marker family before all per-instance
    ``collection_modifyitems`` hooks, receiving all registered markers
    belonging to the family. Use for selection logic that needs to
    consider several markers at once.

    A family consists of all markers whose most derived class
    overriding this hook is the same.
    See ``KindMarker`` for an example implementation. Expected signature:

    name
        The name of the mark as used in ``pytest.mark.<name>``.

    desc
        A description of the mark's purpose, shown in ``pytest --markers``.

    signature
        Optional human-readable parameter list for parametrized marks,
        e.g. ``(major, minor?)``. Only used for display purposes.
    """

    name: str
    _: KW_ONLY
    desc: str = ""
    signature: str = ""

    def configure(self, config: pytest.Config):
        """
        Called during ``pytest_configure``. Registers the mark with pytest.
        """
        config.addinivalue_line("markers", f"{self.name}{self.signature}: {self.desc}")

    def addoption(self, parser: pytest.Parser):
        """
        Called during ``pytest_addoption``. Add related command-line flags here.
        """

    def runtest_setup(self, item: pytest.Item):
        """
        Called during ``pytest_runtest_setup`` for each item, regardless
        of whether it carries this mark. Usually calls ``pytest.skip``
        conditionally.
        """

    def collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]):
        """
        Called at the very end of ``pytest_collection_modifyitems``.
        (De)select items here (remember ``config.hook.pytest_deselected``).
        """


@dataclass
class SkipMarker(Marker):
    """
    A mark that causes tests to be skipped conditionally.

    ``check`` is called with the mark's args/kwargs and should return
    a skip reason string or None if the test should run.
    """

    check: Callable[..., str | None] = field(kw_only=True)

    def runtest_setup(self, item: pytest.Item):
        marker = item.get_closest_marker(self.name)
        if marker is None:
            return
        try:
            reason = self.check(*marker.args, **marker.kwargs)
        except TypeError as err:
            raise pytest.UsageError(f"Invalid arguments to '{self.name}' marker: {err}") from None
        if reason is not None:
            pytest.skip(reason=reason)


@dataclass
class KindMarker(Marker):
    """
    A mark that categorizes tests into a kind whose execution can be
    influenced via command-line flags. Mark names are suffixed with ``_test``.

    With ``default_skip=True``, marked tests are skipped by default:

    --run-<name>
        Run marked tests in addition to the regular ones.
    --<name>-tests
        Run marked tests exclusively.

    With ``default_skip=False``, marked tests run by default:

    --no-<name>
        Deselect marked tests.
    --<name>-tests
        Run marked tests exclusively.

    Exclusive selection composes across kinds: within the same ``group``,
    multiple exclusive flags select the union of their kinds; across
    different groups, the intersection. ``group`` defaults to the kind's
    own name, i.e. each kind forms its own selection dimension.

    A ``display_name`` overrides ``name`` in --help output and skip messages.
    It defaults to ``name``, but with underscores replaced by spaces.

    Membership is determined by ``matches``, which defaults to the presence
    of the mark. Subclasses can derive it differently (see ``SuiteMarker``).
    """

    default_skip: bool = field(kw_only=True, default=False)
    group: str | None = field(kw_only=True, default=None)
    display_name: str | None = field(kw_only=True, default=None)

    def __post_init__(self):
        if self.group is None:
            self.group = self.name
        if self.display_name is None:
            self.display_name = self.name.replace("_", " ")

    def matches(self, item: pytest.Item) -> bool:
        """
        Whether an item belongs to this kind.
        """
        return item.get_closest_marker(f"{self.name}_test") is not None

    @property
    def flag_name(self) -> str:
        return self.name.replace("_", "-")

    @property
    def only_flag(self) -> str:
        return f"--{self.flag_name}-tests"

    @property
    def include_flag(self) -> str:
        if not self.default_skip:
            raise AttributeError(f"'{self.name}' tests run by default, no include flag")
        return f"--run-{self.flag_name}"

    @property
    def exclude_flag(self) -> str:
        if self.default_skip:
            raise AttributeError(f"'{self.name}' tests are skipped by default, no exclude flag")
        return f"--no-{self.flag_name}"

    def configure(self, config: pytest.Config):
        self._validate_options(config)
        if self.default_skip:
            suffix = f"Skipped unless {self.include_flag} or {self.only_flag} is passed."
        else:
            suffix = (
                f"Can be deselected with {self.exclude_flag} "
                f"or run exclusively with {self.only_flag}."
            )
        config.addinivalue_line(
            "markers", f"{self.name}_test{self.signature}: {self.desc.rstrip()} {suffix}"
        )

    def _validate_options(self, config: pytest.Config):
        if (
            not self.default_skip
            and config.getoption(self.exclude_flag)
            and config.getoption(self.only_flag)
        ):
            raise pytest.UsageError(f"Cannot combine {self.exclude_flag} with {self.only_flag}")

    def addoption(self, parser: pytest.Parser):
        group = parser.getgroup("Tests Selection")
        if self.default_skip:
            group.addoption(
                self.include_flag,
                action="store_true",
                default=False,
                help=f"Run {self.display_name} tests. Default: False",
            )
        else:
            group.addoption(
                self.exclude_flag,
                action="store_true",
                default=False,
                help=f"Deselect {self.display_name} tests",
            )
        group.addoption(
            self.only_flag,
            action="store_true",
            default=False,
            help=f"Deselect tests other than {self.display_name} tests",
        )

    def runtest_setup(self, item: pytest.Item):
        # Exclusive selection and exclusion are handled at collection time
        # by MarkerRegistry to avoid flooding reports with skipped tests.
        if not self.default_skip or not self.matches(item):
            return
        if not (item.config.getoption(self.include_flag) or item.config.getoption(self.only_flag)):
            pytest.skip(
                reason=f"{self.display_name} tests are skipped by default. Run with {self.include_flag}"
            )

    @classmethod
    def collection_modifyitems_family(
        cls, config: pytest.Config, items: list[pytest.Item], markers: list["KindMarker"]
    ):
        """
        Apply exclusive kind selection (union within a group, intersection
        across groups) and kind exclusion in a single pass.
        """
        only: dict[str, list[KindMarker]] = {}
        for marker in markers:
            if config.getoption(marker.only_flag):
                only.setdefault(marker.group or marker.name, []).append(marker)
        excluded = [
            marker
            for marker in markers
            if not marker.default_skip and config.getoption(marker.exclude_flag)
        ]
        if not only and not excluded:
            return

        # These are not handled here, but in their own runtest_setup. Still show them to avoid confusion.
        included = [
            marker
            for marker in markers
            if marker.default_skip and config.getoption(marker.include_flag)
        ]
        active_flags = ", ".join(
            [m.only_flag for group in only.values() for m in group]
            + [m.include_flag for m in included]
            + [m.exclude_flag for m in excluded]
        )

        def _predicate(item):
            return all(
                any(marker.matches(item) for marker in group) for group in only.values()
            ) and not any(marker.matches(item) for marker in excluded)

        reporter = config.pluginmanager.getplugin("terminalreporter")
        reporter.write_line(f"  Kind Tests Selection ({active_flags})", purple=True)
        apply_selection(config, items, _predicate)


@dataclass
class SuiteMarker(KindMarker):
    """
    A KindMarker whose membership is derived from the location of the
    test module below ``path`` instead of the presence of a mark.
    It is not registered as a pytest mark, only its flags are added.
    """

    path: "Path" = field(kw_only=True)

    def matches(self, item: pytest.Item) -> bool:
        return item.path.is_relative_to(self.path)

    def configure(self, config: pytest.Config):
        self._validate_options(config)


@dataclass
class ContainerMarker(Marker):
    """
    A mark declaring that a test requires a specific testing container.

    It takes one or more container specs, whose format is described in
    ``ContainerImage.matches``, e.g. ``vault>=1.15`` or ``openbao<2.1``
    (with ``allowed_names``) or ``>=12.0`` (without).
    A test runs if the container it is parametrized with satisfies at
    least one spec. Non-matching parametrizations are deselected during
    collection.

    Items without corresponding container parametrization are unaffected.

    fixture_name
        Name of the parametrized fixture providing the container.

    allowed_names
        Optional container names that are valid in specs, e.g. to account
        for forks. A parametrized image belongs to the first allowed name
        its image name contains.

    image_cls
        The class representing the fixture's parameters. Parameters are
        expected to be instances of it or strings parseable via its
        ``from_str`` classmethod. Matching is delegated to its ``matches``
        method.
    """

    fixture_name: str = field(kw_only=True)
    allowed_names: tuple[str, ...] | None = field(kw_only=True, default=None)
    image_cls: type[ContainerImage] = field(kw_only=True, default=ContainerImage)

    def collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]):
        def _predicate(item):
            marker = item.get_closest_marker(self.name)
            return marker is None or self._satisfied(item, marker)

        if deselected := apply_selection(config, items, _predicate):
            terminal_reporter = config.pluginmanager.getplugin("terminalreporter")
            terminal_reporter.write_line(
                f"  {self.name}: Deselected {len(deselected)} tests "
                "whose container requirements are unmet",
                yellow=True,
            )

    def _satisfied(self, item: pytest.Item, marker: pytest.Mark) -> bool:
        if not marker.args or marker.kwargs:
            raise pytest.UsageError(
                f"The '{self.name}' marker requires at least one "
                "positional container spec and no keyword arguments"
            )
        image = self._container_image(item)
        if image is None:
            return True
        try:
            return image.matches(*marker.args, allowed_names=self.allowed_names)
        except ValueError as err:
            raise pytest.UsageError(f"Invalid spec for '{self.name}' marker: {err}") from None

    def _container_image(self, item: pytest.Item):
        callspec = getattr(item, "callspec", None)
        if callspec is None:
            return None
        image = callspec.params.get(self.fixture_name)
        if image is None or isinstance(image, self.image_cls):
            return image
        return self.image_cls.from_str(image)


class MarkerRegistry:
    """
    Container for all custom markers, dispatching the relevant pytest
    hooks to them.
    """

    def __init__(self):
        self._markers: dict[str, Marker] = {}

    def add(self, marker: Marker):
        if marker.name in self._markers:
            raise ValueError(f"A marker named '{marker.name}' is already registered")
        self._markers[marker.name] = marker

    def configure(self, config: pytest.Config):
        for marker in self._markers.values():
            marker.configure(config)

    def addoption(self, parser: pytest.Parser):
        for marker in self._markers.values():
            marker.addoption(parser)

    def runtest_setup(self, item: pytest.Item):
        for marker in self._markers.values():
            marker.runtest_setup(item)

    def collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]):
        for family in self._families():
            family.collection_modifyitems_family(  # ty: ignore[unresolved-attribute]
                config,
                items,
                [marker for marker in self._markers.values() if isinstance(marker, family)],
            )
        for marker in self._markers.values():
            marker.collection_modifyitems(config, items)

    def _families(self) -> list[type[Marker]]:
        """
        Collect all marker families, i.e. for each registered marker the
        most derived class overriding ``collection_modifyitems_family``,
        in registration order. The base class' no-op is not dispatched.
        """
        families = []
        for marker in self._markers.values():
            for cls in type(marker).__mro__:
                if not issubclass(cls, Marker):
                    continue
                if "collection_modifyitems_family" in vars(cls):
                    if cls not in families:
                        families.append(cls)
                    break
        return families


markers = MarkerRegistry()
