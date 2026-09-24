"""
Custom pytest hook implementations, registered as a plugin
via ``pytest_plugins`` in the root conftest.

Hooks living here instead of ``tests/conftest.py`` can be changed without
triggering a full test run via ``--changed-files``. Hooks whose changes
require a full run, e.g. ``pytest_make_parametrize_id`` (test IDs must
stay consistent for test selection), belong in the root conftest.
"""

import dataclasses
import fnmatch
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from tests.common import REPO_ROOT
from tests.common import SALT_VERSION
from tests.common import TESTS_DIR_REL
from tests.common.containers import CONTAINER_FLAGS
from tests.common.containers import VaultContainer
from tests.common.containers import container_targets
from tests.common.containers import terminate_configured_containers
from tests.support.files_mapping import CHANGED_FILES_MAP
from tests.support.markers import ContainerMarker
from tests.support.markers import KindMarker
from tests.support.markers import Marker
from tests.support.markers import SkipMarker
from tests.support.markers import SuiteMarker
from tests.support.markers import apply_selection
from tests.support.markers import markers
from tests.support.markers import reporter_section


def _check_requires_salt(major, minor=0):
    if (int(major), int(minor)) > SALT_VERSION:
        return f"Requires at least Salt {major}.{minor}"
    return None


# Select specific kinds of tests, alternative to passing the path.
for _suite, _subdir in (("unit", "unit"), ("func", "functional"), ("int", "integration")):
    markers.add(
        SuiteMarker(
            _suite, group="suite", display_name=_subdir, path=REPO_ROOT / TESTS_DIR_REL / _subdir
        )
    )


markers.add(
    ContainerMarker(
        "requires_backend",
        fixture_name="container",
        allowed_names=VaultContainer.SPEC_NAMES,
        signature="(*specs)",
        desc="mark test to only run against containers matching at least one spec, "
        "e.g. 'vault>=1.15' or 'openbao'. Non-matching parametrizations are deselected.",
    )
)
markers.add(
    SkipMarker(
        "requires_salt",
        check=_check_requires_salt,
        signature="(major, minor?)",
        desc="mark test to only run on Salt versions equal to or higher than <major>.<minor or 0>",
    )
)

markers.add(
    KindMarker(
        "behavior",
        default_skip=True,
        desc="mark test as validating assumptions about external (Vault/OpenBao) server behavior.",
    )
)
markers.add(
    Marker(
        "internal_logic",
        desc="mark test to only run against a single container image (the first target), "
        "e.g. because it only exercises internal logic and does not depend on the API.",
    )
)


def pytest_configure(config):
    markers.configure(config)


def pytest_runtest_setup(item):
    markers.runtest_setup(item)


def pytest_addoption(parser):
    markers.addoption(parser)

    test_selection_group = parser.getgroup("Tests Selection")
    test_selection_group.addoption(
        "--changed-files",
        dest="changed_files",
        action="store_true",
        default=False,
        help=("Only run tests that are likely to be affected by changed files"),
    )

    test_selection_group.addoption(
        "--changed-tests",
        dest="changed_tests",
        action="store_true",
        default=False,
        help=("Only run modified test files"),
    )

    custom_exit = parser.getgroup("Custom Exit Code")
    custom_exit.addoption(
        "--allow-empty-runs",
        action="store_true",
        default=False,
        help="Do not exit with > 0 if no tests are collected in a run",
    )

    container_group = parser.getgroup("Container Selection")
    for flag, image_name in CONTAINER_FLAGS:
        container_group.addoption(
            flag,
            action="append",
            nargs="?",
            const="latest",
            metavar="TAG",
            help=f"Test against this {image_name} container image tag (repeatable). "
            "If any of these flags is passed, they replace the TESTING_CONTAINER default.",
        )


def _suppress_single_param_ids(metafunc):
    """
    Patch ``metafunc.parametrize`` to request an empty ID component for
    single-param parametrizations (unless IDs are specified explicitly).
    All later ``pytest_generate_tests`` impls (parametrize marks, fixture
    ``params`` defaults, nested conftest hooks) go through this method.
    The empty components are scrubbed after all impls have run.
    """
    parametrize = metafunc.parametrize

    def suppressing_parametrize(argnames, argvalues, indirect=False, ids=None, scope=None, **kw):
        argvalues = list(argvalues)
        if ids is None and len(argvalues) == 1:
            ids = ("",)
        return parametrize(argnames, argvalues, indirect=indirect, ids=ids, scope=scope, **kw)

    metafunc.parametrize = suppressing_parametrize


@pytest.hookimpl(tryfirst=True, wrapper=True)
def pytest_generate_tests(metafunc):
    # tryfirst + wrapper ensures the container param is recorded before
    # all others, so its `cnt=` component leads the test IDs consistently.
    # It is also exempted from single-param ID suppression on purpose:
    # the container matrix varies per invocation, unlike static params.
    if "container" in metafunc.fixturenames:
        targets = container_targets(metafunc.config)
        if metafunc.definition.get_closest_marker("internal_logic") is not None:
            targets = targets[:1]
        metafunc.parametrize("container", targets, indirect=True, scope="session")
    _suppress_single_param_ids(metafunc)
    res = yield
    # Scrub empty ID components, which hide single-param parametrizations
    # from test IDs. Note: This uses an internal API. might break!
    for i, callspec in enumerate(metafunc._calls):
        if "" in callspec._idlist:
            metafunc._calls[i] = dataclasses.replace(
                callspec, _idlist=tuple(seg for seg in callspec._idlist if seg)
            )
    return res


@pytest.hookimpl(trylast=True, wrapper=True)
def pytest_collection_modifyitems(config, items):
    yield
    run_changed_files(config, items)
    run_changed_tests(config, items)
    markers.collection_modifyitems(config, items)


def run_changed_tests(config, items):
    if not config.getoption("--changed-tests"):
        return

    def _predicate(item):
        itempath = Path(str(item.fspath)).resolve().relative_to(REPO_ROOT)
        return (
            str(itempath) in changed
            and itempath.is_relative_to(TESTS_DIR_REL)
            and itempath.suffix == ".py"
            and itempath.stem != "conftest"
        )

    with reporter_section(config, "Changed Tests Selection (--changed-tests)") as reporter:
        changed = _get_git_modified(reporter)
        if changed is None:
            return
        apply_selection(config, items, _predicate)


def _get_git_modified(terminal_reporter):
    try:
        modified = subprocess.check_output(["git", "diff", "-z", "--name-only"], text=True)
    except subprocess.CalledProcessError as err:
        if terminal_reporter:
            terminal_reporter.write_line(
                f"!! Failed to get changed files from git: {err}", bold=True, red=True
            )
            terminal_reporter.write_line(err.stderr)
        return
    try:
        created = subprocess.check_output(
            ["git", "ls-files", "-z", "--others", "--exclude-standard"], text=True
        )
    except subprocess.CalledProcessError as err:
        if terminal_reporter:
            terminal_reporter.write_line(
                f"!! Failed to get unstaged files from git: {err}", bold=True, red=True
            )
            terminal_reporter.write_line(err.stderr)
        return
    return (modified.rstrip("\0").split("\0") if modified else []) + (
        created.rstrip("\0").split("\0") if created else []
    )


def _get_ci_modified(terminal_reporter):
    if changed_files := os.environ.get("CHANGED_FILES"):
        try:
            return json.loads(changed_files)
        except json.JSONDecodeError as err:
            terminal_reporter.write_line(
                f"!! Failed to parse CHANGED_FILES env var as JSON: {err}", bold=True, red=True
            )
            return None

    if not (changed_files_path := REPO_ROOT / "changed_files.txt").exists():
        terminal_reporter.write_line(
            f"!! CHANGED_FILES env var not set, missing file at {changed_files_path}",
            bold=True,
            red=True,
        )
        return None

    try:
        return json.loads(changed_files_path.read_text())
    except json.JSONDecodeError as err:
        terminal_reporter.write_line(
            f"!! Failed to parse file contents of {changed_files_path} as JSON: {err}",
            bold=True,
            red=True,
        )
    except OSError as err:
        terminal_reporter.write_line(
            f"!! Failed to read file contents of {changed_files_path}: {err}",
            bold=True,
            red=True,
        )
    return None


def run_changed_files(config, items):
    if not config.getoption("--changed-files"):
        return

    with reporter_section(config, "Changed Files Test Selection (--changed-files)") as reporter:
        if os.environ.get("CI"):
            changed = _get_ci_modified(reporter)
        else:
            changed = _get_git_modified(reporter)

        if changed is None:
            return

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
                    reporter.write_line(f"  No rule for changed file '{file}', skipping")
            if "*" in selected_test_globs:
                reporter.write_line(f"  Changed file '{file}' needs full test run", red=True)
                return

        selected_mods = set()
        deselected_mods = set()

        def _predicate(item):
            itempath = Path(str(item.fspath)).resolve().relative_to(REPO_ROOT)
            if itempath in deselected_mods:
                return False
            if itempath not in selected_mods:
                if not any(fnmatch.fnmatch(itempath, ptrn) for ptrn in selected_test_globs):
                    deselected_mods.add(itempath)
                    return False
                selected_mods.add(itempath)
            return True

        if deselected := apply_selection(config, items, _predicate):
            reporter.write_line(
                f"  Deselected {len(deselected_mods)} mods with {len(deselected)} items",
                yellow=True,
            )
            if os.environ.get("CI"):
                reporter.write_line("  Deselected mods:", bold=True)
                for mod in sorted(deselected_mods):
                    reporter.write_line(f"    * {mod}")
        else:
            reporter.write_line("Nothing was deselected")


def pytest_keyboard_interrupt(excinfo):  # pylint: disable=unused-argument
    # On ctrl-c, the regular container cleanup (fixture finalization and
    # saltfactories' atexit fallback) cannot be relied upon: the whole
    # process group is signaled, so pytest may be killed before/during
    # teardown, and killed processes don't run atexit handlers.
    # Remove containers here, before teardown, while we still can.
    terminate_configured_containers()


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if session.config.getoption("--allow-empty-runs"):
        if exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
            session.exitstatus = pytest.ExitCode.OK
