"""
Custom pytest hook implementations, registered as a plugin
via ``pytest_plugins`` in the root conftest.

Hooks living here instead of ``tests/conftest.py`` can be changed without
triggering a full test run via ``--changed-files``. Hooks whose changes
require a full run, e.g. ``pytest_make_parametrize_id`` (test IDs must
stay consistent for test selection), belong in the root conftest.
"""

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
from tests.common.containers import terminate_configured_containers
from tests.support.files_mapping import CHANGED_FILES_MAP


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_salt(major, minor?): mark test to only run on Salt versions equal to or higher than <major>.<minor or 0>",
    )
    config.addinivalue_line(
        "markers",
        "behavior: mark test as validating assumptions about external (Vault/OpenBao) "
        "server behavior. Skipped unless --behavior-tests is passed.",
    )


def pytest_runtest_setup(item):
    if item.get_closest_marker("behavior") is not None and not item.config.getoption(
        "--behavior-tests"
    ):
        pytest.skip(reason="Too specific and costly test. Run with --behavior-tests")

    requires_salt_marker = item.get_closest_marker("requires_salt")
    if requires_salt_marker is not None:
        if len(requires_salt_marker.args) not in (1, 2) or requires_salt_marker.kwargs:
            raise pytest.UsageError(
                "The 'requires_salt' marker only accepts one or two positional arguments"
            )
        try:
            major, minor = int(requires_salt_marker.args[0]), int(requires_salt_marker.args[1])
        except IndexError:
            major, minor = int(requires_salt_marker.args[0]), 0
        if (major, minor) > SALT_VERSION:
            pytest.skip(reason=f"Requires at least Salt {major}.{minor}")


def pytest_addoption(parser):
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

    test_selection_group.addoption(
        "--behavior-tests",
        dest="behavior_tests",
        action="store_true",
        default=False,
        help=("Only run tests that validate assumptions about external server behavior"),
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
    run_changed_files(config, items)
    run_changed_tests(config, items)
    run_behavior_tests(config, items)


def run_behavior_tests(config, items):
    if not config.getoption("--behavior-tests"):
        return
    terminal_reporter = config.pluginmanager.getplugin("terminalreporter")
    terminal_reporter.ensure_newline()
    terminal_reporter.section("Behavior Tests Selection (--behavior-tests)", sep=">")

    selected = []
    deselected = []

    for item in items:
        if item.get_closest_marker("behavior") is not None:
            selected.append(item)
        else:
            deselected.append(item)

    items[:] = selected
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    terminal_reporter.section("Behavior Tests Selection End (--behavior-tests)", sep="<")


def run_changed_tests(config, items):
    if not config.getoption("--changed-tests"):
        return
    terminal_reporter = config.pluginmanager.getplugin("terminalreporter")
    terminal_reporter.ensure_newline()
    terminal_reporter.section("Changed Tests Selection (--changed-tests)", sep=">")

    changed = _get_git_modified(terminal_reporter)
    if changed is None:
        return

    selected = []
    deselected = []

    for item in items:
        itempath = Path(str(item.fspath)).resolve().relative_to(REPO_ROOT)
        if (
            str(itempath) in changed
            and itempath.is_relative_to(TESTS_DIR_REL)
            and itempath.suffix == ".py"
            and itempath.stem != "conftest"
        ):
            selected.append(item)
        else:
            deselected.append(item)

    items[:] = selected
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    terminal_reporter.section("Changed Tests Selection End (--changed-tests)", sep="<")


def _get_git_modified(terminal_reporter):
    try:
        modified = subprocess.check_output(["git", "diff", "-z", "--name-only"], text=True)
    except subprocess.CalledProcessError as err:
        if terminal_reporter:
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
        if terminal_reporter:
            terminal_reporter.write_line(
                f"Failed to get unstaged files from git: {err}", bold=True, red=True
            )
            terminal_reporter.write_line(err.stderr)
        return
    return (modified.rstrip("\0").split("\0") if modified else []) + (
        created.rstrip("\0").split("\0") if created else []
    )


def run_changed_files(config, items):
    if not config.getoption("--changed-files"):
        return
    terminal_reporter = config.pluginmanager.getplugin("terminalreporter")
    terminal_reporter.ensure_newline()
    terminal_reporter.section("Changed Files Test Selection (--changed-files)", sep=">")

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
        changed = _get_git_modified(terminal_reporter)
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
    terminal_reporter.section("Changed Files Test Selection End (--changed-files)", sep="<")


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
