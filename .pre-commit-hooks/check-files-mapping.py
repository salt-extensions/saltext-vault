"""
Verify the changed-files-to-tests map in ``tests/support/files_mapping.py``.

Checks:
 1. Placeholders in target globs correspond to named groups in their pattern.
    Failures abort the remaining checks since rules cannot be resolved then.
 2. Exact-membership entries (tuple patterns) reference tracked files.
 3. Every tracked file under ``src/`` and ``tests/`` resolves to a rule and
    selects at least one existing test file (or triggers a full run).
    Empty files are exempt. This also covers non-Python files, which the
    runtime selection logic otherwise ignores silently.
 4. When a module of this repository (``tests.*``, ``saltext.vault.*``)
    changes, all test modules directly importing (from) it are selected.
    For conftest importers, at least one test in the conftest's subtree
    must be selected (not all of them since conftest imports are usually
    only relevant to a subset). Empty modules (package markers) are exempt.
 5. Every rule is the first match for at least one tracked file, i.e. it is
    neither stale (source renamed/removed) nor shadowed by earlier rules.
 6. No rule selects nearly all tests without being declared as a full run,
    which usually indicates an accidentally broad glob.

Passing one of the following flags prints the requested report instead
of running the checks:

--stats
    Print the maximum selection breadth per rule, broadest first.

--stats=<rule number>
    List all files resolving through the numbered rule.

--full-stats
    For each rule, map all files resolving through it to the test
    modules they select.

--full-stats=<rule number>
    The same, for the numbered rule only.

--files=<comma-separated paths>
    Print the tests selected for each given (changed) file.

--json
    Render the report of any of the above flags as JSON.
    Full runs are represented as ``["*"]``, as in the map itself.

--help / -h
    Print this description.
"""

import ast
import fnmatch
import importlib.util
import json
import re
import string
import subprocess
import sys
import types
from pathlib import Path
from pathlib import PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_RUN = ("*",)


def load_map():
    """
    Load CHANGED_FILES_MAP without importing ``tests.common``,
    which requires salt + saltfactories (unavailable in the hook env).
    """
    stub = types.ModuleType("tests.common")
    stub.PACKAGE_ROOT_REL = PurePosixPath("src/saltext/vault")  # type: ignore[attr-defined]
    stub.TESTS_DIR_REL = PurePosixPath("tests")  # type: ignore[attr-defined]
    for rel in (stub.PACKAGE_ROOT_REL, stub.TESTS_DIR_REL):
        if not (REPO_ROOT / rel).is_dir():
            raise RuntimeError(f"Stubbed path constant is out of date: {rel}")
    parent = types.ModuleType("tests")
    parent.common = stub  # type: ignore[attr-defined]
    sys.modules.setdefault("tests", parent)
    sys.modules["tests.common"] = stub
    spec = importlib.util.spec_from_file_location(
        "files_mapping", REPO_ROOT / "tests/support/files_mapping.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CHANGED_FILES_MAP


def resolve(cfm, file):
    """
    Mirror the resolution logic in ``run_changed_files`` (tests/support/pytest_hooks.py).
    """
    for ptrn, maps in cfm:
        if not isinstance(ptrn, str):
            if file in ptrn:
                return maps
        elif match := re.match(ptrn, file):
            gdict = match.groupdict(default="")
            return tuple(glob.format(**gdict) for glob in maps)
    return None


def selected(cfm, file, test_files):
    globs = resolve(cfm, file)
    if globs is None:
        return None
    if "*" in globs:
        return FULL_RUN
    return {t for t in test_files for g in globs if fnmatch.fnmatch(t, g)}


def check_membership_entries(cfm, tracked):
    for ptrn, _ in cfm:
        if not isinstance(ptrn, str):
            for file in ptrn:
                if file not in tracked:
                    yield f"Rule references missing file: {file}"


def check_placeholders(cfm):
    fmt = string.Formatter()
    for ptrn, maps in cfm:
        groups = set(re.compile(ptrn).groupindex) if isinstance(ptrn, str) else set()
        for glob in maps:
            for _, field, _, _ in fmt.parse(glob):
                if field and field not in groups:
                    yield f"Target '{glob}' references undefined group '{field}' (pattern: {ptrn})"


def _first_match(cfm, file):
    for i, (ptrn, _) in enumerate(cfm):
        if re.match(ptrn, file) if isinstance(ptrn, str) else file in ptrn:
            return i
    return None


def _describe(rule):
    ptrn = rule[0]
    return ptrn if isinstance(ptrn, str) else f"membership tuple starting with {ptrn[0]}"


def check_rule_reachability(cfm, tracked):
    """
    Rule resolution is first-match-wins, so a rule that is never the first
    match for any tracked file is dead - either its source pattern went
    stale (renames/removals) or earlier rules shadow all its matches.
    """
    hit = {_first_match(cfm, file) for file in tracked}
    for i, rule in enumerate(cfm):
        if i not in hit:
            yield f"Rule #{i} never matches any tracked file: {_describe(rule)}"


# Rules selecting at least this share of all tests should declare a full run
NEAR_FULL_RUN_THRESHOLD = 0.9


def check_near_full_run(cfm, tracked, test_files):
    """
    A rule that selects nearly all tests without being declared as a full
    run usually indicates an accidentally broad glob. It should either be
    narrowed or declared as an explicit full run for clarity.
    """
    threshold = NEAR_FULL_RUN_THRESHOLD * len(test_files)
    flagged = set()
    for file in tracked:
        i = _first_match(cfm, file)
        if i is None or i in flagged:
            continue
        sel = selected(cfm, file, test_files)
        if sel != FULL_RUN and len(sel) >= threshold:
            flagged.add(i)
            yield (
                f"Rule #{i} selects {len(sel)}/{len(test_files)} tests (e.g. for {file}) "
                f"without declaring a full run: {_describe(cfm[i])}"
            )


def check_all_sources_select(cfm, tracked, test_files):
    for file in tracked:
        if not file.startswith(("src/", "tests/")):
            continue
        if not (REPO_ROOT / file).read_bytes().strip():
            continue
        sel = selected(cfm, file, test_files)
        if sel is None:
            yield f"No rule matches: {file}"
        elif not sel:
            yield f"Rule matches, but no tests are selected for: {file}"


# Import roots whose modules the map must account for, and their file locations
_IMPORT_ROOTS = {
    "tests": "tests",
    "saltext.vault": "src/saltext/vault",
}


def _module_base(dotted):
    for root, base in _IMPORT_ROOTS.items():
        if dotted == root or dotted.startswith(f"{root}."):
            return f"{base}{dotted[len(root):].replace('.', '/')}"
    return None


def _imported_modules(importer):
    """
    Yield candidate module files for all absolute imports from _IMPORT_ROOTS.
    ``from x.foo import bar`` can reference a member of ``x/foo.py``
    or ``x/foo/__init__.py`` as well as the module ``x/foo/bar.py``,
    so yield all of them. ``import x.foo`` yields the former two only.
    Nonexistent candidates are filtered by the caller.
    """
    tree = ast.parse((REPO_ROOT / importer).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level or not (base := _module_base(node.module or "")):
                continue
            yield f"{base}.py"
            yield f"{base}/__init__.py"
            for alias in node.names:
                yield f"{base}/{alias.name}.py"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if base := _module_base(alias.name):
                    yield f"{base}.py"
                    yield f"{base}/__init__.py"


def check_test_import_edges(cfm, test_files):
    for importer in test_files:
        for imported in _imported_modules(importer):
            if imported == importer or not (REPO_ROOT / imported).exists():
                continue
            if not (REPO_ROOT / imported).read_bytes().strip():
                # Empty modules (usually package markers) are irrelevant as change triggers
                continue
            sel = selected(cfm, imported, test_files)
            if sel != FULL_RUN and importer not in (sel or ()):
                yield f"{imported} is used by {importer}, which is not selected on changes"


def check_conftest_import_edges(cfm, tracked, test_files):
    """
    Conftest imports are only relevant to a subset of the conftest's subtree
    usually, so just ensure the subtree is not missed completely.
    """
    for conftest in sorted(f for f in tracked if re.match(r"tests/(?:.+/)?conftest\.py$", f)):
        subtree = [t for t in test_files if t.startswith(conftest[: -len("conftest.py")])]
        for imported in sorted(set(_imported_modules(conftest))):
            if not (REPO_ROOT / imported).exists():
                continue
            if not (REPO_ROOT / imported).read_bytes().strip():
                continue
            sel = selected(cfm, imported, test_files)
            if sel != FULL_RUN and not any(t in sel for t in subtree):
                yield (
                    f"{imported} is used by {conftest}, "
                    "but none of its subtree tests are selected on changes"
                )


def run_checks(cfm, tracked, test_files):
    problems = list(check_placeholders(cfm))
    if problems:
        # The remaining checks cannot resolve rules with undefined placeholders.
        return problems
    problems.extend(check_membership_entries(cfm, tracked))
    problems.extend(check_rule_reachability(cfm, tracked))
    problems.extend(check_near_full_run(cfm, tracked, test_files))
    problems.extend(check_all_sources_select(cfm, tracked, test_files))
    problems.extend(check_test_import_edges(cfm, test_files))
    problems.extend(check_conftest_import_edges(cfm, tracked, test_files))
    return problems


def _stats_data(cfm, tracked, test_files):
    """
    Collect the maximum selection breadth per rule, broadest first.
    """
    total = len(test_files)
    worst = {}
    for file in sorted(tracked):
        i = _first_match(cfm, file)
        if i is None:
            continue
        sel = selected(cfm, file, test_files)
        count = total if sel == FULL_RUN else len(sel)
        if count > worst.get(i, {"selected": -1})["selected"]:
            worst[i] = {
                "rule": i,
                "pattern": _describe(cfm[i]),
                "selected": count,
                "example_trigger": file,
            }
    return sorted(worst.values(), key=lambda entry: -entry["selected"])


def _rule_matches_data(cfm, tracked, test_files, rule_idx, full=False):
    """
    Collect all tracked files that resolve through the numbered rule.
    With ``full``, map each of them to the test modules it selects.
    Full runs are represented as ["*"], as in the map.
    """
    triggers = sorted(file for file in tracked if _first_match(cfm, file) == rule_idx)
    data = {"rule": rule_idx, "pattern": _describe(cfm[rule_idx])}
    if not full:
        data["triggers"] = triggers
        return data
    data["selected"] = {}
    for file in triggers:
        sel = selected(cfm, file, test_files)
        data["selected"][file] = list(FULL_RUN) if sel == FULL_RUN else sorted(sel)
    return data


def _files_data(cfm, test_files, files):
    """
    Collect the tests selected for each given (changed) file.
    """
    data = []
    for file in files:
        sel = selected(cfm, file, test_files)
        data.append(
            {
                "file": file,
                "rule": _first_match(cfm, file),
                "selected": list(FULL_RUN) if sel == FULL_RUN else sorted(sel or ()),
            }
        )
    return data


def print_files(data, total):
    for i, entry in enumerate(data):
        if i:
            print()
        rule = f"rule #{entry['rule']}" if entry["rule"] is not None else "no rule"
        print(f"{entry['file']} ({rule})")
        sel = entry["selected"]
        if sel == list(FULL_RUN):
            print(f"  => full run ({total} tests)")
        elif not sel:
            print("  => (no tests selected)")
        else:
            for j, target in enumerate(sel):
                print(f"  {'=>' if not j else '  '} {target}")


def print_stats(data, total):
    for entry in data:
        print(
            f"rule #{entry['rule']:2d}: {entry['selected']:3d}/{total} tests "
            f"(e.g. for {entry['example_trigger']})  {entry['pattern']}"
        )


def print_rule_matches(data, total):
    print(f"rule #{data['rule']}: {data['pattern']}")
    for file in data.get("triggers", ()):
        print(f"  {file}")
    # Group triggers sharing the same selection to avoid repetition
    by_selection = {}
    for file, sel in data.get("selected", {}).items():
        by_selection.setdefault(tuple(sel), []).append(file)
    for sel, files in sorted(by_selection.items(), key=lambda item: item[1]):
        print()
        for file in files:
            print(f"  {file}")
        if sel == FULL_RUN:
            print(f"    => full run ({total} tests)")
        elif not sel:
            print("    => (no tests selected)")
        else:
            for i, target in enumerate(sel):
                print(f"    {'=>' if not i else '  '} {target}")


def main():
    tracked = set(
        subprocess.check_output(["git", "ls-files"], text=True, cwd=REPO_ROOT).splitlines()
    )
    test_files = sorted(f for f in tracked if re.match(r"tests/.*/test_\w+\.py$", f))
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__.strip())
        return 0
    as_json = "--json" in args
    files_arg = next((arg for arg in args if arg.startswith("--files=")), None)
    if files_arg is not None:
        files = [file for file in files_arg.partition("=")[2].split(",") if file]
        data = _files_data(load_map(), test_files, files)
        if as_json:
            print(json.dumps(data, indent=2))
        else:
            print_files(data, len(test_files))
        return 0
    mode = next((arg for arg in args if arg.startswith(("--stats", "--full-stats"))), None)
    if mode is not None:
        cfm = load_map()
        full = mode.startswith("--full-stats")
        num = mode.partition("=")[2]
        if num:
            rule_idx = int(num)
            if not 0 <= rule_idx < len(cfm):
                print(f"No rule #{rule_idx}, the map contains rules #0-#{len(cfm) - 1}")
                return 2
            data = _rule_matches_data(cfm, tracked, test_files, rule_idx, full=full)
        elif full:
            data = [
                _rule_matches_data(cfm, tracked, test_files, rule_idx, full=True)
                for rule_idx in range(len(cfm))
            ]
        else:
            data = _stats_data(cfm, tracked, test_files)
        if as_json:
            print(json.dumps(data, indent=2))
        elif not full and not num:
            print_stats(data, len(test_files))
        else:
            for i, entry in enumerate(data if isinstance(data, list) else [data]):
                if i:
                    print()
                print_rule_matches(entry, len(test_files))
        return 0
    if as_json:
        print("--json requires one of the --stats/--full-stats/--files flags")
        return 2
    problems = run_checks(load_map(), tracked, test_files)
    if problems:
        print("The map in tests/support/files_mapping.py needs an update:")
        for problem in sorted(set(problems)):
            print(f"  * {problem}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
