import ast
import os.path
import subprocess
from pathlib import Path

repo_path = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip())
src_dir = repo_path / "src" / "saltext" / "vault"
doc_dir = repo_path / "docs"

docs_by_kind = {}
changed_something = False


def _find_virtualname(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__virtualname__":
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        virtualname = node.value.value
                        break
            else:
                continue
            break
    else:
        virtualname = path.with_suffix("").name
    return virtualname


def write_module(rst_path, header, paths):
    header_len = len(header)
    # The check-merge-conflict pre-commit hook chokes here:
    # https://github.com/pre-commit/pre-commit-hooks/issues/100
    if header_len == 7:
        header_len += 1
    automodules = "\n".join(f""".. automodule:: {make_import_path(path)}
    :members:
""" for path in paths)
    module_contents = f"""\
{header}
{'='*header_len}

{automodules}"""
    if not rst_path.exists() or rst_path.read_text() != module_contents:
        print(rst_path)
        rst_path.write_text(module_contents)
        return True
    return False


def write_index(index_rst, import_paths, kind):
    if kind == "utils":
        header_text = "Utilities"
        common_path = os.path.commonpath(tuple(x.replace(".", "/") for x in import_paths)).replace(
            "/", "."
        )
        if any(x == common_path for x in import_paths):
            common_path = common_path[: common_path.rfind(".")]
    else:
        header_text = (
            "execution modules" if kind.lower() == "modules" else kind.rstrip("s") + " modules"
        )
        common_path = import_paths[0][: import_paths[0].rfind(".")]
    header = f"{'_'*len(header_text)}\n{header_text.title()}\n{'_'*len(header_text)}"
    index_contents = f"""\
.. all-saltext.vault.{kind}:

{header}

.. currentmodule:: {common_path}

.. autosummary::
    :toctree:

{chr(10).join(sorted('    '+p[len(common_path)+1:] for p in import_paths))}
"""
    if not index_rst.exists() or index_rst.read_text() != index_contents:
        print(index_rst)
        index_rst.write_text(index_contents)
        return True
    return False


def make_import_path(path):
    if path.name == "__init__.py":
        path = path.parent
    return ".".join(path.relative_to(repo_path / "src").with_suffix("").parts)


tracked = set(
    subprocess.check_output(["git", "ls-files", "-z"], text=True, cwd=repo_path).split("\x00")
)

for path in src_dir.glob("*/*.py"):
    if path.name != "__init__.py" and str(path.relative_to(repo_path)) in tracked:
        kind = path.parent.name
        if kind != "utils":
            docs_by_kind.setdefault(kind, set()).add(path)

# Utils can have subdirectories, treat them separately
for path in (src_dir / "utils").rglob("*.py"):
    if str(path.relative_to(repo_path)) not in tracked:
        continue
    if path.name == "__init__.py" and not path.read_text():
        continue
    docs_by_kind.setdefault("utils", set()).add(path)


def _group_by_virtualname(paths):
    grouped = {}
    for path in sorted(paths):
        grouped.setdefault(_find_virtualname(path), []).append(path)
    # Make the module whose file name matches the virtualname the
    # canonical one, i.e. the first in the group and the one the
    # rst file is named after.
    for virtualname, group in grouped.items():
        for path in group:
            if path.stem in (virtualname, virtualname + "_mod"):
                group.remove(path)
                group.insert(0, path)
                break
    return grouped


for kind in docs_by_kind:
    kind_path = doc_dir / "ref" / kind
    index_rst = kind_path / "index.rst"
    import_paths = []
    written_rst_paths = set()
    if kind == "utils":
        # Utils are documented under their import path, no grouping necessary
        grouped = {make_import_path(path): [path] for path in sorted(docs_by_kind[kind])}
    else:
        grouped = {
            f"``{virtualname}``": paths
            for virtualname, paths in _group_by_virtualname(docs_by_kind[kind]).items()
        }
    for header, paths in grouped.items():
        import_path = make_import_path(paths[0])
        import_paths.append(import_path)
        rst_path = kind_path / (import_path + ".rst")
        rst_path.parent.mkdir(parents=True, exist_ok=True)
        written_rst_paths.add(rst_path)
        change = write_module(rst_path, header, paths)
        changed_something = changed_something or change

    # Remove stale generated rst files, e.g. after a module has been renamed/
    # removed or merged into another one's docs by sharing its virtualname.
    for rst_path in kind_path.glob(f"saltext.vault.{kind}.*.rst"):
        if rst_path not in written_rst_paths:
            print(f"Removing stale {rst_path}")
            rst_path.unlink()
            changed_something = True

    changed_something |= write_index(index_rst, sorted(import_paths), kind)


# Ensure pre-commit realizes we did something
if changed_something:
    exit(2)
