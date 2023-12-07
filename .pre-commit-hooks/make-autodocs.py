import subprocess
from pathlib import Path


repo_path = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip())
src_dir = repo_path / "src" / "saltext" / "vault"
doc_dir = repo_path / "docs"

docs_by_kind = {}
changed_something = False


def write_module(rst_path, import_path):
    module_contents = f"""\
{import_path}
{'='*len(import_path)}

.. automodule:: {import_path}
    :members:
"""
    if not rst_path.exists() or rst_path.read_text() != module_contents:
        print(rst_path)
        rst_path.write_text(module_contents)
        return True
    return False


def write_index(index_rst, import_paths, kind):
    header_text = (
        "execution modules" if kind.lower() == "modules" else kind.rstrip("s") + " modules"
    )
    header = f"{'_'*len(header_text)}\n{header_text.title()}\n{'_'*len(header_text)}"
    index_contents = f"""\
.. all-saltext.vault.{kind}:

{header}

.. currentmodule:: {import_paths[0][:import_paths[0].rfind(".")]}

.. autosummary::
    :toctree:

{chr(10).join(sorted('    '+p[p.rfind(".")+1:] for p in import_paths))}
"""
    if not index_rst.exists() or index_rst.read_text() != index_contents:
        print(index_rst)
        index_rst.write_text(index_contents)
        return True
    return False


def make_import_path(path):
    return ".".join(path.relative_to(repo_path / "src").with_suffix("").parts)


for path in repo_path.joinpath("src/saltext/vault/").glob("*/*.py"):
    if path.name != "__init__.py":
        kind = path.parent.name
        docs_by_kind.setdefault(kind, set()).add(path)

for kind in docs_by_kind:
    kind_path = doc_dir / "ref" / kind
    index_rst = kind_path / "index.rst"
    import_paths = []
    for path in sorted(docs_by_kind[kind]):
        import_path = make_import_path(path)
        import_paths.append(import_path)
        rst_path = kind_path / (import_path + ".rst")
        rst_path.parent.mkdir(parents=True, exist_ok=True)
        change = write_module(rst_path, import_path)
        changed_something = changed_something or change

    write_index(index_rst, import_paths, kind)


# Ensure pre-commit realizes we did something
if changed_something:
    exit(2)
