import subprocess
import sys
from enum import IntEnum
from pathlib import Path


repo_path = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip())
src_dir = repo_path / "src" / "saltext" / "vault"
doc_dir = repo_path / "docs"

docs_by_kind = {}


def make_import_path(path):
    return ".".join(path.with_suffix("").parts[-4:])


for path in Path(__file__).parent.parent.joinpath("src/saltext/vault/").glob("*/*.py"):
    if path.name != "__init__.py":
        kind = path.parent.name
        docs_by_kind.setdefault(kind, set()).add(path)

for kind in docs_by_kind:
    kind_path = doc_dir / "ref" / kind
    all_rst = kind_path / "all.rst"
    import_paths = []
    for path in sorted(docs_by_kind[kind]):
        import_path = make_import_path(path)
        import_paths.append(import_path)
        rst_path = kind_path.joinpath(import_path).with_suffix(".rst")
        print(rst_path)
        rst_path.parent.mkdir(parents=True, exist_ok=True)
        rst_path.write_text(
            f"""
{import_path}
{'='*len(import_path)}

.. automodule:: {import_path}
    :members:
"""
        )

    header_text = (
        "execution modules" if kind.lower() == "modules" else kind.rstrip("s") + " modules"
    )
    header = f"{'_'*len(header_text)}\n{header_text.title()}\n{'_'*len(header_text)}"

    all_rst.write_text(
        f"""
.. all-saltext.vault.{kind}:

{header}

.. autosummary::
    :toctree:

{chr(10).join(sorted('    '+p for p in import_paths))}
"""
    )
