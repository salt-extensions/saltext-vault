"""
Verify the salt-ssh wrapper modules mirror their execution modules.

For each execution module in ``src/saltext/vault/modules``, a wrapper
module of the same name must exist in ``src/saltext/vault/wrapper`` and

 1. expose every public function of the execution module, either by
    importing and namespacing it (``f = namespaced_function(f, ...)``)
    or by defining a replacement locally,
 2. namespace every function it imports from an execution module,
    including private helpers - otherwise, the function would run with
    the execution module's globals (e.g. ``__salt__``) instead of the
    wrapper's,
 3. pass the same name to ``namespaced_function`` as it assigns, and
 4. mirror the execution module's ``__func_alias__`` entries -
    otherwise, aliased functions are exposed under their unaliased
    names and calls to the aliased ones bypass the wrapper silently.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "src" / "saltext" / "vault" / "modules"
WRAPPER_DIR = REPO_ROOT / "src" / "saltext" / "vault" / "wrapper"
MODULES_PKG = "saltext.vault.modules"

# Known gaps that need a decision instead of a mechanical fix
EXCLUDES = {
    # TODO: Decide whether this needs a local reimplementation handling
    # file arguments on the master (like import_issuer) or can be namespaced.
    "vault_pki.py": {"sign_intermediate"},
}


def _parse(path):
    return ast.parse(path.read_text(encoding="utf-8"))


def _top_level_functions(tree):
    return {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _func_alias(tree):
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(t, ast.Name) and t.id == "__func_alias__" for t in node.targets):
            if isinstance(node.value, ast.Dict):
                return {
                    key.value: value.value
                    for key, value in zip(node.value.keys, node.value.values)
                    if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)
                }
    return {}


def _module_imports(tree):
    """
    Map of imported name -> source module for all imports from the
    execution modules package.
    """
    imports = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level or not (node.module or "").startswith(f"{MODULES_PKG}."):
            continue
        for alias in node.names:
            imports[alias.asname or alias.name] = node.module
    return imports


def _namespaced(tree):
    """
    Map of assignment target -> first argument name for all
    ``X = namespaced_function(Y, ...)`` assignments.
    """
    namespaced = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "namespaced_function":
            continue
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            arg = node.value.args[0] if node.value.args else None
            namespaced[node.targets[0].id] = arg.id if isinstance(arg, ast.Name) else None
    return namespaced


def check_module(mod_path):
    wrapper_path = WRAPPER_DIR / mod_path.name
    prefix = f"{mod_path.relative_to(REPO_ROOT)}: "
    if not wrapper_path.exists():
        yield f"{prefix}missing wrapper module at {wrapper_path.relative_to(REPO_ROOT)}"
        return

    mod = _parse(mod_path)
    wrapper = _parse(wrapper_path)
    prefix = f"{wrapper_path.relative_to(REPO_ROOT)}: "

    public = {
        name
        for name in _top_level_functions(mod)
        if not name.startswith("_") and name not in EXCLUDES.get(mod_path.name, ())
    }
    mod_aliases = _func_alias(mod)
    wrapper_funcs = _top_level_functions(wrapper)
    imports = _module_imports(wrapper)
    namespaced = _namespaced(wrapper)
    wrapper_aliases = _func_alias(wrapper)

    for name in sorted(public):
        if name in wrapper_funcs:
            continue  # local (re)implementation
        if name not in imports:
            yield f"{prefix}public function '{name}' is neither imported nor defined"
        elif name not in namespaced:
            yield f"{prefix}'{name}' is imported, but not namespaced"

    for name in sorted(imports):
        if name in wrapper_funcs:
            continue  # imported for reference, but overridden locally
        if name not in namespaced:
            yield f"{prefix}import '{name}' is not passed through namespaced_function"

    for target, arg in sorted(namespaced.items()):
        if arg != target:
            yield (
                f"{prefix}'{target} = namespaced_function({arg}, ...)' "
                "namespaces a different function than it assigns"
            )

    for src, alias in sorted(mod_aliases.items()):
        if src.startswith("_") or (src not in public and src not in imports):
            continue
        if wrapper_aliases.get(src) != alias:
            yield (
                f"{prefix}missing __func_alias__ entry {{'{src}': '{alias}'}} - "
                f"calls to '{alias}' bypass the wrapper"
            )


def main():
    problems = []
    for mod_path in sorted(MODULES_DIR.glob("*.py")):
        if mod_path.name == "__init__.py":
            continue
        problems.extend(check_module(mod_path))
    if problems:
        print("The salt-ssh wrapper modules are out of sync:")
        for problem in problems:
            print(f"  * {problem}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
