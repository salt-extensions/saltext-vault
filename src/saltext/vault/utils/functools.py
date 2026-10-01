"""
Fixed ``namespaced_function`` from ``salt.utils.functools``
"""

import re
import types

# Only matches function-level annotations (at docstring base indentation),
# not parameter-level ones, which can reference later versions.
VERSIONADDED_RE = re.compile(r"^( {0,4}\.\. version-?added:: )\S+", re.MULTILINE)

CLI_EXAMPLE_REPLACEMENTS = {
    "runners": "salt-run",
    "wrapper": "salt-ssh '*'",
}


def namespaced_function(function, global_dict, versionadded=None):
    """
    Patched function taken from salt.utils.functools.
    It does not set kwdefaults and adapts mirrored docstrings.

    Redefine (clone) a function under a different globals() namespace scope.

    Any keys missing in the passed ``global_dict`` that is present in the
    passed function ``__globals__`` attribute get's copied over into
    ``global_dict``, thus avoiding ``NameError`` from modules imported in
    the original function module.

    When the destination is a runner or wrapper module, additionally adapts
    CLI examples in the function's docstring to the corresponding
    calling convention.

    versionadded
        Override the function-level ``versionadded`` annotation in the
        function's docstring (not parameter-level ones) with this version,
        e.g. because the function was made available in the destination
        module later than in the execution module.
    """
    # Make sure that any key on the globals of the function being copied get's
    # added to the destination globals dictionary, if not present.
    for key, value in function.__globals__.items():
        if key not in global_dict:
            global_dict[key] = value

    new_namespaced_function = types.FunctionType(
        function.__code__,
        global_dict,
        name=function.__name__,
        argdefs=function.__defaults__,
        closure=function.__closure__,
    )
    # patch start >>>
    if function.__kwdefaults__ is not None:
        new_namespaced_function.__kwdefaults__ = function.__kwdefaults__.copy()
    if new_namespaced_function.__doc__:
        doc = new_namespaced_function.__doc__
        parts = global_dict.get("__name__", "").split(".")
        cli_repl = CLI_EXAMPLE_REPLACEMENTS.get(parts[-2]) if len(parts) > 1 else None
        if cli_repl:
            doc = doc.replace("salt '*' ", f"{cli_repl} ")
        if versionadded is not None:
            doc = VERSIONADDED_RE.sub(lambda match: match.group(1) + versionadded, doc, count=1)
        new_namespaced_function.__doc__ = doc
    # patch end   <<<
    new_namespaced_function.__dict__.update(function.__dict__)
    return new_namespaced_function
