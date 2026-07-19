"""
Fixed ``namespaced_function`` from ``salt.utils.functools``
"""

import types


def namespaced_function(function, global_dict):
    """
    Patched function taken from salt.utils.functools.
    It does not set kwdefaults.

    Redefine (clone) a function under a different globals() namespace scope.

    Any keys missing in the passed ``global_dict`` that is present in the
    passed function ``__globals__`` attribute get's copied over into
    ``global_dict``, thus avoiding ``NameError`` from modules imported in
    the original function module.
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
    # patch end   <<<
    new_namespaced_function.__dict__.update(function.__dict__)
    return new_namespaced_function
