from saltext.vault.utils.functools import namespaced_function

SOME_GLOBAL = "original"


def _example(pos, args=None, *, kwarg="kwdefault"):
    _example.calls.append((pos, args, kwarg))  # type: ignore
    return SOME_GLOBAL


_example.calls = []  # type: ignore


def test_namespaced_function():
    """
    Ensure the cloned function resolves globals from the new namespace,
    while keeping defaults, missing globals and function attributes
    """
    new_global_dict = {"SOME_GLOBAL": "overridden"}
    cloned = namespaced_function(_example, new_global_dict)

    assert cloned is not _example
    assert cloned.__name__ == _example.__name__
    assert cloned("posarg") == "overridden"  # pylint: disable=not-callable
    # positional and keyword-only defaults must be preserved
    assert cloned.calls[-1] == ("posarg", None, "kwdefault")
    assert cloned(1, 2, kwarg=3) == "overridden"  # pylint: disable=not-callable
    assert cloned.calls[-1] == (1, 2, 3)
    # the original function is unaffected
    assert _example("posarg") == "original"

    # missing globals are copied over (e.g. the _example self-reference
    # needed for the call log), the overridden one is kept
    assert new_global_dict["_example"] is _example
    assert new_global_dict["SOME_GLOBAL"] == "overridden"

    # kwdefaults must be a copy, not a shared reference
    cloned.__kwdefaults__["kwarg"] = "changed"
    assert _example.__kwdefaults__ == {"kwarg": "kwdefault"}


def test_namespaced_function_without_kwdefaults():
    """
    Ensure functions without keyword-only defaults are supported
    """

    def _no_kwdefaults(pos):
        return pos

    cloned = namespaced_function(_no_kwdefaults, {})
    assert cloned.__kwdefaults__ is None
    assert cloned("foo") == "foo"  # pylint: disable=not-callable
