import warnings
from unittest.mock import patch

import pytest

from saltext.vault.utils import versions


@pytest.fixture(autouse=True)
def current_version():
    with patch("saltext.vault.utils.versions.__version__", "1.3.0"):
        yield


@pytest.mark.parametrize("version", ["3.0.0", 3.0, 3, (3, 0, 0), ["3", "0"]])
def test_warn_until_warns(version):
    """
    Ensure a warning is emitted when the current version is below the
    specified one and that all documented version specification types
    are supported
    """
    with pytest.warns(DeprecationWarning, match="brace yourself for 3"):
        versions.warn_until(version, "brace yourself for {version}")


def test_warn_until_custom_category():
    with pytest.warns(FutureWarning, match="the future is near"):
        versions.warn_until(3, "the future is near", category=FutureWarning)


@pytest.mark.parametrize("version", ["1.3.0", "1.0.0"])
def test_warn_until_reminds_of_removal(version):
    """
    Once the specified version has been released, developers should be
    reminded of removing the deprecated code path, including a pointer
    to the calling code
    """
    with pytest.raises(RuntimeError, match=f"test_versions.py.*until version {version}"):
        versions.warn_until(version, "brace yourself for {version}")


def test_warn_until_respects_pythonwarnings_ignore():
    with patch.dict(versions.os.environ, {"PYTHONWARNINGS": "ignore"}):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            versions.warn_until(3, "brace yourself for {version}")


def test_warn_until_invalid_version_specification():
    with pytest.raises(RuntimeError, match="must be a string, integer, float or an iterable"):
        versions.warn_until(object(), "nope")


@pytest.mark.parametrize(
    "a,op,b,expected",
    [
        ("1.0.0", "lt", "1.1.0", True),
        ("1.1.0", "lt", "1.1.0", False),
        ("1.0.0", "le", "1.0.0", True),
        ("1.1.0", "le", "1.0.0", False),
        ("1.0.0", "eq", "1.0.0", True),
        ("1.0.0", "eq", "1.1.0", False),
        ("1.0.0", "ne", "1.1.0", True),
        ("1.0.0", "ne", "1.0.0", False),
        ("1.1.0", "ge", "1.1.0", True),
        ("1.0.0", "ge", "1.1.0", False),
        ("1.1.0", "gt", "1.0.0", True),
        ("1.0.0", "gt", "1.0.0", False),
    ],
)
@pytest.mark.parametrize("as_str", [False, True])
def test_version_compares_with_strings(a, op, b, expected, as_str):
    """
    Ensure Version instances can be compared with plain strings
    and Version instances (inherited behavior)
    """
    other = b if as_str else versions.Version(b)
    assert getattr(versions.Version(a), f"__{op}__")(other) is expected
