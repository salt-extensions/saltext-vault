"""
Helper for warning about deprecations
"""

import inspect
import os
import sys
import warnings

import packaging.version

from saltext.vault import __version__


def warn_until(
    version,
    message,
    category=DeprecationWarning,
):
    """
    Warn about deprecations until the specified version is reached, after which
    raise a RuntimeError to remind developers about removal.

    Loosely based on ``salt.utils.versions.warn_until``.

    version
        The version at which the warning turns into an error. Can be specified
        as a string, float, int or iterable with items castable to integers.

    message
        The warning message to show.

    category
        The warning class to be thrown, by default ``DeprecationWarning``.
    """
    version = _parse_version(version)
    saltext_version = _parse_version(__version__)
    # Attribute the warning to the calling function, not to warn_until()
    stacklevel = 2

    if saltext_version >= version:
        caller = inspect.getframeinfo(sys._getframe(stacklevel - 1))
        raise RuntimeError(
            f"The warning triggered on filename '{caller.filename}', line number "
            f"{caller.lineno}, is supposed to be shown until version "
            f"{version} is released. Current version is now "
            f"{saltext_version}. Please remove the warning."
        )

    if os.environ.get("PYTHONWARNINGS") != "ignore":
        warnings.warn(
            message.format(version=version),
            category,
            stacklevel=stacklevel,
        )


class Version(packaging.version.Version):
    def __lt__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return super().__lt__(other)

    def __le__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return super().__le__(other)

    def __eq__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return super().__eq__(other)

    def __ge__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return super().__ge__(other)

    def __gt__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return super().__gt__(other)

    def __ne__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return super().__ne__(other)


def _parse_version(version):
    if isinstance(version, str):
        pass
    elif isinstance(version, (float, int)):
        version = str(version)
    else:
        try:
            version = ".".join(str(x) for x in version)
        except TypeError as err:
            raise RuntimeError("`version` must be a string, integer, float or an iterable") from err
    return Version(version)
