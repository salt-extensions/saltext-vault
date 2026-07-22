"""
Several utility functions for the Vault modules
"""

import base64
import datetime
import logging
import re
import string
import typing
from collections.abc import Mapping
from types import EllipsisType

import salt.utils.atomicfile
import salt.utils.files
from salt.exceptions import InvalidConfigError
from salt.exceptions import SaltInvocationError
from salt.state import STATE_INTERNAL_KEYWORDS as _STATE_INTERNAL_KEYWORDS

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltLogger


log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

SALT_RUNTYPE_MASTER = 0
SALT_RUNTYPE_MASTER_IMPERSONATING = 1
SALT_RUNTYPE_MASTER_PEER_RUN = 2
SALT_RUNTYPE_MINION_LOCAL = 3
SALT_RUNTYPE_MINION_REMOTE = 4


def get_salt_run_type(
    opts: dict[str, typing.Any],
) -> (
    typing.Literal[0]
    | typing.Literal[1]
    | typing.Literal[2]
    | typing.Literal[3]
    | typing.Literal[4]
):
    if "vault" in opts and opts.get("__role", "minion") == "master":
        if opts.get("minion_id"):
            log.debug("Salt runtype: impersonating master")
            return SALT_RUNTYPE_MASTER_IMPERSONATING
        if "grains" in opts and "id" in opts["grains"]:
            log.debug("Salt runtype: peer run master")
            return SALT_RUNTYPE_MASTER_PEER_RUN
        log.debug("Salt runtype: regular master")
        return SALT_RUNTYPE_MASTER

    config_location = opts.get("vault", {}).get("config_location")
    if config_location and config_location not in ("local", "master"):
        raise InvalidConfigError(
            "Invalid vault configuration: config_location must be either local or master"
        )

    if config_location == "master":
        pass
    elif any(
        (
            opts.get("local", None),
            opts.get("file_client", None) == "local",
            opts.get("master_type", None) == "disable",
            config_location == "local",
        )
    ):
        log.debug("Salt runtype: local minion")
        return SALT_RUNTYPE_MINION_LOCAL
    log.debug("Salt runtype: regular minion")
    return SALT_RUNTYPE_MINION_REMOTE


def check_salt_ssh_opts(opts: dict[str, typing.Any]) -> dict[str, typing.Any]:
    if "__master_opts__" in opts and "vault" not in opts:
        # Let's run the same way as during pillar compilation.
        vopts = {}
        vopts.update(opts)
        vopts.update(opts["__master_opts__"])
        # Salt 3008 OptsDict introduced an issue where the __master_opts__ cachedir
        # can point to the minion-specific one. The original one is still preserved in _caller_cachedir.
        if "_caller_cachedir" in opts:
            vopts["cachedir"] = opts["_caller_cachedir"]
        vopts["id"] = vopts["minion_id"] = opts["id"]
        opts = vopts
    return opts


def iso_to_timestamp(iso_time: str) -> int:
    """
    Most endpoints respond with RFC3339-formatted strings
    This is a hacky way to use inbuilt tools only for converting
    to a timestamp
    """
    # drop subsecond precision to make it easier on us
    # (length would need to be 3, 6 or 9)
    iso_time = re.sub(r"\.[\d]+", "", iso_time)
    iso_time = re.sub(r"Z$", "+00:00", iso_time)
    try:
        # Python >=v3.7
        return int(datetime.datetime.fromisoformat(iso_time).timestamp())
    except AttributeError:
        # Python < v3.7
        dstr, tstr = iso_time.split("T")
        year = int(dstr[:4])
        month = int(dstr[5:7])
        day = int(dstr[8:10])
        hour = int(tstr[:2])
        minute = int(tstr[3:5])
        second = int(tstr[6:8])
        tz_pos = (tstr.find("-") + 1 or tstr.find("+") + 1) - 1
        tz_hour = int(tstr[tz_pos + 1 : tz_pos + 3])
        tz_minute = int(tstr[tz_pos + 4 : tz_pos + 6])
        if all(x == 0 for x in (tz_hour, tz_minute)):
            tz = datetime.timezone.utc
        else:
            tz_sign = -1 if tstr[tz_pos] == "-" else 1
            td = datetime.timedelta(hours=tz_hour, minutes=tz_minute)
            tz = datetime.timezone(tz_sign * td)
        return int(datetime.datetime(year, month, day, hour, minute, second, 0, tz).timestamp())


def expand_pattern_lists(pattern: str, **mappings) -> list[str]:
    """
    Expands the pattern for any list-valued mappings, such that for any list of
    length N in the mappings present in the pattern, N copies of the pattern are
    returned, each with an element of the list substituted.

    pattern
        A pattern to expand, for example ``by-role/{pillar[roles]}``

    mappings
        A dictionary of variables that can be expanded into the pattern.

    Example: Given the pattern `` by-role/{pillar[roles]}`` and the below pillar

    .. code-block:: yaml

        roles:
          - web
          - database

    This function expands into two patterns,
    ``[by-role/web, by-role/database]``.

    Note that this method does not expand any non-list patterns.
    """
    expanded_patterns = []
    f = string.Formatter()

    # This function uses a string.Formatter to get all the formatting tokens from
    # the pattern, then recursively replaces tokens whose expanded value is a
    # list. For a list with N items, it creates N new pattern strings and
    # then continue with the next token. In practice this is expected to not be
    # very expensive, since patterns typically involve a handful of lists at
    # most.

    for _, field_name, _, _ in f.parse(pattern):
        if field_name is None:
            continue
        value, _ = f.get_field(field_name, (), mappings)
        if isinstance(value, (list, dict)):
            token = f"{{{field_name}}}"
            expanded = [pattern.replace(token, str(elem)) for elem in value]
            for expanded_item in expanded:
                result = expand_pattern_lists(expanded_item, **mappings)
                expanded_patterns += result
            return expanded_patterns
    return [pattern]


@typing.overload
def timestring_map(val: int | float | str, cast: type[int]) -> int: ...
@typing.overload
def timestring_map(val: int | float | str, cast: type[float] = float) -> float: ...
@typing.overload
def timestring_map(val: int | float | str) -> float: ...
@typing.overload
def timestring_map(val: int | float | str | None, cast: type[int]) -> int | None: ...
@typing.overload
def timestring_map(val: int | float | str | None) -> float | None: ...
@typing.overload
def timestring_map(val: int | float | str | None, cast: type[float] = float) -> float | None: ...
def timestring_map(
    val: int | float | str | None, cast: type[float] | type[int] = float
) -> float | int | None:
    """
    Turn a time string (like ``60m``) into a float with seconds as a unit.
    """
    if val is None:
        return val
    if isinstance(val, (int, float)):
        return cast(val)
    try:
        return cast(val)
    except ValueError:
        pass
    if not isinstance(val, str):
        raise SaltInvocationError("Expected integer or time string")
    if not re.match(r"^\d+(?:\.\d+)?[smhd]$", val):
        raise SaltInvocationError(f"Invalid time string format: {val}")
    raw, unit = float(val[:-1]), val[-1]
    if unit == "s":
        return cast(raw)
    raw *= 60
    if unit == "m":
        return cast(raw)
    raw *= 60
    if unit == "h":
        return cast(raw)
    raw *= 24
    if unit == "d":
        return cast(raw)
    raise RuntimeError("This path should not have been hit")  # pragma: no cover


def filter_state_internal_kwargs(kwargs: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """
    Removes state-internal kwargs from a kwargs dict.
    """
    # check_cmd is a valid argument to file.managed
    ignore = set(_STATE_INTERNAL_KEYWORDS) - {"check_cmd"}
    return {k: v for k, v in kwargs.items() if k not in ignore}


@typing.overload
def deserialize_csl(data: None) -> None: ...
@typing.overload
def deserialize_csl(data: str | list[str]) -> list[str]: ...
def deserialize_csl(data: str | list[str] | None) -> list[str] | None:
    """
    Ensure a value is a proper Python list, not a string containing
    a comma-separated list.
    """
    if data is None:
        return data
    if isinstance(data, str):
        # need to account for the empty string
        if not data:
            return []
        return data.split(",")
    try:
        return list(data)
    except TypeError:
        pass
    raise SaltInvocationError(f"Expected a comma-separated string list or a list, got {type(data)}")


K = typing.TypeVar("K")
V = typing.TypeVar("V")


@typing.overload
def filter_unset(
    data: Mapping[K, V | None],
    unset: None = None,
) -> dict[K, V]: ...


@typing.overload
def filter_unset(
    data: Mapping[K, V | EllipsisType],
    unset: EllipsisType,
) -> dict[K, V]: ...


@typing.overload
def filter_unset(
    data: Mapping[K, V],
    unset: object,
) -> dict[K, V]: ...


def filter_unset(
    data: Mapping[K, V],
    unset: object = None,
) -> dict[K, object]:
    return {k: v for k, v in data.items() if v is not unset}


def try_base64(data: str | bytes) -> tuple[bytes, bool]:
    """
    Given a string or bytes input, check if it is valid Base64
    and decode it if so. Otherwise, return the raw bytes.

    Returns a tuple of output, was_base64.
    """
    if isinstance(data, str):
        try:
            data = data.encode("ascii", "strict")
        except UnicodeEncodeError:
            return data.encode("utf-8"), False  # type: ignore
    elif isinstance(data, bytes):
        pass
    else:
        raise TypeError("try_base64 only works with strings and bytes")  # pragma: no cover
    try:
        decoded = base64.b64decode(data)
        if base64.b64encode(decoded) == data.replace(b"\n", b""):
            return decoded, True
        return data, False
    except (TypeError, ValueError):
        return data, False


def x_of(*, _min=1, _max=1, _predicate=bool, **kwargs):
    num_set = sum(map(_predicate, kwargs.values()))
    if _min <= num_set <= _max:
        return

    num_words = ("zero", "one", "two", "three", "four", "five", "six")

    def join(params, char=",", last="or"):
        ret = (char + " ").join(f"`{param}`" for param in params)
        if last and len(params) > 1:
            ret = f" {last}".join(ret.rsplit(char, maxsplit=1))
        return ret

    if _min == _max == 1:
        if num_set == 0:
            msg = "Either " + join(kwargs) + " is required"
        elif len(kwargs) == 2:
            msg = "Either " + join(kwargs) + " is required (exclusive)"
        else:
            msg = "Only specify either " + join(kwargs) + " (exclusive)"
    elif num_set < _min:
        msg = f"At least {num_words[_min]} of " + join(kwargs) + " must be passed"
    else:
        msg = f"At most {num_words[_max]} of " + join(kwargs) + " can be specified"
    raise SaltInvocationError(msg)


def one_of(*, _predicate=bool, **kwargs):
    return x_of(_predicate=_predicate, **kwargs)


try:
    safe_atomic_write = salt.utils.atomicfile.safe_atomic_write
except AttributeError:
    # Polyfill for <3008

    def safe_atomic_write(dst, data, backup_mode="", cachedir=""):
        """
        Create a temporary file with only user r/w perms, write the
        data and atomically copy it to the destination. Supports the
        Salt file backup mechanism.

        dst
            The path to write to.

        data
            String or bytes of data to write.

        backup_mode
            Optional parameter to override the configured
            :ref:`backup mode <file-state-backups>` explicitly.

        cachedir
            Optional parameter to override the configured
            cachedir explicitly. Backups are written into
            a subdirectory of this path called ``file_backup``.
        """
        mode = "wb" if isinstance(data, bytes) else "w"
        tmp = salt.utils.files.mkstemp(prefix=salt.utils.files.TEMPFILE_PREFIX)
        with salt.utils.files.fopen(tmp, mode) as tmp_:
            tmp_.write(data)
        salt.utils.files.copyfile(tmp, dst, backup_mode, cachedir)
        salt.utils.files.safe_rm(tmp)
