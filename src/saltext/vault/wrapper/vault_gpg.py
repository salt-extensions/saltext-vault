"""
SSH wrapper for the :py:mod:`vault_gpg <saltext.vault.modules.vault_gpg>` execution module.

See there for documentation.

.. versionadded:: 1.8.0
"""

import base64
import logging
import typing

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules.vault_gpg import _decrypt_cmd
from saltext.vault.modules.vault_gpg import _norm_format
from saltext.vault.modules.vault_gpg import create_key
from saltext.vault.modules.vault_gpg import decrypt
from saltext.vault.modules.vault_gpg import delete_key
from saltext.vault.modules.vault_gpg import export_private_key
from saltext.vault.modules.vault_gpg import export_public_key
from saltext.vault.modules.vault_gpg import import_key
from saltext.vault.modules.vault_gpg import list_keys
from saltext.vault.modules.vault_gpg import read_key
from saltext.vault.modules.vault_gpg import show_session_key
from saltext.vault.modules.vault_gpg import sign
from saltext.vault.modules.vault_gpg import verify
from saltext.vault.utils.functools import namespaced_function
from saltext.vault.utils.vault import helpers

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltGrains
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltOpts

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __grains__: SaltGrains

log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__virtualname__ = "vault_gpg"


def __virtual__():
    return __virtualname__


globals_dict = globals()

_decrypt_cmd = namespaced_function(_decrypt_cmd, globals_dict)
_norm_format = namespaced_function(_norm_format, globals_dict)
create_key = namespaced_function(create_key, globals_dict)
decrypt = namespaced_function(decrypt, globals_dict)
delete_key = namespaced_function(delete_key, globals_dict)
export_private_key = namespaced_function(export_private_key, globals_dict)
export_public_key = namespaced_function(export_public_key, globals_dict)
import_key = namespaced_function(import_key, globals_dict)
list_keys = namespaced_function(list_keys, globals_dict)
read_key = namespaced_function(read_key, globals_dict)
show_session_key = namespaced_function(show_session_key, globals_dict)
sign = namespaced_function(sign, globals_dict)
verify = namespaced_function(verify, globals_dict)


def _get_file_or_data(
    data: str | bytes | None, path: str | None, b64: str | bytes | None = None
) -> bytes:
    """
    Return file contents as bytes, otherwise encode [ciphertext] string.
    Overrides the function of the same name in the execution module.

    data
        Raw data value

    path
        Path to a file to load

    b64
        Base64-encoded data
    """
    if data is not None:
        try:
            ret = typing.cast(bytes, data.encode())  # type: ignore
        except AttributeError:
            ret = typing.cast(bytes, data)  # please don't pass in other stuff :)
        return ret
    if b64 is not None:
        ret, was_b64 = helpers.try_base64(b64)
        if not was_b64:
            raise SaltInvocationError("Received unexpected non-Base64-encoded value for parameter")
        return ret
    if path is not None:
        if __salt__["file.file_exists"](path):
            return base64.b64decode(__salt__["hashutil.base64_encodefile"](path))
        raise CommandExecutionError(f"Specified path {path} does not exist")
    raise RuntimeError("This should not have been hit")  # pragma: no cover


def _write_path(path: str, data: str | bytes):
    if not isinstance(data, bytes):
        data = data.encode()
    parent = __salt__["file.dirname"](path)
    __salt__["file.mkdir"](parent)
    __salt__["file.touch"](path)
    __salt__["file.set_mode"](path, "0600")
    # There seems to be a bug in Salt-SSH where this can be interpreted as a kwarg
    while (encoded := base64.b64encode(data)).endswith(b"="):
        data += b"\n"
    __salt__["hashutil.base64_decodefile"](encoded.decode(), path)
