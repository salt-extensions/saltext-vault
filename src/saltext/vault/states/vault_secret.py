"""
Manage Vault KV v1/v2 secrets statefully.

.. versionadded:: 1.2.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import copy
import logging

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltException
from salt.exceptions import SaltInvocationError

log = logging.getLogger(__name__)


def present(name, values, sync=False):
    """
    Ensure a secret is present as specified.
    Does not report a diff.

    name
        The path of the secret.

    values
        A mapping of values the secret should expose.

    sync
        Ensure the secret only exposes ``values`` and delete unspecified ones.
        Defaults to false, which results in patching (merging over) existing data
        and deleting keys that are set to ``None``/``null``. For details, see
        https://datatracker.ietf.org/doc/html/draft-ietf-appsawg-json-merge-patch-07
    """
    # TODO: manage KV v2 metadata?
    ret = {
        "name": name,
        "result": True,
        "comment": "The secret is already present as specified",
        "changes": {},
    }
    try:
        try:
            current = __salt__["vault.read_secret"](name)
        except CommandExecutionError as err:
            # VaultNotFoundError should be subclassed to
            # CommandExecutionError and not re-raised by the
            # execution module @FIXME?
            if "VaultNotFoundError" not in str(err):
                raise
            current = None
        else:
            if sync:
                if current == values:
                    return ret
            else:

                def apply_json_merge_patch(data, patch):
                    if not patch:
                        return data
                    if not isinstance(data, dict) or not isinstance(patch, dict):
                        raise ValueError("Data and patch must be dictionaries.")

                    for key, value in patch.items():
                        if value is None:
                            data.pop(key, None)
                        elif isinstance(value, dict):
                            data[key] = apply_json_merge_patch(data.get(key, {}), value)
                        else:
                            data[key] = value
                    return data

                new = apply_json_merge_patch(copy.deepcopy(current), values)
                if new == current:
                    return ret
        verb = "patch" if current is not None and not sync else "write"
        pp = "patched" if verb == "patch" else "written"
        ret["changes"][pp] = name
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Would have {pp} the secret"
            return ret
        if not __salt__[f"vault.{verb}_secret"](name, **values):
            # Only read_secret raises exceptions sadly FIXME?
            raise CommandExecutionError(f"Failed to {verb} secret, see logs for details")
        ret["comment"] = f"The secret was {pp}"
    except SaltException as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret


def absent(name, operation="delete"):
    """
    Ensure a secret is absent. This operates only on the most recent version
    for delete/destroy. Currently does not destroy/wipe a secret that has
    been made unreadable in some other way.

    name
        The path of the secret.

    operation
        The operation to perform to remove the secret. Only relevant for KV v2.
        Options are: ``delete`` (meaning: soft-delete), ``destroy`` (meaning delete unrecoverably)
        and ``wipe`` (forget about the secret completely). Defaults to ``delete``.
        KV v1 secrets are always wiped since the backend does not support versioning.
    """
    valid_ops = ("delete", "destroy", "wipe")
    if operation not in valid_ops:
        raise SaltInvocationError(f"Invalid operation '{operation}'. Valid: {', '.join(valid_ops)}")
    ret = {
        "name": name,
        "result": True,
        "comment": "The secret is already absent",
        "changes": {},
    }
    pp = "destroyed" if operation == "destroy" else operation + "d"
    try:
        try:
            __salt__["vault.read_secret"](name)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            return ret
        ret["changes"][pp] = name
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Would have {pp} the secret"
            return ret
        if not __salt__[f"vault.{operation}_secret"](name):
            # Only read_secret raises exceptions sadly FIXME?
            raise CommandExecutionError(f"Failed to {operation} secret, see logs for details")
        ret["comment"] = f"The secret has been {pp}"
    except SaltException as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret
