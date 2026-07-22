"""
Interface with the `Vault GPG secret engine <https://github.com/LeSuisse/vault-gpg-plugin/tree/main>`_.

.. versionadded:: 1.8.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
import re
import typing

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

if typing.TYPE_CHECKING:

    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltOpts
    from saltext.vault.utils._types import SaltStates

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __states__: SaltStates


log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__virtualname__ = "vault_gpg"


def __virtual__():
    return __virtualname__


def key_present(
    name,
    real_name=None,
    email=None,
    comment=None,
    key_bits=None,
    exportable=False,
    regenerate=False,
    mount="gpg",
):
    """
    Ensure a named GPG key is present.

    name
        Name of the key.

    real_name
        Real name of the identity associated with the GPG key.

    email
        Email of the identity associated with the GPG key.

    comment
        Comment of the identity associated with the GPG key.

    key_bits
        Bitlength of the generated GPG key.

    exportable
        If the raw private key should be exportable. Defaults to false.

    regenerate
        Whether to regenerate the key when the state parameters do not
        match an existing key with ``name``. Defaults to false.

        .. important::

            When set to true, deletes existing keys to follow the state
            of all parameters above. Ensure you have a good reason to enable this.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    ret = {"name": name, "result": True, "comment": "Key is already configured", "changes": {}}

    try:
        curr = __salt__["vault_gpg.read_key"](name, mount=mount)
        changes = {}
        if curr is None:
            changes["created"] = name
        elif not regenerate:
            return ret
        else:
            # Requires Salt 3008
            try:
                info = __salt__["gpg.read_key"](text=curr["public_key"])[0]
            except KeyError:
                ret["comment"] += "\nNote: `regenerate` requires Salt 3008, cannot inspect changes"
                return ret
            except IndexError:  # pragma: no cover
                ret["result"] = False
                ret["comment"] = (
                    "Failed to parse public key returned by server/no keys found in payload"
                )
                return ret
            ptrn = (
                r"^(?P<real_name>[^\(<]*?)(?:\s*\((?P<comment>.*)\))?(?:\s*<(?P<email>.*@.*)>)?\s*$"
            )
            uids = info.get("uids") or []
            if uids and (match := re.match(ptrn, uids[0])):
                groups = match.groupdict(default="")
                loc = locals()
                for var in ("real_name", "email", "comment"):
                    if loc[var] is not None and groups.get(var) != loc[var]:
                        changes[var] = {"old": groups.get(var), "new": loc[var]}
            if key_bits is not None and info["keyLength"] != str(key_bits):
                changes["key_bits"] = {"old": int(info["keyLength"]), "new": key_bits}
            if exportable is not curr["exportable"]:
                changes["exportable"] = {"old": curr["exportable"], "new": exportable}
            if not changes:
                return ret
        changes["fingerprint"] = {"old": curr["fingerprint"] if curr else None, "new": "<TBD>"}
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Would have {'regenerated' if curr else 'created'} the key"
            ret["changes"] = changes
            return ret
        if curr:
            __salt__["vault_gpg.delete_key"](name, mount=mount)
            ret["changes"]["deleted"] = name
        __salt__["vault_gpg.create_key"](
            name,
            real_name=real_name,
            email=email,
            comment=comment,
            key_bits=key_bits,
            exportable=exportable,
            mount=mount,
        )
        ret["changes"].update(changes)
        new = __salt__["vault_gpg.read_key"](name, mount=mount)
        ret["changes"]["fingerprint"] = {
            "old": curr["fingerprint"] if curr else None,
            "new": new["fingerprint"],
        }
        ret["comment"] = f"{'Regenerated' if curr else 'Created'} the key"

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


def key_absent(name, mount="gpg"):
    """
    Ensure a named GPG key is absent.

    name
        Name of the key.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    ret = {"name": name, "result": True, "comment": "Key is already absent", "changes": {}}

    try:
        curr = __salt__["vault_gpg.read_key"](name, mount=mount)
        if curr is None:
            return ret
        ret["changes"]["deleted"] = name
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Would have deleted the key"
            return ret
        __salt__["vault_gpg.delete_key"](name, mount=mount)
        ret["comment"] = "Deleted the key"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


def keychain_present(name, mount="gpg", **kwargs):
    """
    Ensure the named GPG key has been imported in the specified GPG keychain.
    This is just a convenience wrapper around :py:func:`gpg.present <salt.states.gpg.present>`,
    most keyword arguments are passed through. See there for parameter documentation.

    .. important::

        This functionality requires the GPG modules from Salt >=3008.

    .. hint::

        You can achieve similar behavior by using Jinja, but risk crashing
        the whole state compilation when the Vault connection has issues.

        .. code-block:: jinja

            {%- set signing_key = salt["vault_gpg.read_key"]("my_key", mount="my_gpg_mount") %}

            Ensure my signing key can be used by file.managed source_sig:
              gpg.present:
                - name: {{ signing_key["fingerprint"][-16:].upper() }}
                - text: {{ signing_key["public_key"] | json }}

    name
        Name of the key (on the Vault mount).

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.

    kwargs
        Most other parameters (exception: ``text``, ``source``, and ``keys``)
        are passed through to :py:func:`gpg.present <salt.states.gpg.present>`.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The keychain is in the correct state",
        "changes": {},
    }

    try:
        key = __salt__["vault_gpg.read_key"](name, mount=mount)
        if key is None:
            ret["result"] = False
            ret["comment"] = f"Key {name} does not exist."
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] += (
                    " Not failing because test mode is active. If the key is created"
                    " during the same run, you can ignore this message."
                )
            return ret
        fp = key["fingerprint"][-16:].upper()
        kwargs["text"] = key["public_key"]
        kwargs["keys"] = None
        kwargs["source"] = None
        return __states__["gpg.present"](fp, **kwargs)
    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret
