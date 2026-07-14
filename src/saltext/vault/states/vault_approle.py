"""
Manage the Vault (or OpenBao) AppRole auth backend.

.. versionadded:: 1.8.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from typing import TYPE_CHECKING

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from salt.utils.dictdiffer import diff

from saltext.vault.utils.vault.helpers import timestring_map

if TYPE_CHECKING:

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

__virtualname__ = "vault_approle"


def __virtual__():
    return __virtualname__


def present(
    name,
    bind_secret_id=None,
    secret_id_bound_cidrs=None,
    secret_id_num_uses=None,
    secret_id_ttl=None,
    local_secret_ids=None,
    token_ttl=None,
    token_max_ttl=None,
    token_policies=None,
    token_bound_cidrs=None,
    token_explicit_max_ttl=None,
    token_no_default_policy=None,
    token_num_uses=None,
    token_period=None,
    token_type=None,
    alias_metadata=None,
    token_strictly_bind_ip=None,
    mount="approle",
):
    """
    Ensure an AppRole is present as specified.

    name
        Name of the AppRole.

    secret_id_bound_cidrs
        List of CIDR blocks that specifies blocks of IP addresses which can
        perform the login operation

    secret_id_num_uses
        Number of times any particular SecretID can be used to fetch a token from
        this AppRole, after which the SecretID by default will expire. A value of
        zero will allow unlimited uses. However, this option may be overridden by
        the request's 'num_uses' field when generating a SecretID.

    secret_id_ttl
        Duration in either an integer number of seconds (3600) or an integer
        time unit (60m) after which by default any SecretID expires.
        A value of zero will allow the SecretID to not expire. However, this option
        may be overridden by the request's 'ttl' field when generating a SecretID.

    local_secret_ids
        If set, the SecretIDs generated using this role will be cluster local.
        This can only be set during role creation and once set, it can't be reset later.

    token_ttl
        Incremental lifetime for generated tokens. This value will be
        referenced at renewal time.

    token_max_ttl
        Maximum lifetime for generated tokens. This value will be
        referenced at renewal time.

    token_policies
        List of token policies to encode onto generated tokens. Depending on the
        auth method, this list may be supplemented by user/group/other values.

    token_bound_cidrs
        List of CIDR blocks that specifies blocks of IP addresses which can
        authenticate successfully, and ties the resulting token to these blocks as well.

    token_explicit_max_ttl
        If set, will encode an explicit max TTL onto the token.
        This is a hard cap, even if token_ttl and token_max_ttl would otherwise
        allow a renewal.

    token_no_default_policy
        If set, the default policy will not be set on generated tokens;
        otherwise it will be added to the policies set in ``token_policies``.

    token_num_uses
        Maximum number of times a generated token may be used (within its lifetime);
        0 means unlimited. If you require the token to have the ability to create
        child tokens, you will need to set this value to 0.

    token_period
        Maximum allowed period value when a periodic token is requested from this role.

    token_type
        Type of token that should be generated. Can be ``service``, ``batch``,
        or ``default`` to use the mount's tuned default.
        For token store roles, there are two additional possibilities:
        ``default-service`` and ``default-batch``, which specify the type
        to return unless the client requests a different type at generation time.

    alias_metadata
        .. important::
            Only available on Vault, not OpenBao.

        Map of arbitrary string to arbitrary string that pre-populates the custom metadata
        of new entity aliases created at login.

    token_strictly_bind_ip
        .. important::
            Only available on OpenBao, not Vault.

        If set, the token will be restricted to the source IP address making the initial login request.
        This conflicts with ``token_bound_cidrs``.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "AppRole is present as specified",
        "changes": {},
    }
    verb = "create"
    changes = {}

    try:
        try:
            curr = __salt__["vault_approle.read"](name, mount=mount)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            curr = None
            changes["created"] = name
        else:
            for param, wanted in (
                ("bind_secret_id", bind_secret_id),
                ("secret_id_num_uses", secret_id_num_uses),
                ("local_secret_ids", local_secret_ids),
                ("token_no_default_policy", token_no_default_policy),
                ("token_num_uses", token_num_uses),
                ("token_type", token_type),
            ):
                if wanted is not None and curr[param] != wanted:
                    changes[param] = {"old": curr[param], "new": wanted}
            for param, wanted in (
                ("secret_id_bound_cidrs", secret_id_bound_cidrs),
                ("token_policies", token_policies),
                ("token_bound_cidrs", token_bound_cidrs),
            ):
                if wanted is not None and (old_set := set(curr[param] or [])) != (
                    new_set := set(wanted)
                ):
                    changes[param] = {
                        "added": list(sorted(new_set.difference(old_set))),
                        "removed": list(sorted(old_set.difference(new_set))),
                    }
            for param, wanted in (
                ("secret_id_ttl", secret_id_ttl),
                ("token_ttl", token_ttl),
                ("token_max_ttl", token_max_ttl),
                ("token_explicit_max_ttl", token_explicit_max_ttl),
                ("token_period", token_period),
            ):
                if wanted is not None and curr[param] != timestring_map(wanted):
                    changes[param] = {"old": curr[param], "new": wanted}
            if (
                alias_metadata is not None
                and "alias_metadata" in curr
                and curr["alias_metadata"] != alias_metadata
            ):
                meta_diff = diff(alias_metadata, curr["alias_metadata"])
                changes["alias_metadata"] = {
                    "added": list(meta_diff.added()),
                    "changed": list(meta_diff.changed()),
                    "removed": list(meta_diff.removed()),
                }
            if (
                token_strictly_bind_ip is not None
                and "token_strictly_bind_ip" in curr
                and curr["token_strictly_bind_ip"] is not token_strictly_bind_ip
            ):
                changes["token_strictly_bind_ip"] = {
                    "old": curr["token_strictly_bind_ip"],
                    "new": token_strictly_bind_ip,
                }

        if not changes:
            return ret

        params = {
            "bind_secret_id": bind_secret_id,
            "secret_id_bound_cidrs": secret_id_bound_cidrs,
            "secret_id_num_uses": secret_id_num_uses,
            "secret_id_ttl": secret_id_ttl,
            "local_secret_ids": local_secret_ids,
            "token_ttl": token_ttl,
            "token_max_ttl": token_max_ttl,
            "token_policies": token_policies,
            "token_bound_cidrs": token_bound_cidrs,
            "token_explicit_max_ttl": token_explicit_max_ttl,
            "token_no_default_policy": token_no_default_policy,
            "token_num_uses": token_num_uses,
            "token_period": token_period,
            "token_type": token_type,
            "alias_metadata": alias_metadata,
            "token_strictly_bind_ip": token_strictly_bind_ip,
        }
        if curr and "token_type" in changes and token_type == "batch":
            # Switching the token type needs to would need to token_period
            # and token_num_uses, which needs a policy allowing those paths.
            # Just recreate the AppRole
            verb = "recreate"
            for param, wanted in (
                ("bind_secret_id", bind_secret_id),
                ("secret_id_num_uses", secret_id_num_uses),
                ("local_secret_ids", local_secret_ids),
                ("token_no_default_policy", token_no_default_policy),
                ("token_num_uses", token_num_uses),
                ("secret_id_bound_cidrs", secret_id_bound_cidrs),
                ("token_policies", token_policies),
                ("token_bound_cidrs", token_bound_cidrs),
                ("secret_id_ttl", secret_id_ttl),
                ("token_ttl", token_ttl),
                ("token_max_ttl", token_max_ttl),
                ("token_explicit_max_ttl", token_explicit_max_ttl),
                ("token_period", token_period),
            ):
                if token_type == "batch" and param in ("token_period", "token_num_uses"):
                    if curr[param] != 0:
                        changes[param] = {"old": curr[param], "new": 0}
                    continue
                if wanted is None:
                    params[param] = curr[param]
            if "alias_metadata" in curr and alias_metadata is None:
                params["alias_metadata"] = curr["alias_metadata"]
            if "token_strictly_bind_ip" in curr and token_strictly_bind_ip is None:
                params["token_strictly_bind_ip"] = curr["token_strictly_bind_ip"]
        elif curr:
            verb = "update"

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"AppRole '{name}' would have been {verb}d"
            ret["changes"] = changes
            return ret

        if verb == "recreate":
            __salt__["vault_approle.delete"](name, mount=mount)
            # Ensure we tell the user if the write fails, but the existing AppRole was deleted successfully
            ret["changes"]["deleted"] = name
        __salt__["vault_approle.write"](
            name,
            **params,
            mount=mount,
        )
        ret["comment"] = f"AppRole '{name}' has been {verb}d"
        ret["changes"] = changes

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
    return ret


def absent(name, mount="approle"):
    """
    Ensure an AppRole is not present.

    name
        Name of the AppRole.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "AppRole is already absent",
        "changes": {},
    }
    try:
        try:
            __salt__["vault_approle.read"](name, mount=mount)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            return ret

        ret["changes"]["deleted"] = name
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"AppRole '{name}' would have been deleted"
            return ret

        __salt__["vault_approle.delete"](name, mount=mount)
        ret["comment"] = f"AppRole '{name}' has been deleted"

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret
