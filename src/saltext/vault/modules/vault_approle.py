"""
Manage the Vault (or OpenBao) AppRole auth backend, request and cache
AppRole SecretIDs.

.. versionadded:: 1.8.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from datetime import datetime
from datetime import timezone
from typing import TYPE_CHECKING

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault
from saltext.vault.utils.vault import approle

if TYPE_CHECKING:
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

__func_alias__ = {"list_": "list"}
__virtualname__ = "vault_approle"


def __virtual__():
    return __virtualname__


def list_(mount="approle"):
    """
    List existing AppRoles.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.list

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role" {
            capabilities = ["list"]
        }

    mount
        Name of the mount point the AppRole auth backend is mounted to.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).list_approles(mount=mount)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read(name, mount="approle"):
    """
    Read an AppRole configuration.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.read salt_master

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>" {
            capabilities = ["read"]
        }

    name
        Name of the AppRole.

    mount
        Name of the mount point the AppRole auth backend is mounted to.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).read_approle(name, mount=mount)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write(
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
    Write an AppRole configuration.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.write salt_master token_num_uses=0

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>" {
            capabilities = ["create", "update"]
        }

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
    try:
        return vault.get_approle_api(__opts__, __context__).write_approle(
            name,
            bind_secret_id=bind_secret_id,
            secret_id_bound_cidrs=secret_id_bound_cidrs,
            secret_id_num_uses=secret_id_num_uses,
            secret_id_ttl=secret_id_ttl,
            local_secret_ids=local_secret_ids,
            token_ttl=token_ttl,
            token_max_ttl=token_max_ttl,
            token_policies=token_policies,
            token_bound_cidrs=token_bound_cidrs,
            token_explicit_max_ttl=token_explicit_max_ttl,
            token_no_default_policy=token_no_default_policy,
            token_num_uses=token_num_uses,
            token_period=token_period,
            token_type=token_type,
            alias_metadata=alias_metadata,
            token_strictly_bind_ip=token_strictly_bind_ip,
            mount=mount,
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete(name, mount="approle"):
    """
    Delete an AppRole.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.delete salt_master_bak

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>" {
            capabilities = ["delete"]
        }

    name
        Name of the AppRole.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).delete_approle(name, mount=mount)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def get_role_id(name, wrap=False, mount="approle"):
    """
    Get an AppRole's RoleID.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.get_role_id salt_master

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/role-id" {
            capabilities = ["read"]
        }

    name
        Name of the AppRole.

    wrap
        Instead of returning the RoleID, return a response wrapping token
        that is valid for this amount of time. Defaults to false.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        ret = vault.get_approle_api(__opts__, __context__).read_role_id(
            name, wrap=wrap, mount=mount
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    return str(ret)


def get_secret_id(
    name,
    metadata=None,
    cidr_list=None,
    token_bound_cidrs=None,
    num_uses=None,
    ttl=None,
    cache=None,
    min_ttl=60,
    wrap=False,
    all_data=False,
    mount="approle",
):
    """
    Generate a SecretID for an AppRole.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.get_secret_id salt_master_bak

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id" {
            capabilities = ["create", "update"]
        }

    name
        Name of the AppRole.

    metadata
        A string-valued dictionary of metadata tied to this particular SecretID.

    cidr_list
        List of CIDR blocks enforcing SecretIDs to be used from specific set of
        IP addresses.
        If ``secret_id_bound_cidrs`` is set on the role, then this list of CIDR
        blocks should be a subset of the CIDR blocks listed on the role.

    token_bound_cidrs
        A list of CIDR blocks which can use the auth tokens generated by this SecretID.
        Overrides any role-set value, but must be a subset thereof.

    num_uses
        Number of times this SecretID can be used, after which the SecretID expires.
        A value of zero will allow unlimited uses. Overrides ``secret_id_num_uses``
        role option when supplied. May not be higher than role's ``secret_id_num_uses``.

    ttl
        Duration in seconds (``3600``) or an integer time unit (``60m``) after which
        this SecretID expires.
        Overrides ``secret_id_ttl`` role option when supplied.
        May not be longer than role's ``secret_id_ttl``.

    cache
        Whether to cache issued SecretIDs. Disabled when ``wrap`` is set,
        otherwise defaults to true.
        Set this to a string to be able to issue distinct SecretIDs for
        the same role.

    min_ttl
        When using cached data, ensure the SecretID is at least valid for this amount of time.
        Can be an integer, which is interpreted as seconds, or a time string such as ``1h``.
        Defaults to 60 (seconds).

    wrap
        Instead of returning the SecretID, return a response wrapping token that is valid for
        this amount of time.
        Can be an integer, which is interpreted as seconds, or a time string such as ``1h``.
        Defaults to false.

    all_data
        Return a dictionary of information, including ``[wrapping_]accessor``, duration, expire_time etc.
        If this is false, only returns the SecretID/wrapping token as a string.
        Defaults to false.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    if cache is None:
        cache = not bool(wrap)
    if wrap and cache:
        raise SaltInvocationError(
            "Cannot cache wrapped responses. Disable either `wrap` or `cache`."
        )
    secid_store = None
    ckey = None
    if cache:
        ckey = f"secid.{mount}.{name}." + ("default" if cache is True else cache)
        secid_store = approle.get_store(__opts__, __context__)
        try:
            secret_id = secid_store.get(ckey, valid_for=min_ttl)
        except vault.VaultException:
            pass
        else:
            if not secret_id:
                pass
            elif all_data:
                return secret_id.to_dict()
            else:
                return str(secret_id)

    try:
        secret_id = vault.get_approle_api(__opts__, __context__).generate_secret_id(
            name,
            metadata=metadata,
            cidr_list=cidr_list,
            token_bound_cidrs=token_bound_cidrs,
            num_uses=num_uses,
            ttl=ttl,
            wrap=wrap,
            mount=mount,
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if cache and ckey and secid_store:
        secid_store.store(ckey, secret_id)
    if all_data:
        return secret_id.to_dict()
    return str(secret_id)


def lookup_secret_id(name, secret_id=None, accessor=None, mount="approle"):
    """
    Lookup Secret ID meta information.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.lookup_secret_id salt_master accessor=abcde1-f234...

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id/lookup" {
            capabilities = ["create", "update"]
        }

        path "auth/<mount>/role/<name>/secret-id-accessor/lookup" {
            capabilities = ["create", "update"]
        }

    name
        Name of the AppRole the SecretID belongs to.

    secret_id
        A SecretID to look up. Specify either this or ``accessor``.

    accessor
        An accessor for the SecretID to look up. Specify either this or ``secret_id``.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        if secret_id:
            return vault.get_approle_api(__opts__, __context__).read_secret_id(
                name, secret_id=secret_id, mount=mount
            )
        if accessor:
            return vault.get_approle_api(__opts__, __context__).read_secret_id(
                name, accessor=accessor, mount=mount
            )
        raise TypeError("Either secret_id or accessor is required")
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def destroy_secret_id(name, secret_id=None, accessor=None, mount="approle"):
    """
    Destroy a Secret ID.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.destroy_secret_id salt_master accessor=abcde1-f234...

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id/destroy" {
            capabilities = ["create", "update"]
        }

        path "auth/<mount>/role/<name>/secret-id-accessor/destroy" {
            capabilities = ["create", "update"]
        }

    name
        Name of the AppRole the SecretID belongs to.

    secret_id
        SecretID to destroy. Specify either this or ``accessor``.

    accessor
        Accessor for the SecretID to destroy. Specify either this or ``secret_id``.

    mount
        Name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        if secret_id:
            return vault.get_approle_api(__opts__, __context__).destroy_secret_id(
                name, secret_id=secret_id, mount=mount
            )
        if accessor:
            return vault.get_approle_api(__opts__, __context__).destroy_secret_id(
                name, accessor=accessor, mount=mount
            )
        raise TypeError("Either secret_id or accessor is required")
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def clear_cached(name=None, cache=None, mount=None, flush_on_failure=True):
    """
    Flush cached SecretIDs. Attempts revocation.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.clear_cached

    Recommended policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id-accessor/destroy" {
            capabilities = ["create", "update"]
        }

    name
        Only clear SecretIDs for this role name.

    cache
        Only clear SecretIDs with this cache name.

    mount
        Only clear SecretIDs from this backend mount.

    flush_on_failure
        If a revocation fails, remove the lease from cache anyways.
        Defaults to true.
    """
    return approle.get_store(__opts__, __context__).destroy_cached(
        match=approle.create_cache_pattern(name=name, cache=cache, mount=mount),
        flush_on_failure=flush_on_failure,
    )


def list_cached(name=None, cache=None, mount=None):
    """
    List cached AppRoles matching specified parameters.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_approle.list_cached name=myrole mount=database
            salt '*' vault_approle.list_cached mount=database
            salt '*' vault_approle.list_cached

    name
        Only list credentials using this AppRole name.

    mount
        Only list credentials from this mount.

    cache
        Only list credentials using this cache name (refer to :py:func:`get_secret_id <saltext.vault.modules.vault_approle.get_secret_id>`
        for details).
    """
    creds_cache = approle.get_store(__opts__, __context__)
    info = creds_cache.list_cached_info(
        match=approle.create_cache_pattern(name=name, mount=mount, cache=cache)
    )
    for secid in info.values():
        for val in ("creation_time", "expire_time"):
            if val in secid:
                secid[val] = (
                    datetime.fromtimestamp(secid[val], tz=timezone.utc)
                    .astimezone()
                    .strftime("%Y-%m-%d %H:%M:%S %Z")
                )
    return info
