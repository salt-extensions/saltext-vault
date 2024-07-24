"""
Manage the Vault database secret engine, request and cache
leased database credentials.

.. versionadded:: 1.1.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging

from salt.defaults import NOT_SET
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault import db as vaultdb
from saltext.vault.utils.vault.helpers import timestring_map

log = logging.getLogger(__name__)


def connection_present(
    name,
    plugin,
    version=None,
    verify=True,
    allowed_roles=None,
    root_rotation_statements=None,
    password_policy=None,
    rotate=True,
    force=False,
    mount="database",
    **kwargs,
):
    """
    Ensure a database connection is present as specified.

    name
        The name of the database connection.

    plugin
        The name of the database plugin. Known plugins to this module are:
        ``cassandra``, ``couchbase``, ``elasticsearch``, ``influxdb``, ``hanadb``, ``mongodb``,
        ``mongodb_atlas``, ``mssql``, ``mysql``, ``oracle``, ``postgresql``, ``redis``,
        ``redis_elasticache``, ``redshift``, ``snowflake``.
        If you pass an unknown plugin, make sure its Vault-internal name can be formatted
        as ``{plugin}-database-plugin`` and to pass all required parameters as kwargs.

    version
        Specifies the semantic version of the plugin to use for this connection.

    verify
        Verify the connection during initial configuration. Defaults to True.

    allowed_roles
        List of the roles allowed to use this connection. ``["*"]`` means any role
        can use this connection. Defaults to empty (no role can use it).

    root_rotation_statements
        Specifies the database statements to be executed to rotate the root user's credentials.
        See the plugin's API page for more information on support and formatting for this parameter.

    password_policy
        The name of the password policy to use when generating passwords for this database.
        If not specified, this will use a default policy defined as:
        20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.

    rotate
        Rotate the root credentials after plugin setup. Defaults to True.

    force
        When the plugin changes, this state fails to protect from accidental errors.
        Set force to True to delete existing connections with the same name and a
        different plugin type. Defaults to False.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.

    kwargs
        Different plugins require different parameters. You need to make sure that you pass them
        as supplemental keyword arguments. For known plugins, the required arguments will
        be checked.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The connection is present as specified",
        "changes": {},
    }
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    def _diff_params(current):
        nonlocal version, allowed_roles, root_rotation_statements, password_policy, kwargs
        diff_params = (
            ("plugin_version", version),
            ("allowed_roles", allowed_roles),
            ("root_credentials_rotate_statements", root_rotation_statements),
            ("password_policy", password_policy),
            # verify_connection is not reported
        )
        changed = {}
        for param, arg in diff_params:
            if arg is None:
                continue
            # Strip statements to avoid tripping over final newlines
            if param.endswith("statements"):
                arg = [x.rstrip() for x in arg]
                if param in current:
                    current[param] = [x.rstrip() for x in current[param]]
            if param not in current or current[param] != arg:
                changed.update({param: {"old": current.get(param), "new": arg}})
        for param, val in kwargs.items():
            if param == "password":
                # password is not reported
                continue
            if (
                param not in current["connection_details"]
                or current["connection_details"][param] != val
            ):
                changed.update(
                    {param: {"old": current["connection_details"].get(param), "new": val}}
                )
        return changed

    try:
        current = __salt__["vault_db.fetch_connection"](name, mount=mount)
        changes = {}

        if current:
            if current["plugin_name"] != vaultdb.get_plugin_name(plugin):
                if not force:
                    raise CommandExecutionError(
                        "Cannot change plugin type without deleting the existing connection. "
                        "Set force: true to override."
                    )
                if not __opts__["test"]:
                    __salt__["vault_db.delete_connection"](name, mount=mount)
                ret["changes"]["deleted_for_plugin_change"] = name
                current = None
            else:
                changes = _diff_params(current)
                if not changes:
                    return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                f"Connection `{name}` would have been {'updated' if current else 'created'}"
            )
            ret["changes"].update(changes)
            if not current:
                ret["changes"]["created"] = name
            return ret

        if current and "password" in kwargs:
            kwargs.pop("password")

        __salt__["vault_db.write_connection"](
            name,
            plugin,
            version=version,
            verify=verify,
            allowed_roles=allowed_roles,
            root_rotation_statements=root_rotation_statements,
            password_policy=password_policy,
            rotate=rotate,
            mount=mount,
            **kwargs,
        )
        new = __salt__["vault_db.fetch_connection"](name, mount=mount)

        if new is None:
            raise CommandExecutionError(
                "There were no errors during role management, but it is still reported as absent."
            )
        if not current:
            ret["changes"]["created"] = name

        new_diff = _diff_params(new)
        if new_diff:
            ret["result"] = False
            ret["comment"] = (
                "There were no errors during connection management, but "
                f"the reported parameters do not match: {new_diff}"
            )
            return ret
        ret["changes"].update(changes)
        ret["comment"] = f"Connection `{name}` has been {'updated' if current else 'created'}"

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        # do not reset changes

    return ret


def connection_absent(name, mount="database"):
    """
    Ensure a database connection is absent.

    name
        The name of the connection.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        current = __salt__["vault_db.fetch_connection"](name, mount=mount)

        if current is None:
            ret["comment"] = f"Connection `{name}` is already absent."
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Connection `{name}` would have been deleted."
            return ret

        __salt__["vault_db.delete_connection"](name, mount=mount)

        if __salt__["vault_db.fetch_connection"](name, mount=mount) is not None:
            raise CommandExecutionError(
                "There were no errors during connection deletion, "
                "but it is still reported as present."
            )
        ret["comment"] = f"Connection `{name}` has been deleted."

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_present(
    name,
    connection,
    creation_statements,
    default_ttl=None,
    max_ttl=None,
    revocation_statements=None,
    rollback_statements=None,
    renew_statements=None,
    credential_type=None,
    credential_config=None,
    mount="database",
):
    """
    Ensure a regular database role is present as specified.

    name
        The name of the database role.

    connection
        The name of the database connection this role applies to.

    creation_statements
        Specifies a list of database statements executed to create and configure a user,
        usually templated with {{name}} and {{password}}. Required.

    default_ttl
        Specifies the TTL for the leases associated with this role. Accepts time suffixed
        strings (1h) or an integer number of seconds. Defaults to system/engine default TTL time.

    max_ttl
        Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed
        strings (1h) or an integer number of seconds. Defaults to sys/mounts's default TTL time;
        this value is allowed to be less than the mount max TTL (or, if not set,
        the system max TTL), but it is not allowed to be longer.

    revocation_statements
        Specifies a list of database statements to be executed to revoke a user.

    rollback_statements
        Specifies a list of database statements to be executed to rollback a create operation
        in the event of an error. Availability and formatting depend on the specific plugin.

    renew_statements
        Specifies a list of database statements to be executed to renew a user.
        Availability and formatting depend on the specific plugin.

    credential_type
        Specifies the type of credential that will be generated for the role.
        Options include: ``password``, ``rsa_private_key``. Defaults to ``password``.
        See the plugin's API page for credential types supported by individual databases.

    credential_config
        Specifies the configuration for the given ``credential_type`` as a mapping.
        For ``password``, only ``password_policy`` can be passed.
        For ``rsa_private_key``, ``key_bits`` (defaults to 2048) and ``format``
        (defaults to ``pkcs8``) are available.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    if not isinstance(creation_statements, list):
        creation_statements = [creation_statements]
    if revocation_statements and not isinstance(revocation_statements, list):
        revocation_statements = [revocation_statements]
    if rollback_statements and not isinstance(rollback_statements, list):
        rollback_statements = [rollback_statements]
    if renew_statements and not isinstance(renew_statements, list):
        renew_statements = [renew_statements]

    def _diff_params(current):
        nonlocal connection, creation_statements, default_ttl, max_ttl, revocation_statements
        nonlocal rollback_statements, renew_statements, credential_type, credential_config

        diff_params = (
            ("db_name", connection),
            ("creation_statements", creation_statements),
            ("default_ttl", timestring_map(default_ttl)),
            ("max_ttl", timestring_map(max_ttl)),
            ("revocation_statements", revocation_statements),
            ("rollback_statements", rollback_statements),
            ("renew_statements", renew_statements),
            ("credential_type", credential_type),
            ("credential_config", credential_config),
        )
        changed = {}
        for param, arg in diff_params:
            if arg is None:
                continue
            # Strip statements to avoid tripping over final newlines
            if param.endswith("statements"):
                arg = [x.rstrip() for x in arg]
                if param in current:
                    current[param] = [x.rstrip() for x in current[param]]
            if param not in current or current[param] != arg:
                changed.update({param: {"old": current.get(param), "new": arg}})
        return changed

    try:
        current = __salt__["vault_db.fetch_role"](name, static=False, mount=mount)

        if current:
            changed = _diff_params(current)
            if not changed:
                ret["comment"] = "Role is present as specified"
                return ret
            ret["changes"].update(changed)

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Role `{name}` would have been {'updated' if current else 'created'}"
            if not current:
                ret["changes"]["created"] = name
            return ret

        __salt__["vault_db.write_role"](
            name,
            connection,
            creation_statements,
            default_ttl=default_ttl,
            max_ttl=max_ttl,
            revocation_statements=revocation_statements,
            rollback_statements=rollback_statements,
            renew_statements=renew_statements,
            credential_type=credential_type,
            credential_config=credential_config,
            mount=mount,
        )
        new = __salt__["vault_db.fetch_role"](name, static=False, mount=mount)

        if new is None:
            raise CommandExecutionError(
                "There were no errors during role management, but it is still reported as absent."
            )

        if not current:
            ret["changes"]["created"] = name

        new_diff = _diff_params(new)
        if new_diff:
            ret["result"] = False
            ret["comment"] = (
                "There were no errors during role management, but "
                f"the reported parameters do not match: {new_diff}"
            )
            return ret

        ret["comment"] = f"Role `{name}` has been {'updated' if current else 'created'}"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_absent(name, static=False, mount="database"):
    """
    Ensure a database role is absent.

    name
        The name of the role.

    static
        Whether this role is static. Defaults to False.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        current = __salt__["vault_db.fetch_role"](name, static=static, mount=mount)

        if current is None:
            ret["comment"] = f"Role `{name}` is already absent."
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Role `{name}` would have been deleted."
            return ret

        __salt__["vault_db.delete_role"](name, static=static, mount=mount)

        if __salt__["vault_db.fetch_role"](name, static=static, mount=mount) is not None:
            raise CommandExecutionError(
                "There were no errors during role deletion, but it is still reported as present."
            )
        ret["comment"] = f"Role `{name}` has been deleted."

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def static_role_present(
    name,
    connection,
    username,
    rotation_period,
    rotation_statements=None,
    credential_type=None,
    credential_config=None,
    mount="database",
):
    """
    Ensure a database Static Role is present as specified.

    name
        The name of the database role.

    connection
        The name of the database connection this role applies to.

    username
        The username to manage.

    rotation_period
        Specifies the amount of time Vault should wait before rotating the password.
        The minimum is ``5s``.

    rotation_statements
        Specifies the database statements to be executed to rotate the password for the
        configured database user. Not every plugin type will support this functionality.

    credential_type
        Specifies the type of credential that will be generated for the role.
        Options include: ``password``, ``rsa_private_key``. Defaults to ``password``.
        See the plugin's API page for credential types supported by individual databases.

    credential_config
        Specifies the configuration for the given ``credential_type`` as a mapping.
        For ``password``, only ``password_policy`` can be passed.
        For ``rsa_private_key``, ``key_bits`` (defaults to 2048) and ``format``
        (defaults to ``pkcs8``) are available.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    if rotation_statements and not isinstance(rotation_statements, list):
        rotation_statements = [rotation_statements]

    def _diff_params(current):
        nonlocal connection, username, rotation_period, rotation_statements, credential_type, credential_config
        diff_params = (
            ("db_name", connection),
            ("username", username),
            ("rotation_period", timestring_map(rotation_period)),
            ("rotation_statements", rotation_statements),
            ("credential_type", credential_type),
            ("credential_config", credential_config),
        )
        changed = {}
        for param, arg in diff_params:
            if arg is None:
                continue
            # Strip statements to avoid tripping over final newlines
            if param.endswith("statements"):
                arg = [x.rstrip() for x in arg]
                if param in current:
                    current[param] = [x.rstrip() for x in current[param]]
            if param not in current or current[param] != arg:
                changed.update({param: {"old": current.get(param), "new": arg}})
        return changed

    try:
        current = __salt__["vault_db.fetch_role"](name, static=True, mount=mount)

        if current:
            changed = _diff_params(current)
            if not changed:
                ret["comment"] = "Role is present as specified"
                return ret
            ret["changes"].update(changed)

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Role `{name}` would have been {'updated' if current else 'created'}"
            if not current:
                ret["changes"]["created"] = name
            return ret

        __salt__["vault_db.write_static_role"](
            name,
            connection,
            username,
            rotation_period,
            rotation_statements=None,
            credential_type=credential_type,
            credential_config=credential_config,
            mount=mount,
        )
        new = __salt__["vault_db.fetch_role"](name, static=True, mount=mount)

        if new is None:
            raise CommandExecutionError(
                "There were no errors during role management, but it is still reported as absent."
            )

        if not current:
            ret["changes"]["created"] = name

        new_diff = _diff_params(new)
        if new_diff:
            ret["result"] = False
            ret["comment"] = (
                "There were no errors during role management, but "
                f"the reported parameters do not match: {new_diff}"
            )
            return ret

        ret["comment"] = f"Role `{name}` has been {'updated' if current else 'created'}"

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def creds_cached(
    name,
    static=False,
    cache=None,
    valid_for=NOT_SET,
    renew_increment=None,
    revoke_delay=None,
    meta=None,
    mount="database",
    **kwargs,  # pylint: disable=unused-argument
):
    """
    Ensure valid credentials are present in the minion's cache based on the named role.
    Supports ``mod_beacon``.

    .. note::

        This function is mosly intended to associate a specific credential with
        a beacon that warns about expiry and allows to run an associated state to
        reconfigure an application with new credentials.
        See the :py:mod:`vault_lease beacon module <saltext.vault.beacons.vault_lease>`
        for an :ref:`example state to configure a lease together with a beacon <beacon-state-example>`.

    name
        The name of the database role.

    static
        Whether this role is static. Defaults to False.

    cache
        A variable cache suffix to be able to use multiple distinct credentials
        using the same role on the same minion.
        Ignored when ``static`` is true.

        .. note::

            This uses the same cache backend as the Vault integration, so make
            sure you configure a persistent backend like ``disk`` if you expect
            the credentials to survive a single run.

    valid_for
        Ensure the credentials are valid for at least this amount of time,
        otherwise request new ones.
        This can be an integer, which will be interpreted as seconds, or a time string
        using the same format as Vault does:
        Suffix ``s`` for seconds, ``m`` for minuts, ``h`` for hours, ``d`` for days.
        Defaults to ``0``.

    renew_increment
        When using cache and ``valid_for`` results in a renewal attempt, request this
        amount of time extension on the lease. This will be cached together with the
        lease and might be used by other modules later.

    revoke_delay
        When using cache and ``valid_for`` results in a revocation, set the lease
        validity to this value to allow a short amount of delay between the issuance
        of the new lease and the revocation of the old one. Defaults to ``60``.
        This will be cached together with the lease and might be used by other
        modules later.

    meta
        When using cache, this value will be cached together with the lease. It will
        be emitted by the ``vault_lease`` beacon module whenever a lease is
        running out (usually because it cannot be extended further). It is intended
        to support the reactor in deciding what needs to be done in order
        to to reconfigure dependent, Vault-unaware software with newly issued
        credentials. Entirely optional.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The credentials are already cached and valid",
        "changes": {},
    }

    cached = __salt__["vault_db.list_cached"](
        name, static=static, cache=cache or True if not static else True, mount=mount
    )
    pp = "issued"
    if cached:
        info = cached[next(iter(cached))]
        if valid_for is NOT_SET:
            if info["min_ttl"] is not None:
                valid_for = info["min_ttl"]
            else:
                valid_for = None
        for attr, val in (
            ("min_ttl", valid_for),
            ("renew_increment", renew_increment),
            ("revoke_delay", revoke_delay),
            ("meta", meta),
        ):
            if val is not None and info.get(attr) != val:
                # Meta-only changes should be reported as well because the
                # execution module needs to be called later to update them.
                # This is especially valid for a lowering of min_ttl, which
                # might result in a reissuance if the current lease has already
                # reached its min_ttl (the current logic would not recognize that
                # situation otherwise).
                ret["changes"][attr] = {"old": info.get(attr), "new": val}
                pp = "edited"

        current_effective_valid_for = valid_for or 0
        if info["min_ttl"] is not None:
            current_effective_valid_for = max(info["min_ttl"], valid_for or 0)
        if info["expires_in"] <= timestring_map(current_effective_valid_for):
            ret["changes"]["expiry"] = True
            pp = "renewed"
        if not ret["changes"]:
            return ret
    else:
        ret["changes"]["new"] = True
    if __opts__["test"]:
        ret["result"] = None
        if pp == "renewed":
            pp = "renewed/reissued"
        ret["comment"] = f"The credentials would have been {pp}"
        return ret
    __salt__["vault_db.get_creds"](
        name,
        static=static,
        cache=cache or True,
        valid_for=valid_for,
        renew_increment=renew_increment,
        revoke_delay=revoke_delay,
        meta=meta,
        mount=mount,
        _warn_about_attr_change=False,
    )
    new_cached = __salt__["vault_db.list_cached"](name, static=static, cache=cache, mount=mount)
    if not new_cached:
        raise CommandExecutionError(
            "Could not find cached credentials after issuing, this is likely a bug"
        )
    # Ensure the reporting is correct.
    if cached and new_cached[next(iter(cached))]["lease_id"] != info["lease_id"]:
        pp = "reissued"
        ret["changes"][pp] = True

    ret["comment"] = f"The credentials have been {pp}"
    return ret


def creds_uncached(
    name, static=False, cache=None, mount="database", **kwargs
):  # pylint: disable=unused-argument
    """
    Ensure credentials are absent in the minion's cache based on the named role.
    Supports ``mod_beacon``.

    .. note::

        This function is mosly intended to remove a cached lease and its
        beacon. See :py:func:`creds_cached` for a more detailed description.
        To remove the associated beacon together with the lease, just pass
        ``beacon: true`` as a parameter to this state.

    name
        The name of the database role.

    static
        Whether this role is static. Defaults to False.

    cache
        A variable cache suffix to be able to use multiple distinct credentials
        using the same role on the same minion.
        Ignored when ``static`` is true.

    mount
        The mount path the database backend is mounted to. Defaults to ``database``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "No matching credentials present",
        "changes": {},
    }

    cached = __salt__["vault_db.list_cached"](name, static=static, cache=cache, mount=mount)
    if not cached:
        return ret
    ret["changes"]["revoked"] = True
    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The credentials would have been revoked"
        return ret
    __salt__["vault_db.clear_cached"](name, static=static, cache=cache or True, mount=mount)
    ret["comment"] = "The credentials have been revoked"
    return ret


def mod_beacon(name, sfun=None, static=False, cache=None, mount="database", **kwargs):
    """
    Associates a Vault lease with a ``vault_lease`` beacon and
    possibly a state.

    beacon_interval
        The interval to run the beacon in. Defaults to 60.

    min_ttl
        If this minimum TTL on the lease is undercut, the beacon will
        fire an event. Defaults to 0.
    """
    ret = {"name": name, "changes": {}, "result": True, "comment": ""}
    supported_funcs = ("creds_cached", "creds_uncached")

    if sfun not in supported_funcs:
        ret["result"] = False
        ret["comment"] = f"'vault_db.{sfun}' does not work with mod_beacon"
        return ret
    if not kwargs.get("beacon"):
        ret["comment"] = "Not managing beacon"
        return ret
    lease = vaultdb.create_cache_pattern(name, mount=mount, static=static, cache=cache or True)
    beacon_module = "vault_lease"
    beacon_name = f"{beacon_module}_{lease}"
    if sfun == "creds_uncached":
        beacon_kwargs = {
            "name": beacon_name,
            "beacon_module": beacon_module,
        }
        bfun = "absent"
    else:
        # sfun == "creds_cached" evidently
        beacon_kwargs = {
            "name": beacon_name,
            "beacon_module": beacon_module,
            "interval": kwargs.get("beacon_interval", 60),
            "leases": lease,
            "min_ttl": kwargs.get("min_ttl", 0),
            "meta": kwargs.get("meta"),
            "check_server": kwargs.get("check_server", False),
        }
        bfun = "present"
    return __states__[f"beacon.{bfun}"](**beacon_kwargs)
