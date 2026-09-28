"""
Interface with a Vault (or OpenBao) server and the KV secret backend.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from typing import TYPE_CHECKING

from salt.defaults import NOT_SET
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltException

from saltext.vault.utils import vault
from saltext.vault.utils.versions import warn_until

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


ALIAS_WARNING = (
    "The `vault.{old_name}` function was renamed to `{new_name}`. "
    "Please adjust your calls accordingly. "
    "This compatibility alias will be dropped in version {{version}}."
)


def query(method, endpoint, payload=None):
    """
    .. versionadded:: 1.0.0

    Issue arbitrary queries against the Vault API.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.query GET auth/token/lookup-self

    Required policy: Depends on the query.

    You can ask the Vault CLI to output the necessary policy:

    .. code-block:: bash

        vault read -output-policy auth/token/lookup-self

    method
        HTTP method to use.

        .. note::
            A literal ``LIST`` is passed through as-is and does not
            follow the :vconf:`client:list_as_get` option.

    endpoint
        Vault API endpoint to issue the request against. Do not include ``/v1/``.

    payload
        Optional dictionary to use as JSON payload.
    """
    try:
        return vault.query(method, endpoint, __opts__, __context__, payload=payload)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def clear_cache(connection=True, session=False):
    """
    .. versionadded:: 1.0.0

    Delete Vault caches. Ensures the current token and associated leases
    are revoked by default.

    The cache is organized in a hierarchy: ``/vault/connection/session/leases``.
    (*italics* mark data that is only cached when receiving configuration from a master)

    ``connection`` contains KV metadata (by default), *configuration* and *(AppRole) auth credentials*.
    ``session`` contains the currently active token.
    ``leases`` contains leases issued to the currently active token like database credentials.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.clear_cache
        salt '*' vault.clear_cache session=True

    connection
        Only clear the cached data scoped to a connection. This includes
        configuration, auth credentials, the currently active auth token
        as well as leases and KV metadata (by default). Defaults to true.
        Set this to false to clear all Vault caches.

    session
        Only clear the cached data scoped to a session. This only includes
        leases and the currently active auth token, but not configuration
        or (AppRole) auth credentials. Defaults to false.
        Setting this to true keeps the connection cache, regardless
        of ``connection``.
    """
    try:
        return vault.clear_cache(__opts__, __context__, connection=connection, session=session)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def update_config(keep_session=False):
    """
    .. versionadded:: 1.0.0

    Attempt to update the cached configuration without clearing the
    currently active Vault session.

    .. note::
        This is only relevant on minions that receive issued credentials
        from the master. On locally configured minions, this does nothing.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.update_config

    keep_session
        Only update configuration that can be updated without
        creating a new login session.
        If this is false, still tries to keep the active session,
        but might clear it if the server configuration has changed
        significantly.
        Defaults to False.
    """
    try:
        return vault.update_config(__opts__, __context__, keep_session=keep_session)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def get_server_config():
    """
    .. versionadded:: 1.0.0

    Return the server connection configuration that's currently in use by Salt.
    Contains :vconf:`url <server:url>`, :vconf:`verify <server:verify>`
    and :vconf:`namespace <server:namespace>`.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.get_server_config
    """
    try:
        client = vault.get_authd_client(__opts__, __context__)
        return client.get_config()
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def clear_token_cache():
    """
    .. deprecated:: 1.0.0
    .. versionchanged:: 1.0.0

        This is now an alias for :func:`vault.clear_cache<clear_cache>` with ``connection=True``
        and ``session=False`` (the defaults).

    Delete minion Vault token cache.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.clear_token_cache
    """
    log.debug("Deleting vault connection cache.")
    warn_until(
        2,
        "The `vault.clear_token_cache` function is just an alias for `vault.clear_cache()`. "
        "Please migrate. This alias will be dropped in version {version}",
    )
    return clear_cache(connection=True, session=False)


#############################################################################
# Deprecated aliases. They were refactored into separate execution modules: #
#############################################################################


def _log_kv_error(err, prefix):
    # The new vault_secret functions raise errors prefixed like this,
    # these aliases used to log them and return False instead.
    err_msg = str(err)
    if err_msg.startswith(prefix):
        log.error(err_msg)
    else:
        log.error("%s %s: %s", prefix, type(err).__name__, err)
    return False


def read_secret(path, key=None, metadata=False, default=NOT_SET, version=None):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.read <saltext.vault.modules.vault_secret.read>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Return the value of <key> at <path> in vault, or entire secret.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.read_secret salt/kv/secret

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/<secret>" {
            capabilities = ["read"]
        }

        # or KV v2
        path "<mount>/data/<secret>" {
            capabilities = ["read"]
        }

    path
        Path to the secret, including mount.

    key
        Field of secret at ``path`` to read.
        If unspecified, returns the whole dataset.

    metadata
        If ``path`` is on a KV v2 backend, display full results, including metadata.
        Only respected if ``key`` is not set. Defaults to False.

    default
        Instead of raising an exception, return this value when ``path``
        is not found or the secret at ``path`` does not contain ``key``.

    version
        Version to read. If unset, reads the latest one.

        .. versionadded:: 1.2.0
    """
    warn_until(2, ALIAS_WARNING.format(old_name="read_secret", new_name="vault_secret.read"))
    try:
        return __salt__["vault_secret.read"](path, key=key, metadata=metadata, version=version)
    except Exception as err:  # pylint: disable=broad-except
        # This used to swallow all exceptions
        if default == NOT_SET or default is CommandExecutionError:
            if not isinstance(err, CommandExecutionError) or not str(err).startswith(
                "Failed to read secret!"
            ):
                raise CommandExecutionError(
                    f"Failed to read secret! {type(err).__name__}: {err}"
                ) from err
            raise
        return default


def read_secret_meta(path):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.read_meta <saltext.vault.modules.vault_secret.read_meta>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    .. versionadded:: 1.2.0

    Return secret metadata and versions for <path>.
    Requires KV v2.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.read_secret_meta salt/kv/secret

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/metadata/<secret>" {
            capabilities = ["read"]
        }

    path
        Path to the secret, including mount.
    """
    warn_until(
        2, ALIAS_WARNING.format(old_name="read_secret_meta", new_name="vault_secret.read_meta")
    )
    try:
        return __salt__["vault_secret.read_meta"](path)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to read secret metadata!")


def write_secret(path, **kwargs):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.write <saltext.vault.modules.vault_secret.write>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Set secret dataset at <path>.
    Fields are specified as arbitrary keyword arguments.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.write_secret "secret/my/secret" user="foo" password="bar"

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/<secret>" {
            capabilities = ["create", "update"]
        }

        # or KV v2
        path "<mount>/data/<secret>" {
            capabilities = ["create", "update"]
        }

    path
        Path to the secret, including mount.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="write_secret", new_name="vault_secret.write"))
    try:
        return __salt__["vault_secret.write"](path, **kwargs)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to write secret!")


def write_raw(path, raw):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.write_raw <saltext.vault.modules.vault_secret.write_raw>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Set raw data at <path>.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.write_raw "secret/my/secret" '{user: foo, password: bar}'

    Required policy: see :func:`write_secret`

    path
        Path to the secret, including mount.

    raw
        Secret data to write to <path>. Has to be a mapping.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="write_raw", new_name="vault_secret.write_raw"))
    try:
        return __salt__["vault_secret.write_raw"](path, raw)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to write secret!")


def patch_secret(path, **kwargs):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.patch <saltext.vault.modules.vault_secret.patch>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Patch secret dataset at <path>. Fields are specified as arbitrary keyword arguments.

    .. note::

        This works even for older Vault versions, KV v1 and with missing
        ``patch`` capability, but uses more than one request to simulate
        the functionality by issuing a read and update request.

        For proper, single-request patching, requires versions of KV v2 that
        support the ``patch`` capability and the ``patch`` capability to be available
        for the path.

    .. note::

        This uses JSON Merge Patch format internally.
        Keys set to ``null`` (JSON/YAML)/``None`` (Python) are deleted.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.patch_secret "secret/my/secret" password="baz"

    Required policy:

    .. code-block:: vaultpolicy

        # Proper patching
        path "<mount>/data/<secret>" {
            capabilities = ["patch"]
        }

        # OR (!), for older KV v2 setups:

        path "<mount>/data/<secret>" {
            capabilities = ["read", "update"]
        }

        # OR (!), for KV v1 setups:

        path "<mount>/<secret>" {
            capabilities = ["read", "update"]
        }

    path
        Path to the secret, including mount.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="patch_secret", new_name="vault_secret.patch"))
    try:
        return __salt__["vault_secret.patch"](path, **kwargs)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to patch secret!")


def patch_raw(path, raw):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.patch_raw <saltext.vault.modules.vault_secret.patch_raw>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    .. versionadded:: 1.8.0

    Patch raw data at <path>.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.patch_raw "secret/my/secret" '{user: foo, password: bar}'

    Required policy: see :func:`patch_secret`

    path
        Path to the secret, including mount.

    raw
        Secret data to patch into <path>. Has to be a mapping.
        Keys set to ``null`` (JSON/YAML)/``None`` (Python) are deleted.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="patch_raw", new_name="vault_secret.patch_raw"))
    try:
        return __salt__["vault_secret.patch_raw"](path, raw)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to patch secret!")


def delete_secret(path, *args, all_versions=False, **_):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.delete <saltext.vault.modules.vault_secret.delete>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Delete secret at <path>. If <path> is on KV v2, the secret is soft-deleted.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.delete_secret "secret/my/secret"
        salt '*' vault.delete_secret "secret/my/secret" 1 2 3
        salt '*' vault.delete_secret "secret/my/secret" all_versions=true

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/<secret>" {
            capabilities = ["delete"]
        }

        # or KV v2
        path "<mount>/data/<secret>" {
            capabilities = ["delete"]
        }

        # KV v2 versions
        # all_versions=True additionally requires the policy for vault.read_secret_meta
        path "<mount>/delete/<secret>" {
            capabilities = ["update"]
        }

    path
        Path to the secret, including mount.

    all_versions
        .. versionadded:: 1.2.0

        Delete all versions of the secret for KV v2.
        Can only be passed as a keyword argument.
        Defaults to false.

    .. versionadded:: 1.0.0

        For KV v2, you can specify versions to soft-delete as supplemental
        positional arguments.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="delete_secret", new_name="vault_secret.delete"))
    try:
        return __salt__["vault_secret.delete"](path, *args, all_versions=all_versions)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to delete secret!")


def restore_secret(path, *versions, all_versions=False, **_):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.restore <saltext.vault.modules.vault_secret.restore>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    .. versionadded:: 1.2.0

    Restore specific versions of a secret path. Only supported on Vault KV v2.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.restore_secret secret/my/secret 1 2

    Required policy:

    .. code-block:: vaultpolicy

        # all_versions=True or defaulting to the most recent version additionally
        # requires the policy for vault.read_secret_meta
        path "<mount>/undelete/<secret>" {
            capabilities = ["update"]
        }

    path
        Path to the secret, including mount.

    all_versions
        Restore all versions of the secret for KV v2.
        Can only be passed as a keyword argument.
        Defaults to false.

    You can specify versions to restore as supplemental positional arguments.
    If no version is specified, tries to restore the latest version, and if
    the latest version has not been deleted, fails.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="restore_secret", new_name="vault_secret.restore"))
    # This one always raised errors
    return __salt__["vault_secret.restore"](path, *versions, all_versions=all_versions)


def destroy_secret(path, *args, all_versions=False, **_):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.destroy <saltext.vault.modules.vault_secret.destroy>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Destroy specified secret versions at <path>.
    This makes a secret version unrecoverable.
    On KV v1, there is no functional difference to ``delete``
    because the backend does not support versioning.
    Specifying versions fails there.

    .. versionchanged:: 1.8.0
        KV v1 secrets are now deleted instead of failing.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.destroy_secret "secret/my/secret"
        salt '*' vault.destroy_secret "secret/my/secret" 1 2
        salt '*' vault.destroy_secret "secret/my/secret" all_versions=true

    Required policy:

    .. code-block:: vaultpolicy

        # all_versions=True or defaulting to the most recent version additionally
        # requires the policy for vault.read_secret_meta
        path "<mount>/destroy/<secret>" {
            capabilities = ["update"]
        }

    path
        Path to the secret, including mount.

    all_versions
        .. versionadded:: 1.2.0

        Destroy all versions of the secret for KV v2.
        Can only be passed as a keyword argument.
        Defaults to false.

    You can specify versions to destroy as supplemental positional arguments.

    .. versionchanged:: 1.2.0

        If no version was specified, defaults to the most recent one.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="destroy_secret", new_name="vault_secret.destroy"))
    try:
        return __salt__["vault_secret.destroy"](path, *args, all_versions=all_versions)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to destroy secret!")


def wipe_secret(path):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.wipe <saltext.vault.modules.vault_secret.wipe>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    .. versionadded:: 1.2.0

    Remove all version history and data for the secret at <path>.
    On KV v1, there is no functional difference to ``delete``
    because the backend does not support versioning.

    .. versionchanged:: 1.8.0
        KV v1 secrets are now deleted instead of failing.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.wipe_secret "secret/my/secret"

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/metadata/<secret>" {
            capabilities = ["delete"]
        }
    """
    warn_until(2, ALIAS_WARNING.format(old_name="wipe_secret", new_name="vault_secret.wipe"))
    try:
        return __salt__["vault_secret.wipe"](path)
    except Exception as err:  # pylint: disable=broad-except
        return _log_kv_error(err, "Failed to wipe secret!")


def list_secrets(path, default=NOT_SET, keys_only=None):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_secret.list <saltext.vault.modules.vault_secret.list_>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    List secret keys at <path>. The path should end with a trailing slash.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.list_secrets "secret/my/"

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/<path>" {
            capabilities = ["list"]
        }

        # or KV v2
        path "<mount>/metadata/<path>" {
            capabilities = ["list"]
        }

    path
        Path to the secret, including mount.

    default
        When the path is not found, an exception is raised, unless a default
        is provided here.

    keys_only
        .. versionadded:: 1.0.0

        This function used to return a dictionary like ``{"keys": ["some/", "some/key"]}``.
        Setting this to True only returns the list of keys.
        For backwards-compatibility reasons, this defaults to False.
        The :py:func:`migrated function <saltext.vault.modules.vault_secret.list_>` always
        returns a list of keys and does not have this parameter.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="list_secrets", new_name="vault_secret.list"))
    try:
        res = __salt__["vault_secret.list"](path)
    except Exception as err:  # pylint: disable=broad-except
        # This used to swallow all exceptions
        if default == NOT_SET or default is CommandExecutionError:
            if not isinstance(err, CommandExecutionError) or not str(err).startswith(
                "Failed to list secrets!"
            ):
                raise CommandExecutionError(
                    f"Failed to list secrets! {type(err).__name__}: {err}"
                ) from err
            raise
        return default
    if keys_only:
        return res
    # this is the way Salt behaved previously
    return {"keys": res}


def policy_fetch(policy):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_policy.fetch <saltext.vault.modules.vault_policy.fetch>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Fetch the rules associated with an ACL policy. Returns ``None`` if the policy
    does not exist.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.policy_fetch salt_minion

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy/<policy>" {
            capabilities = ["read"]
        }

    policy
        Name of the policy to fetch.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="policy_fetch", new_name="vault_policy.fetch"))
    return __salt__["vault_policy.fetch"](policy)


def policy_write(policy, rules):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_policy.write <saltext.vault.modules.vault_policy.write>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Create or update an ACL policy.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.policy_write salt_minion 'path "secret/foo" {...}'

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy/<policy>" {
            capabilities = ["create", "update"]
        }

    policy
        Name of the policy to create/update.

    rules
        Rules to write, formatted as in-line HCL.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="policy_write", new_name="vault_policy.write"))
    return __salt__["vault_policy.write"](policy, rules=rules)


def policy_delete(policy):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_policy.delete <saltext.vault.modules.vault_policy.delete>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    Delete an ACL policy. Returns False if the policy does not exist.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.policy_delete salt_minion

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy/<policy>" {
            capabilities = ["delete"]
        }

    policy
        Name of the policy to delete.
    """
    warn_until(2, ALIAS_WARNING.format(old_name="policy_delete", new_name="vault_policy.delete"))
    return __salt__["vault_policy.delete"](policy)


def policies_list():
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_policy.list <saltext.vault.modules.vault_policy.list_>`.
        Please adjust your calls accordingly.
        This compatibility alias will be dropped in the next major release.

    List all ACL policies.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.policies_list

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy" {
            capabilities = ["read"]
        }
    """
    warn_until(2, ALIAS_WARNING.format(old_name="policies_list", new_name="vault_policy.list"))
    return __salt__["vault_policy.list"]()
