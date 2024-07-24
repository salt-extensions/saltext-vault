"""
Interface with a Vault server.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging

from salt.defaults import NOT_SET
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltException
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault
from saltext.vault.utils.versions import warn_until

log = logging.getLogger(__name__)


def read_secret(path, key=None, metadata=False, default=NOT_SET):
    """
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
        The path to the secret, including mount.

    key
        The data field at <path> to read. If unspecified, returns the
        whole dataset.

    metadata
        If using KV v2 backend, display full results, including metadata.
        Defaults to False.

    default
        When the path or path/key combination is not found, an exception will
        be raised, unless a default is provided here.
    """
    if default == NOT_SET:
        default = CommandExecutionError
    if key is not None:
        metadata = False
    log.debug("Reading Vault secret for %s at %s", __grains__.get("id"), path)
    try:
        data = vault.read_kv(path, __opts__, __context__, include_metadata=metadata)
        if key is not None:
            return data[key]
        return data
    except Exception as err:  # pylint: disable=broad-except
        if default is CommandExecutionError:
            raise CommandExecutionError(
                f"Failed to read secret! {type(err).__name__}: {err}"
            ) from err
        return default


def write_secret(path, **kwargs):
    """
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
        The path to the secret, including mount.
    """
    log.debug("Writing vault secrets for %s at %s", __grains__.get("id"), path)
    data = {x: y for x, y in kwargs.items() if not x.startswith("__")}
    try:
        res = vault.write_kv(path, data, __opts__, __context__)
        if isinstance(res, dict):
            return res["data"]
        return res
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to write secret! %s: %s", type(err).__name__, err)
        return False


def write_raw(path, raw):
    """
    Set raw data at <path>.

    CLI Example:

    .. code-block:: bash

            salt '*' vault.write_raw "secret/my/secret" '{"user":"foo","password": "bar"}'

    Required policy: see :func:`write_secret`

    path
        The path to the secret, including mount.

    raw
        Secret data to write to <path>. Has to be a mapping.
    """
    log.debug("Writing vault secrets for %s at %s", __grains__.get("id"), path)
    try:
        res = vault.write_kv(path, raw, __opts__, __context__)
        if isinstance(res, dict):
            return res["data"]
        return res
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to write secret! %s: %s", type(err).__name__, err)
        return False


def patch_secret(path, **kwargs):
    """
    Patch secret dataset at <path>. Fields are specified as arbitrary keyword arguments.

    .. note::

        This works even for older Vault versions, KV v1 and with missing
        ``patch`` capability, but will use more than one request to simulate
        the functionality by issuing a read and update request.

        For proper, single-request patching, requires versions of KV v2 that
        support the ``patch`` capability and the ``patch`` capability to be available
        for the path.

    .. note::

        This uses JSON Merge Patch format internally.
        Keys set to ``null`` (JSON/YAML)/``None`` (Python) will be deleted.

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
        The path to the secret, including mount.
    """
    log.debug("Patching vault secrets for %s at %s", __grains__.get("id"), path)
    data = {x: y for x, y in kwargs.items() if not x.startswith("__")}
    try:
        res = vault.patch_kv(path, data, __opts__, __context__)
        if isinstance(res, dict):
            return res["data"]
        return res
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to patch secret! %s: %s", type(err).__name__, err)
        return False


def delete_secret(path, *args):
    """
    Delete secret at <path>. If <path> is on KV v2, the secret will be soft-deleted.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.delete_secret "secret/my/secret"
        salt '*' vault.delete_secret "secret/my/secret" 1 2 3

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
        path "<mount>/delete/<secret>" {
            capabilities = ["update"]
        }

    path
        The path to the secret, including mount.

    .. versionadded:: 1.0.0

        For KV v2, you can specify versions to soft-delete as supplemental
        positional arguments.
    """
    log.debug("Deleting vault secrets for %s in %s", __grains__.get("id"), path)
    if args:
        log.debug(f"Affected versions: {' '.join(str(x) for x in args)}")
    try:
        return vault.delete_kv(path, __opts__, __context__, versions=list(args) or None)
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to delete secret! %s: %s", type(err).__name__, err)
        return False


def destroy_secret(path, *args):
    """
    Destroy specified secret versions at <path>. Only supported on Vault KV v2.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.destroy_secret "secret/my/secret" 1 2

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/destroy/<secret>" {
            capabilities = ["update"]
        }

    path
        The path to the secret, including mount.

    You can specify versions to destroy as supplemental positional arguments.
    At least one is required.
    """
    if not args:
        raise SaltInvocationError("Need at least one version to destroy.")
    log.debug("Destroying vault secrets for %s in %s", __grains__.get("id"), path)
    if args:
        log.debug(f"Affected versions: {' '.join(str(x) for x in args)}")
    try:
        return vault.destroy_kv(path, list(args), __opts__, __context__)
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to destroy secret! %s: %s", type(err).__name__, err)
        return False


def list_secrets(path, default=NOT_SET, keys_only=None):
    """
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
        The path to the secret, including mount.

    default
        When the path is not found, an exception will be raised, unless a default
        is provided here.

    keys_only
        .. versionadded:: 1.0.0

        This function used to return a dictionary like ``{"keys": ["some/", "some/key"]}``.
        Setting this to True will only return the list of keys.
        For backwards-compatibility reasons, this currently defaults to False.
        Beginning with version 2 of this extension, the default will change to True.
    """
    if default == NOT_SET:
        default = CommandExecutionError
    if keys_only is None:
        try:
            warn_until(
                2,
                (
                    "In version {version}, this function will return the list of "
                    "secret keys only. You can switch to the new behavior explicitly "
                    "by specifying keys_only=True."
                ),
            )
            keys_only = False
        except RuntimeError:
            keys_only = True

    log.debug("Listing vault secret keys for %s in %s", __grains__.get("id"), path)
    try:
        keys = vault.list_kv(path, __opts__, __context__)
        if keys_only:
            return keys
        # this is the way Salt behaved previously
        return {"keys": keys}
    except Exception as err:  # pylint: disable=broad-except
        if default is CommandExecutionError:
            raise CommandExecutionError(
                f"Failed to list secrets! {type(err).__name__}: {err}"
            ) from err
        return default


def clear_cache(connection=True, session=False):
    """
    .. versionadded:: 1.0.0

    Delete Vault caches. Will ensure the current token and associated leases
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
        Setting this to true will keep the connection cache, regardless
        of ``connection``.
    """
    return vault.clear_cache(__opts__, __context__, connection=connection, session=session)


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
    return clear_cache(connection=True, session=False)


def policy_fetch(policy):
    """
    .. versionadded:: 1.0.0

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
        The name of the policy to fetch.
    """
    # there is also "sys/policies/acl/{policy}"
    endpoint = f"sys/policy/{policy}"

    try:
        data = vault.query("GET", endpoint, __opts__, __context__)
        return data["rules"]

    except vault.VaultNotFoundError:
        return None
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def policy_write(policy, rules):
    r"""
    .. versionadded:: 1.0.0

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
        The name of the policy to create/update.

    rules
        Rules to write, formatted as in-line HCL.
    """
    endpoint = f"sys/policy/{policy}"
    payload = {"policy": rules}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def policy_delete(policy):
    """
    .. versionadded:: 1.0.0

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
        The name of the policy to delete.
    """
    endpoint = f"sys/policy/{policy}"

    try:
        return vault.query("DELETE", endpoint, __opts__, __context__)
    except vault.VaultNotFoundError:
        return False
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def policies_list():
    """
    .. versionadded:: 1.0.0

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
    try:
        return vault.query("GET", "sys/policy", __opts__, __context__)["policies"]
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


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

    endpoint
        Vault API endpoint to issue the request against. Do not include ``/v1/``.

    payload
        Optional dictionary to use as JSON payload.
    """
    try:
        return vault.query(method, endpoint, __opts__, __context__, payload=payload)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def update_config(keep_session=False):
    """
    .. versionadded:: 1.0.0

    Attempt to update the cached configuration without clearing the
    currently active Vault session.

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
    return vault.update_config(__opts__, __context__, keep_session=keep_session)


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
