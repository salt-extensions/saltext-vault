"""
Interface with the Vault (or OpenBao) KV secret backend.

.. versionadded:: 1.9.0
    Functions in this module were extracted from the :py:mod:`vault execution module <saltext.vault.modules.vault>`.

.. versionchanged:: 1.9.0
    The previous implementation swallowed any kind of error and
    returned False (or the ``default`` argument, if available).

    Calls to this module only catch select Vault API errors and raise ``CommandExecutionError``
    (or return the ``default`` argument, if available) instead of failing silently.

    Also, :func:`read` made ``default`` the third positional parameter, replacing ``metadata``,
    and made ``metadata`` and ``version`` keyword-only arguments.

    :func:`list <list_>` lost its ``keys_only`` parameter, which only served for backwards-compatibility.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from typing import TYPE_CHECKING

from salt.defaults import NOT_SET
from salt.exceptions import CommandExecutionError

from saltext.vault.utils import vault

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
__virtualname__ = "vault_secret"


def read(path, key=None, default=NOT_SET, *, metadata=False, version=None, **_):
    """
    Return the value of <key> at <path> in vault, or entire secret.

    .. versionchanged:: 1.9.0

        Changed parameter order versus :py:func:`vault.read_secret <saltext.vault.modules.vault.read_secret>`:

        * ``default`` became the third positional argument, replacing ``metadata``.
        * ``metadata`` and ``version`` became keyword-only arguments

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.read salt/kv/secret

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2
        path "<mount>/data/<secret>" {
            capabilities = ["read"]
        }

        # OR (!) for KV v1
        path "<mount>/<secret>" {
            capabilities = ["read"]
        }

    path
        Path to the secret, including mount.

    key
        Field of secret at ``path`` to read.
        If unspecified, returns the whole dataset.

    default
        Instead of raising an exception, return this value when ``path``
        is not found or the secret at ``path`` does not contain ``key``.

    metadata
        If ``path`` is on a KV v2 backend, display full results, including metadata.
        Only respected if ``key`` is not set. Defaults to False.

    version
        Version to read. If unset, reads the latest one.
    """
    if default == NOT_SET:
        default = CommandExecutionError
    if metadata and key is not None:
        log.warning("Cannot read metadata when `key` param is specified. Disabled `metadata`.")
        metadata = False

    def _default_or_err(err):
        if default is CommandExecutionError:
            raise CommandExecutionError(
                f"Failed to read secret! {type(err).__name__}: {err}"
            ) from err
        return default

    log.debug("Reading Vault secret for %s at %s", __grains__.get("id"), path)
    try:
        data = vault.read_kv(
            path, __opts__, __context__, include_metadata=metadata, version=version
        )
    except vault.VaultException as err:
        return _default_or_err(err)

    if key is None:
        return data

    try:
        return data[key]
    except KeyError as err:
        return _default_or_err(err)


def read_meta(path):
    """
    Return secret metadata and versions for <path>.
    Requires KV v2.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.read_meta salt/kv/secret

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/metadata/<secret>" {
            capabilities = ["read"]
        }

    path
        Path to the secret, including mount.
    """
    log.debug("Reading Vault secret metadata for %s at %s", __grains__.get("id"), path)
    try:
        return vault.read_kv_meta(path, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(
            f"Failed to read secret metadata! {type(err).__name__}: {err}"
        ) from err


def write(path, **kwargs):
    """
    Set secret dataset at <path>.
    Fields are specified as arbitrary keyword arguments.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.write "secret/my/secret" user="foo" password="bar"

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2
        path "<mount>/data/<secret>" {
            capabilities = ["create", "update"]
        }

        # OR (!) for KV v1
        path "<mount>/<secret>" {
            capabilities = ["create", "update"]
        }

    path
        Path to the secret, including mount.
    """
    log.debug("Writing vault secrets for %s at %s", __grains__.get("id"), path)
    data = {x: y for x, y in kwargs.items() if not x.startswith("__")}

    try:
        res = vault.write_kv(path, data, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"Failed to write secret! {type(err).__name__}: {err}") from err
    if isinstance(res, dict):
        return res["data"]
    return res


def write_raw(path, raw):
    """
    Set raw data at <path>.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.write_raw "secret/my/secret" '{user: foo, password: bar}'

    Required policy: see :func:`write`

    path
        Path to the secret, including mount.

    raw
        Secret data to write to <path>. Has to be a mapping.
    """
    log.debug("Writing vault secrets for %s at %s", __grains__.get("id"), path)
    try:
        res = vault.write_kv(path, raw, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"Failed to write secret! {type(err).__name__}: {err}") from err
    if isinstance(res, dict):
        return res["data"]
    return res


def patch(path, **kwargs):
    """
    Patch secret dataset at <path>. Fields are specified as arbitrary keyword arguments.

    .. note::

        This works even for older Vault versions, KV v1 and with missing
        ``patch`` capability, but uses more than one request to simulate
        the functionality by issuing a read and update request.

        For proper, single-request patching, requires versions of KV v2 that
        support the ``patch`` capability and the ``patch`` capability to be
        available for the path.

    .. note::

        This uses JSON Merge Patch format internally.
        Keys set to ``null`` (JSON/YAML)/``None`` (Python) are deleted.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.patch "secret/my/secret" password="baz"

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2: Proper patching
        path "<mount>/data/<secret>" {
            capabilities = ["patch"]
        }

        # OR (!), for very old KV v2 releases:
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
    log.debug("Patching vault secrets for %s at %s", __grains__.get("id"), path)
    data = {x: y for x, y in kwargs.items() if not x.startswith("__")}

    try:
        res = vault.patch_kv(path, data, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"Failed to patch secret! {type(err).__name__}: {err}") from err
    if isinstance(res, dict):
        return res["data"]
    return res


def patch_raw(path, raw):
    """
    Patch raw data at <path>.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.patch_raw "secret/my/secret" '{user: foo, password: bar}'

    Required policy: see :func:`patch`

    path
        Path to the secret, including mount.

    raw
        Secret data to patch into <path>. Has to be a mapping.
        Keys set to ``null`` (JSON/YAML)/``None`` (Python) are deleted.
    """
    log.debug("Patching vault secrets for %s at %s", __grains__.get("id"), path)
    try:
        res = vault.patch_kv(path, raw, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"Failed to patch secret! {type(err).__name__}: {err}") from err
    if isinstance(res, dict):
        return res["data"]
    return res


def list_(path, default=NOT_SET):
    """
    List secret keys at <path>. The path should end with a trailing slash.

    .. versionchanged:: 1.9.0

        Dropped ``keys_only`` parameter versus :py:func:`vault.list_secrets <saltext.vault.modules.vault.list_secrets>`.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.list "secret/my/"

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2
        path "<mount>/metadata/<path>" {
            capabilities = ["list"]
        }

        # OR (!) for KV v1
        path "<mount>/<path>" {
            capabilities = ["list"]
        }

    path
        Path to the secret, including mount.

    default
        When the path is not found, an exception is raised, unless a default
        is provided here.
    """
    if default == NOT_SET:
        default = CommandExecutionError

    log.debug("Listing vault secret keys for %s in %s", __grains__.get("id"), path)
    try:
        return vault.list_kv(path, __opts__, __context__)
    except vault.VaultException as err:
        if default is CommandExecutionError:
            raise CommandExecutionError(
                f"Failed to list secrets! {type(err).__name__}: {err}"
            ) from err
        return default


def delete(path, *versions, all_versions=False, **_):
    """
    Delete secret at <path>. If <path> is on KV v2, the secret is soft-deleted.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.delete "secret/my/secret"
        salt '*' vault_secret.delete "secret/my/secret" 1 2 3
        salt '*' vault_secret.delete "secret/my/secret" all_versions=true

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2, delete most recent version
        path "<mount>/data/<secret>" {
            capabilities = ["delete"]
        }

        # KV v2, delete older version(s)
        # all_versions=True additionally requires the policy for vault_secret.read_meta
        path "<mount>/delete/<secret>" {
            capabilities = ["update"]
        }

        # OR (!) for KV v1
        path "<mount>/<secret>" {
            capabilities = ["delete"]
        }

    path
        Path to the secret, including mount.

    all_versions
        Delete all versions of the secret for KV v2.
        Can only be passed as a keyword argument.
        Defaults to false.

    .. note::
        For KV v2, you can specify versions to soft-delete as supplemental
        positional arguments.
    """
    log.debug("Deleting vault secrets for %s in %s", __grains__.get("id"), path)
    if versions:
        log.debug(f"Affected versions: {' '.join(str(x) for x in versions)}")
    try:
        return vault.delete_kv(
            path, __opts__, __context__, versions=list(versions) or None, all_versions=all_versions
        )
    except vault.VaultException as err:
        raise CommandExecutionError(
            f"Failed to delete secret! {type(err).__name__}: {err}"
        ) from err


def restore(path, *versions, all_versions=False, **_):
    """
    Restore specific versions of a secret path. Only supported on Vault KV v2.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.restore secret/my/secret 1 2

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2 only.
        # all_versions=True or defaulting to the most recent version additionally
        # requires the policy for vault_secret.read_meta
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
    log.debug("Restoring vault secrets for %s in %s", __grains__.get("id"), path)

    try:
        return vault.restore_kv(
            path, __opts__, __context__, list(versions) or None, all_versions=all_versions
        )
    except vault.VaultException as err:
        raise CommandExecutionError(
            f"Failed to restore secret! {type(err).__name__}: {err}"
        ) from err


def destroy(path, *versions, all_versions=False, **_):
    """
    Destroy specified secret versions at <path>.
    This makes a secret version unrecoverable.
    On KV v1, there is no functional difference to ``delete``
    because the backend does not support versioning.
    Specifying versions fails there.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.destroy "secret/my/secret"
        salt '*' vault_secret.destroy "secret/my/secret" 1 2
        salt '*' vault_secret.destroy "secret/my/secret" all_versions=true

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2
        # all_versions=True or defaulting to the most recent version additionally
        # requires the policy for vault_secret.read_meta
        path "<mount>/destroy/<secret>" {
            capabilities = ["update"]
        }

        # OR (!) for KV v1 (same as `vault_secret.delete`)
        path "<mount>/<secret>" {
            capabilities = ["delete"]
        }

    path
        Path to the secret, including mount.

    all_versions
        Destroy all versions of the secret for KV v2.
        Can only be passed as a keyword argument.
        Defaults to false.

    You can specify versions to destroy as supplemental positional arguments.
    If no version was specified, defaults to the most recent one.
    """
    log.debug("Destroying vault secrets for %s in %s", __grains__.get("id"), path)
    if versions:
        log.debug(f"Affected versions: {' '.join(str(x) for x in versions)}")
    try:
        return vault.destroy_kv(
            path, list(versions) or None, __opts__, __context__, all_versions=all_versions
        )
    except vault.VaultException as err:
        raise CommandExecutionError(
            f"Failed to destroy secret! {type(err).__name__}: {err}"
        ) from err


def wipe(path):
    """
    Remove all version history and data for the secret at <path>.
    On KV v1, there is no functional difference to ``delete``
    because the backend does not support versioning.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_secret.wipe "secret/my/secret"

    Required policy:

    .. code-block:: vaultpolicy

        # KV v2
        path "<mount>/metadata/<secret>" {
            capabilities = ["delete"]
        }

        # OR (!) for KV v1 (same as `vault_secret.delete`)
        path "<mount>/<secret>" {
            capabilities = ["delete"]
        }
    """
    log.debug("Wiping vault secrets for %s in %s", __grains__.get("id"), path)
    try:
        return vault.wipe_kv(path, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"Failed to wipe secret! {type(err).__name__}: {err}") from err
