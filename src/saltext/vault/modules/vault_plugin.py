"""
Manage Vault (or OpenBao) plugins.

.. versionadded:: 1.8.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import fnmatch
import logging
import typing

import salt.utils.versions
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltException
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault

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

__func_alias__ = {"list_": "list"}

__virtualname__ = "vault_plugin"


def __virtual__():
    return __virtualname__


def _list_all_filtered(
    plugin_type=None, name=None, builtin=None, version=None, sha256=None, glob=False
):
    if plugin_type is not None:
        plugin_type = _check_type(plugin_type)
    if version is not None:
        version = version.lstrip("v")
    try:
        res = vault.query("GET", "sys/plugins/catalog", __opts__, __context__)["data"]
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    return [
        plugin
        for plugin in res["detailed"]
        if (
            (plugin_type is None or plugin["type"] == plugin_type)
            and (name is None or plugin["name"] == name or fnmatch.fnmatch(plugin["name"], name))
            and (builtin is None or plugin["builtin"] is builtin)
            and (
                version is None
                or plugin["version"].lstrip("v") == version
                or (glob and fnmatch.fnmatch(plugin["version"].lstrip("v"), version))
            )
            and (sha256 is None or ("sha256" in plugin and plugin["sha256"] == sha256))
        )
    ]


def _list_pins_filtered(plugin_type=None, name=None, glob=False):
    if plugin_type is not None:
        plugin_type = _check_type(plugin_type)
    try:
        res = vault.query("GET", "sys/plugins/pins", __opts__, __context__)["data"][
            "pinned_versions"
        ]
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    return [
        pin
        for pin in res
        if (
            (plugin_type is None or pin["type"] == plugin_type)
            and (
                name is None or pin["name"] == name or (glob and fnmatch.fnmatch(pin["name"], name))
            )
        )
    ]


def list_(plugin_type):
    """
    List all registered plugins of a specific type.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.list auth

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog" {
            capabilities = ["read"]
        }

    plugin_type
        Plugin type to list. Either ``auth``, ``database`` or ``secret``.
    """
    # When custom plugins are registered with a version, they are not included in the
    # plugin type-specific lists, only in the full list. Workaround that bug ourselves.
    # Related: https://github.com/hashicorp/vault/issues/28936
    matches = _list_all_filtered(plugin_type)
    return list(sorted({plugin["name"] for plugin in matches}))


def list_versions(plugin_type, name):
    """
    List all registered versions of a plugin.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.list_versions database mymysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog" {
            capabilities = ["read"]
        }

    plugin_type
        Type of the plugin to list versions of. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to list versions of.
    """
    matches = _list_all_filtered(plugin_type, name)
    return list(sorted({plugin["version"] for plugin in matches}))


def list_detailed(plugin_type=None, name=None, builtin=None, version=None, sha256=None):
    """
    List detailed information about plugins.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.list_detailed
        salt '*' vault_plugin.list_detailed database
        salt '*' vault_plugin.list_detailed database mymysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog" {
            capabilities = ["read"]
        }

    plugin_type
        Filter for type of plugin. Optional. Either ``auth``, ``database`` or ``secret``.

    name
        Filter for the name of the plugin. Optional. Can be a glob.

    builtin
        Filter for plugins that are builtin/not builtin. Either ``true`` or ``false``. Optional.

    version
        Filter for the plugin version. Optional. Can be a glob.
        Set this to the empty string to filter for unversioned plugins.

    sha256
        Filter for plugins that match this SHA256 hash. Optional.
    """
    return _list_all_filtered(
        plugin_type=plugin_type,
        name=name,
        builtin=builtin,
        version=version,
        sha256=sha256,
        glob=True,
    )


def list_pins(plugin_type=None, name=None):
    """
    List detailed information about pinned plugins.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.list_pins
        salt '*' vault_plugin.list_pins database
        salt '*' vault_plugin.list_pins name='my*'

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/pins" {
            capabilities = ["read"]
        }

    plugin_type
        Filter for type of plugin. Optional. Either ``auth``, ``database`` or ``secret``.

    name
        Filter for the name of the plugin. Optional. Can be a glob.
    """
    return _list_pins_filtered(plugin_type, name, glob=True)


def pinned_version(plugin_type, name):
    """
    Get the pinned version of a plugin, if any.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.pinned_version database mymysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/pins/<plugin_type>/<name>" {
            capabilities = ["read"]
        }

    plugin_type
        Type of the plugin to show pinned version for. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to show pinned version for.
    """
    try:
        return vault.query("get", f"sys/plugins/pins/{plugin_type}/{name}", __opts__, __context__)[
            "data"
        ]["version"]
    except vault.VaultNotFoundError:
        return None
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def pin(plugin_type, name, version, now=False, now_globally=False):
    """
    Pin a plugin to a specific version. Optionally reload existing mounts to apply new pin.

    .. note::
        Only available on Vault.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.pin database mymysql-database-plugin v1.2.3
        salt '*' vault_plugin.pin database mymysql-database-plugin v1.2.3 now=true
        salt '*' vault_plugin.pin database mymysql-database-plugin v1.2.3 now=true now_globally=true

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/pins/<plugin_type>/<name>" {
            capabilities = ["update"]
        }

        # For reload behavior
        path "sys/plugins/reload/<plugin_type>/<name>" {
            capabilities = ["update"]
        }

    plugin_type
        Type of the plugin to pin. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to pin.

    now
        After pinning, reload all mounts of the plugin. Defaults to false.

    now_globally
        When ``now`` is true, begin reloading plugin on all cluster nodes. Defaults to false,
        which only reloads mounts on the targeted node.
    """
    plugin_type = _check_type(plugin_type)
    payload = {"version": version}
    try:
        vault.query(
            "POST", f"sys/plugins/pins/{plugin_type}/{name}", __opts__, __context__, payload=payload
        )
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if not now:
        return True
    reload(plugin_type, name, globally=now_globally)
    return True


def unpin(plugin_type, name, now=False, now_globally=False):
    """
    Unpin a plugin. Optionally reload existing mounts to apply removed restriction.

    .. note::
        Only available on Vault.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.unpin database mymysql-database-plugin
        salt '*' vault_plugin.unpin database mymysql-database-plugin now=true
        salt '*' vault_plugin.unpin database mymysql-database-plugin now=true now_globally=true

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/pins/<plugin_type>/<name>" {
            capabilities = ["delete"]
        }

        # For reload behavior
        path "sys/plugins/reload/<plugin_type>/<name>" {
            capabilities = ["update"]
        }

    plugin_type
        Type of the plugin to pin. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to pin.

    now
        After unpinning, reload all mounts of the plugin. Defaults to false.

    now_globally
        When ``now`` is true, begin reloading plugin on all cluster nodes. Defaults to false,
        which only reloads mounts on the targeted node.
    """
    plugin_type = _check_type(plugin_type)
    try:
        vault.query("DELETE", f"sys/plugins/pins/{plugin_type}/{name}", __opts__, __context__)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if not now:
        return True
    reload(plugin_type, name, globally=now_globally)
    return True


def get_config(plugin_type, name, version=None):
    """
    Get plugin configuration of a specific plugin (version).

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.get_config database mysql-database-plugin
        salt '*' vault_plugin.get_config database mymysql-database-plugin version=v1.0.0

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>/<name>" {
            capabilities = ["read", "sudo"]
        }

    plugin_type
        Type of the plugin to get config for. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to get config for.

    version
        Registered plugin version to get configuration for.

        Behavior if unspecified:

        * If the plugin is a builtin plugin or an unversioned custom one, this works in a straightforward way.
        * If the plugin is a versioned custom one, Vault errors. In this case, this function tries to find
          the version Vault defaults to for new mounts.
          First, by checking if any version is pinned (on Vault).
          If not, looks for the highest version and returns its configuration.

        Explicitly set this to the empty string to disable fallback behavior and query for builtin/unversioned plugins only.
    """
    plugin_type = _check_type(plugin_type)
    endpoint = f"sys/plugins/catalog/{plugin_type}/{name}"
    try:
        return vault.query(
            "GET",
            endpoint,
            __opts__,
            __context__,
            payload={"version": version} if version else None,
        )["data"]
    except vault.VaultNotFoundError as err:
        if version is not None:
            raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
        # version was unspecified, let's try to find a custom versioned plugin and return its default version for new mounts.
        try:
            pinned = pinned_version(plugin_type, name)
        except SaltException:
            pinned = None
        highest = None
        if not pinned:
            # No version is pinned for this plugin. Try listing all versions and selecting the highest one.
            try:
                versions = list_detailed(plugin_type=plugin_type, name=name)
            except SaltException:
                pass
            else:
                for ver in versions:
                    if not ver.get("version"):  # pragma: no cover
                        continue  # sanity check
                    if not highest or salt.utils.versions.version_cmp(ver["version"], highest) > 0:
                        highest = ver["version"]
        best_version = pinned or highest
        if not best_version:
            raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    try:
        return vault.query(
            "GET",
            endpoint,
            __opts__,
            __context__,
            payload={"version": best_version},
        )["data"]
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def register(
    plugin_type,
    name,
    sha256=None,
    command=None,
    args=None,
    env=None,
    version=None,
    oci_image=None,
    runtime=None,
    download=False,
):
    """
    Register a plugin.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.register database mymysql-database-plugin deadbeefcafebabe...

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>/<name>" {
            capabilities = ["create", "update", "sudo"]
        }

    plugin_type
        Type of the plugin to register. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to register.

    sha256
        SHA256 hexdigest of the plugin binary or the OCI image.
        Before Vault runs a plugin, it checks the plugin SHA against this value.
        If the actual SHA of the plugin binary and the SHA provided here do not match,
        Vault refuses to run the plugin.

        .. note::
            Required to register a plugin binary. Must be unset to register an extracted ``.zip`` file.

    command
        Specifies the command used to execute the plugin. This is relative to the plugin directory,
        e.g. "myplugin", or if ``oci_image`` is also specified, it is relative to the image's
        working directory. If unspecified and ``oci_image`` is not defined, defaults to the ``name``.

        .. note::
            Ignored when registering with an extracted ``.zip`` file as the associated run command is known then.

    args
        List of arguments used to execute the plugin. Optional.

    env
        List of environment variables used during the execution of the plugin.
        Each entry is of the form "key=value".

    version
        Specifies the semantic version of this plugin.
        Used as the tag when specifying ``oci_image``, but with any leading 'v' trimmed.
        You can omit version to register a plugin binary, but you must provide an explicit version
        to register an extracted ``.zip`` file

    oci_image
        Vault only:
        Specifies OCI image to run. If specified, setting ``command``, ``args``, and ``env`` updates
        the container's entrypoint, args, and environment variables (append-only) respectively.

    runtime
        Vault only:
        Specifies Vault plugin runtime to use if ``oci_image`` is specified.

    download
        Vault Enterprise only:
        Download the specified plugin from HashiCorp's releases page.
    """
    plugin_type = _check_type(plugin_type)
    if command is None and not oci_image:
        command = name

    payload = {}
    if command is not None:
        payload["command"] = command
    if sha256 is not None:
        payload["sha256"] = sha256
    if version is not None:
        payload["version"] = version
    if args is not None:
        payload["args"] = args
    if env is not None:
        payload["env"] = env
    if oci_image is not None:
        payload["oci_image"] = oci_image
        if runtime is not None:
            payload["runtime"] = runtime
    if download:
        payload["download"] = True
    try:
        vault.query(
            "POST",
            f"sys/plugins/catalog/{plugin_type}/{name}",
            __opts__,
            __context__,
            payload=payload,
        )
        return True
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def deregister(plugin_type, name, version=None):
    """
    Deregister a plugin.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.deregister database mymysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>/<name>" {
            capabilities = ["delete", "sudo"]
        }

    plugin_type
        Type of the plugin to deregister. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to deregister.

    version
        Specifies the semantic version of the plugin to delete.
    """
    plugin_type = _check_type(plugin_type)
    endpoint = f"sys/plugins/catalog/{plugin_type}/{name}"
    try:
        vault.query(
            "DELETE",
            endpoint,
            __opts__,
            __context__,
            payload={"version": version} if version else None,
        )
        return True
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def reload(plugin_type, name, globally=False):
    """
    Reload a plugin across all namespaces. Kills all instances and starts new ones,
    respecting a potentially modified pin.

    .. note::
        Only available on Vault.

    .. note::
        Must be run inside the root namespace.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.reload database mymysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/reload/<plugin_type>/<name>" {
            capabilities = ["update"]
        }

    plugin_type
        Type of the plugin to reload. Either ``auth``, ``database`` or ``secret``.

    name
        Name of the plugin to reload.

    globally
        By default, reloads the plugin on the targeted Vault instance.
        If true, begins reloading the plugin on all instances of a cluster.
    """
    plugin_type = _check_type(plugin_type)
    payload = {}
    if globally:
        payload["scope"] = "global"
    try:
        ret = vault.query(
            "post",
            f"sys/plugins/reload/{plugin_type}/{name}",
            __opts__,
            __context__,
            payload=payload,
        )
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    if ret.get("warnings") and "no plugins were reloaded" in ret["warnings"]:
        return False
    return ret["data"]["reload_id"]


def reload_named(name, globally=False):
    """
    Reload plugin by name in the current namespace.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.reload_name mysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/reload/backend" {
            capabilities = ["update"]
        }

    name
        Name of the plugin to reload.

    globally
        By default, reloads the plugin on the targeted Vault instance.
        If true, begins reloading the plugin on all instances of a cluster.
    """
    endpoint = "sys/plugins/reload/backend"
    payload = {"plugin": name}
    if globally:
        payload["scope"] = "global"
    try:
        res = vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultInvocationError as err:
        # Make OpenBao behave the same as Vault
        if "plugin not found in the catalog" not in str(err):
            raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
        return False
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    if res.get("warnings") and "no plugins were reloaded" in res["warnings"]:
        return False
    return res["data"]["reload_id"]


def reload_mounts(mounts, globally=False):
    """
    Reload plugins for specified mounts in the current namespace.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.reload_mounts database
        salt '*' vault_plugin.reload_mounts mounts='[database, other_mount]'

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/reload/backend" {
            capabilities = ["update"]
        }

    mounts
        Mount names or list thereof to reload backing plugins for.

    globally
        By default, reloads the mounts on the targeted Vault instance.
        If true, begins reloading the mounts on all instances of a cluster.
    """
    endpoint = "sys/plugins/reload/backend"
    if not isinstance(mounts, list):
        mounts = [mounts]
    payload = {"mounts": mounts}
    if globally:
        payload["scope"] = "global"
    try:
        ret = vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    if ret.get("warnings") and "no plugins were reloaded" in ret["warnings"]:
        return False
    return ret["data"]["reload_id"]


def _check_type(
    plugin_type: str,
) -> typing.Literal["auth"] | typing.Literal["database"] | typing.Literal["secret"]:
    if plugin_type not in ("auth", "database", "secret"):
        raise SaltInvocationError(f"Invalid plugin type: {plugin_type}")
    return plugin_type
