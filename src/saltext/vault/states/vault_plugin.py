"""
Manage Vault (or OpenBao) plugins.

.. versionadded:: 1.8.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
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

__virtualname__ = "vault_plugin"


def __virtual__():
    return __virtualname__


def _manage_plugin(
    name,
    plugin_type,
    *,
    sha256,
    version,
    command,
    args,
    env,
    oci_image,
    runtime,
    download,
):
    ret = {
        "name": name,
        "result": True,
        "comment": "Plugin is registered as specified",
        "changes": {},
    }
    changes = {}
    try:
        try:
            current = __salt__["vault_plugin.get_config"](plugin_type, name, version=version)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            current = None
            changes["registered"] = name
        else:
            if current["sha256"] != sha256:
                changes["sha256"] = {"old": current["sha256"], "new": sha256}
            if command is not None and current["command"] != command:
                changes["command"] = {"old": current["command"], "new": command}
            if args is not None and current["args"] != args:
                changes["args"] = {"old": current["args"], "new": args}
            # env is not reported
            # unsure about the following, could not test
            if oci_image is not None and current.get("oci_image") != oci_image:
                changes["oci_image"] = {"old": current["oci_image"], "new": oci_image}
            if runtime is not None and current.get("runtime") != runtime:
                changes["runtime"] = {"old": current["runtime"], "new": runtime}

        if not changes:
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["changes"] = changes
            ret["comment"] = (
                f"Plugin config would have been {'updated' if current else 'registered'}"
            )
            return ret

        __salt__["vault_plugin.register"](
            plugin_type=plugin_type,
            name=name,
            sha256=sha256,
            version=version or None,
            command=command,
            args=args,
            env=env,
            oci_image=oci_image,
            runtime=runtime,
            download=download,
        )
        ret["comment"] = f"Plugin config has been {'updated' if current else 'registered'}"
        ret["changes"] = changes
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)

    return ret


def registered(
    name,
    plugin_type,
    sha256=None,
    command=None,
    args=None,
    env=None,
    oci_image=None,
    runtime=None,
    download=False,
):
    """
    Ensure an unversioned plugin is registered as specified.

    name
        Name of the plugin to manage.

    plugin_type
        Type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.

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

        .. important::
            Not managed statefully since the API does not report the value, i.e. this is only
            set when a plugin is registered for the first time or when other values change.

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
    return _manage_plugin(
        name,
        plugin_type,
        sha256=sha256,
        version="",
        command=command,
        args=args,
        env=env,
        oci_image=oci_image,
        runtime=runtime,
        download=download,
    )


def unregistered(name, plugin_type):
    """
    Ensure an unversioned plugin is not registered.

    name
        Name of the plugin to manage.

    plugin_type
        Type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "Unversioned plugin is already absent",
        "changes": {},
    }

    try:
        try:
            __salt__["vault_plugin.get_config"](plugin_type, name, version="")
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["changes"]["deregistered"] = name
            ret["comment"] = "Unversioned plugin would have been deregistered"
            return ret

        __salt__["vault_plugin.deregister"](plugin_type=plugin_type, name=name)
        ret["comment"] = "Unversioned plugin has been deregistered"
        ret["changes"]["deregistered"] = name
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)

    return ret


def version_registered(
    name,
    plugin_type,
    version,
    sha256=None,
    command=None,
    args=None,
    env=None,
    oci_image=None,
    runtime=None,
    download=False,
):
    """
    Ensure a versioned plugin is registered as specified.

    name
        Name of the plugin to manage.

    plugin_type
        Type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.

    version
        Specifies the semantic version of this plugin.
        Used as the tag when specifying ``oci_image``, but with any leading 'v' trimmed.

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

        .. important::
            Not managed statefully since the API does not report the value, i.e. this is only
            set when a plugin is registered for the first time or when other values change.

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
    if not version:
        return {
            "name": name,
            "result": False,
            "comment": "Plugin version must be specified and not empty",
            "changes": {},
        }

    return _manage_plugin(
        name,
        plugin_type,
        sha256=sha256,
        version=version,
        command=command,
        args=args,
        env=env,
        oci_image=oci_image,
        runtime=runtime,
        download=download,
    )


def version_unregistered(name, plugin_type, version):
    """
    Ensure one or more versions of a versioned plugin are not registered.

    name
        Name of the plugin to manage.

    plugin_type
        Type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.

    version
        Version to remove. Can be a glob, which removes all matching versions.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "All matching plugin versions are already absent",
        "changes": {},
    }

    if not version:
        ret["result"] = False
        ret["comment"] = "Plugin version must be specified and not empty"
        return ret

    try:
        matches = __salt__["vault_plugin.list_detailed"](
            plugin_type=plugin_type, name=name, version=version
        )
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        return ret

    versions = [plugin["version"] for plugin in matches if plugin["version"]]
    if not versions:
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["changes"]["deregistered"] = versions
        ret["comment"] = "Matching plugin versions would have been deregistered"
        return ret

    failed = {}
    for ver in versions:
        try:
            __salt__["vault_plugin.deregister"](plugin_type=plugin_type, name=name, version=ver)
            ret["changes"].setdefault("deregistered", []).append(ver)
        except (CommandExecutionError, SaltInvocationError) as err:
            failed[ver] = str(err)

    if failed:
        ret["result"] = False
        ret["comment"] = "Some versions could not be deregistered:\n  * " + "\n  * ".join(
            f"{version}: {err}" for version, err in failed.items()
        )
        return ret

    ret["comment"] = "Matching plugin versions have been deregistered"
    return ret


def version_pinned(name, plugin_type, version, now=False, now_globally=False):
    """
    Ensure a plugin is pinned to a specific version.

    .. note::
        Only available on Vault.

    name
        Name of the plugin to manage.

    plugin_type
        Type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.

    version
        Version to pin.

    now
        After pinning, reload all mounts of the plugin. Defaults to false.

    now_globally
        When ``now`` is true, begin reloading plugin on all cluster nodes. Defaults to false,
        which only reloads mounts on the targeted node.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "Plugin is already pinned to correct version",
        "changes": {},
    }
    try:
        if not version:
            raise CommandExecutionError("Plugin version must be specified and not empty")
        curr = __salt__["vault_plugin.pinned_version"](plugin_type, name)
        if curr:
            if curr.lstrip("v") == version.lstrip("v"):
                return ret
        ret["changes"] = {"old": curr, "new": version}
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                "Pinned version would have been updated"
                if curr
                else "Plugin would have been pinned"
            )
            return ret
        # Note: It might be better to do the reload logic in here for better reporting
        __salt__["vault_plugin.pin"](plugin_type, name, version, now=now, now_globally=now_globally)
        ret["comment"] = "Pinned version has been updated" if curr else "Plugin has been pinned"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def version_unpinned(name, plugin_type, now=False, now_globally=False):
    """
    Ensure a plugin is pinned to a specific version.

    .. note::
        Only available on Vault.

    name
        Name of the plugin to manage.

    plugin_type
        Type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.

    now
        After unpinning, reload all mounts of the plugin. Defaults to false.

    now_globally
        When ``now`` is true, begin reloading plugin on all cluster nodes. Defaults to false,
        which only reloads mounts on the targeted node.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "Plugin is already unpinned",
        "changes": {},
    }
    try:
        curr = __salt__["vault_plugin.pinned_version"](plugin_type, name)
        if curr is None:
            return ret
        ret["changes"] = {"old": curr, "new": None}
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Version pin would have been removed"
            return ret
        # Note: It might be better to do the reload logic in here for better reporting
        __salt__["vault_plugin.unpin"](plugin_type, name, now=now, now_globally=now_globally)
        ret["comment"] = "Version pin has been removed"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret
