"""
Manage the Vault SSH secret engine.

.. versionadded:: 1.2.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging

import salt.utils.dictdiffer
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault.helpers import deserialize_csl
from saltext.vault.utils.vault.helpers import timestring_map

log = logging.getLogger(__name__)

LIST_ROLE_PARAMS = (
    "allowed_users",
    "allowed_critical_options",
    "allowed_domains",
    "allowed_extensions",
    "cidr_list",
    "exclude_cidr_list",
)
MAP_ROLE_PARAMS = ("default_critical_options", "default_extensions", "allowed_user_key_lengths")
TIME_ROLE_PARAMS = ("ttl", "max_ttl", "not_before_duration")


def ca_present(
    name,
    private_key=None,
    public_key=None,
    key_type="ssh-rsa",
    key_bits=0,
    mount="ssh",
):
    """
    Ensure a CA is present on the mount. Note that only one is possible
    per mount. This state will not inspect the properties once a CA
    has been initialized.

    name
        Irrelevant.

    private_key
        The private key part of the SSH CA key pair. Can be a file
        local to the minion or a PEM-encoded string.
        If this or ``public_key`` is unspecified, will generate a pair
        on the Vault server.

    public_key
        The public key part of the SSH CA key pair. Can be a file
        local to the minion or a PEM-encoded string.
        If this or ``public_key`` is unspecified, will generate a pair
        on the Vault server.

    key_type
        The desired key type for the generated SSH CA key when generating
        on the Vault server. Valid: ``ssh-rsa`` (default), ``sha2-nistp256``,
        ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521``, or ``ssh-ed25519``.
        Can also specify an algorithm: ``rsa``, ``ec``, or ``ed25519``.

    key_bits
        The desired key bits for the generated SSH CA key when generating
        on the Vault server. Only used for variable length keys (e.g. ``ssh-rsa``)
        or when ``ec`` was specified as ``key_type``, in which case this
        selects the NIST P-curve: ``256``, ``384``, ``521``.
        0 (default) will select 4096 bits for RSA or NIST P-256 for EC.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The CA has already been initialized",
        "changes": {},
    }

    try:
        try:
            current = __salt__["vault_ssh.read_ca"](mount=mount)
        except CommandExecutionError as err:
            if "keys haven't been configured yet" not in str(err):
                raise
            current = None
        if current:
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The CA would have been initialized"
            ret["changes"]["created"] = f"SSH CA on mount {mount}"
            return ret

        ca = __salt__["vault_ssh.create_ca"](
            private_key=private_key,
            public_key=public_key,
            key_type=key_type,
            key_bits=key_bits,
            mount=mount,
        )
        ret["comment"] = "The CA has been initialized"
        ret["changes"]["created"] = ca

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def ca_absent(
    name,
    mount="ssh",
):
    """
    Ensure a CA is absent from the mount. Note that you will not be
    able to easily recover a destroy private key.

    name
        Irrelevant.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "There is no CA on the mount",
        "changes": {},
    }

    try:
        try:
            current = __salt__["vault_ssh.read_ca"](mount=mount)
        except CommandExecutionError as err:
            if "keys haven't been configured yet" not in str(err):
                raise
            # not sure if not found or empty response @TODO test
            current = None
        if not current:
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The CA would have been destroyed"
            ret["changes"]["destroyed"] = f"SSH CA on mount {mount}"
            return ret

        ca = __salt__["vault_ssh.destroy_ca"](mount=mount)
        ret["comment"] = "The CA has been destroyed"
        ret["changes"]["destroyed"] = ca

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_present_otp(
    name,
    default_user,
    cidr_list=None,
    allowed_users=None,
    exclude_cidr_list=None,
    port=None,
    mount="ssh",
):
    """
    Ensure an SSH role (OTP type) is present as specified.

    name
        The name of the SSH role.

    default_user
        The default username for which a credential will be generated.
        Required.

    cidr_list
        List of CIDR blocks to which the role is applicable.
        Required, unless the role is registered as a zero-address role.

    allowed_users
        List of usernames the client can request under this role.
        By default, **any usernames are allowed** (``*``).
        The ``default_user`` will always be allowed.

    exclude_cidr_list
        List of CIDR blocks not accepted by the role.

    port
        Specifies the port number for SSH connections, which will be returned to
        OTP clients as an informative value. Defaults to ``22``.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The role is present as specified",
        "changes": {},
    }

    try:
        port = int(port) if port else None
    except TypeError:
        ret["result"] = False
        ret["comment"] = "'port' must be castable to an integer"
        return ret

    payload = {
        "default_user": default_user,
        "cidr_list": cidr_list,
        "allowed_users": allowed_users,
        "exclude_cidr_list": exclude_cidr_list,
        "port": port,
    }
    return _role_present(name, "otp", ret, mount=mount, **payload)


def _diff_role_params(curr, wanted):
    diff = {}
    for param, val in wanted.items():
        if param in LIST_ROLE_PARAMS:
            curr_param = set(deserialize_csl(curr.get(param, [])))
            wanted_param = set(deserialize_csl(val or []))
            added = wanted_param - curr_param
            removed = curr_param - wanted_param
            if added or removed:
                diff[param] = {"added": list(sorted(added)), "removed": list(sorted(removed))}
            continue
        if param in MAP_ROLE_PARAMS:
            val = val or {}
            if param == "allowed_user_key_lengths":
                for algo, allowed in val.items():
                    if isinstance(allowed, int):
                        val[algo] = [allowed]
                    else:
                        val[algo] = deserialize_csl(allowed)
            map_diff = salt.utils.dictdiffer.recursive_diff(
                curr.get(param, {}), val, ignore_missing_keys=False
            )
            if map_diff.added() or map_diff.changed() or map_diff.removed():
                diff[param] = {
                    "added": map_diff.added(),
                    "changed": map_diff.changed(),
                    "removed": map_diff.removed(),
                }
            continue
        curr_val = curr.get(param)
        if param in TIME_ROLE_PARAMS:
            curr_val = timestring_map(curr_val)
            val = timestring_map(val)
        if curr_val != val:
            diff[param] = {"old": curr_val, "new": val}
    return diff


def _role_present(name, key_type, ret, mount="ssh", **kwargs):
    try:
        try:
            current = __salt__["vault_ssh.read_role"](name, mount=mount)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            current = None
            ret["changes"]["created"] = name
        if current:
            if current["key_type"] != key_type:
                ret["changes"]["key_type"] = {"old": current["key_type"], "new": key_type}
            else:
                ret["changes"] = _diff_role_params(current, kwargs)

        if not ret["changes"]:
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Role `{name}` would have been {'updated' if current else 'created'}"
            return ret

        __salt__[f"vault_ssh.write_role_{key_type}"](
            name,
            **kwargs,
            mount=mount,
        )

        try:
            new = __salt__["vault_ssh.read_role"](name, mount=mount)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            raise CommandExecutionError(
                "There were no errors during role management, but it is reported as absent."
            ) from err

        new_diff = _diff_role_params(new, kwargs)

        if new_diff:
            ret["result"] = False
            ret["comment"] = (
                "There were no errors during role management, but "
                f"the reported parameters do not match: {new_diff}"
            )
        else:
            ret["comment"] = f"Role `{name}` has been {'updated' if current else 'created'}"

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_present_ca(
    name,
    default_user="",
    default_user_template=False,
    allowed_users=None,
    allowed_users_template=False,
    allowed_domains=None,
    allowed_domains_template=False,
    ttl=0,
    max_ttl=0,
    allowed_critical_options=None,
    allowed_extensions=None,
    default_critical_options=None,
    default_extensions=None,
    default_extensions_template=False,
    allow_user_certificates=False,
    allow_host_certificates=False,
    allow_bare_domains=False,
    allow_subdomains=False,
    allow_user_key_ids=False,
    key_id_format="",
    allowed_user_key_lengths=None,
    algorithm_signer="default",
    not_before_duration=30,
    mount="ssh",
):
    """
    Ensure an SSH role (CA type) is present as specified.

    name
        The name of the SSH role.

    default_user
        The default username for which a credential will be generated.
        When ``default_user_template`` is true, this can contain an identity
        template with any prefix or suffix, like ``ssh-{{identity.entity.id}}-user``.
        If you wish this to be a valid principal, it must also be in ``allowed_users``.

    default_user_template
        Allow ``default_users`` to be specified using identity template values.
        A non-templated user is also permitted. Defaults to false.

    allowed_users
        List of usernames the client can request under this role.
        By default, none are allowed. Set this to ``*`` to allow any usernames.
        If ``allowed_users_template`` is true, this list can contain an
        identity template with any prefix or suffix. The ``default_user``
        will always be allowed.

    allowed_users_template
        Allow ``allowed_users`` to be specified using identity template values.
        Non-templated users are also permitted. Defaults to false.

    allowed_domains
        List of domains for which a client can request a host certificate.
        ``*`` allows any domain. See also ``allow_bare_domains`` and ``allow_subdomains``.

    allowed_domains_template
        Allow ``allowed_domains`` to be specified using identity template values.
        Non-templated domains are also permitted. Defaults to false.

    ttl
        Specifies the Time To Live value provided as a string duration with
        time suffix. Hour is the largest suffix. If unset, uses the system
        default value or the value of ``max_ttl``, whichever is shorter

    max_ttl
        Specifies the maximum Time To Live provided as a string duration with
        time suffix. Hour is the largest suffix. If unset, defaults to the
        system maximum lease TTL.

    allowed_critical_options
        List of critical options that certificates can carry when signed.
        If unset (default), allows any option.

    allowed_extensions
        List of extensions that certificates can carry when signed.
        If unset (default), will always take the extensions
        from ``default_extensions`` only. If set to ``*``, will allow
        any extension to be set.
        For the list of extensions, take a look at the sshd manual's
        AUTHORIZED_KEYS FILE FORMAT section. You should add a ``permit-``
        before the name of extension to allow it.

    default_critical_options
        Map of critical options to their values certificates should carry
        if none are provided when signing.

    default_extensions
        Map of extensions to their values certificates should carry
        if none are provided when signing or allowed_extensions is unset.

    default_extensions_template
        Allow ``default_extensions`` to be specified using identity template values.
        Non-templated values are also permitted. Defaults to false.

    allow_user_certificates
        Allow certificates to be signed for ``user`` use. Defaults to false.

    allow_host_certificates
        Allow certificates to be signed for ``host`` use. Defaults to false.

    allow_bare_domains
        Allow host certificates to be signed for the base domains listed in
        ``allowed_domains``. This is a separate option as in some cases this
        can be considered a security threat. Defaults to false.

    allow_subdomains
        Allow host certificates to be signed for subdomains of the base domains
        listed in ``allowed_domains``. Defaults to false.

    allow_user_key_ids
        Allow users to override the key ID for a certificate. When false (default),
        the key ID will always be the token display name.
        The key ID is logged by the SSH server and can be useful for auditing.

    key_id_format
        Specifies a custom format for the key ID of a signed certificate.
        See `key_id_format <https://developer.hashicorp.com/vault/api-docs/secret/ssh#key_id_format>`_
        for available template values.

    allowed_user_key_lengths
        Map of ssh key types to allowed sizes when signing with the CA type.
        Values can be a list of multiple sizes.
        Keys can both be OpenSSH-style key identifiers and short names
        (``rsa``, ``ecdsa``, ``dsa``, or ``ed25519``). If an algorithm has
        a fixed key size, values are ignored.

    algorithm_signer
        **RSA** algorithm to sign keys with. Valid: ``ssh-rsa``, ``rsa-sha2-256``,
        ``rsa-sha2-512``, or ``default`` (which is the default). Ignored
        when not signing with an RSA key.

    not_before_duration
        Specifies the duration by which to backdate the ``ValidAfter`` property.
        Defaults to ``30s``.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The role is present as specified",
        "changes": {},
    }

    if not (allow_user_certificates or allow_host_certificates):
        ret["result"] = False
        ret["comment"] = "Either allow_user_certificates or allow_host_certificates must be true"
        return ret

    payload = {
        "default_user": default_user,
        "default_user_template": default_user_template,
        "allowed_users": allowed_users,
        "allowed_users_template": allowed_users_template,
        "allowed_domains": allowed_domains,
        "allowed_domains_template": allowed_domains_template,
        "ttl": ttl,
        "max_ttl": max_ttl,
        "allowed_critical_options": allowed_critical_options,
        "allowed_extensions": allowed_extensions,
        "default_critical_options": default_critical_options,
        "default_extensions": default_extensions,
        "default_extensions_template": default_extensions_template,
        "allow_user_certificates": allow_user_certificates,
        "allow_host_certificates": allow_host_certificates,
        "allow_bare_domains": allow_bare_domains,
        "allow_subdomains": allow_subdomains,
        "allow_user_key_ids": allow_user_key_ids,
        "key_id_format": key_id_format,
        "allowed_user_key_lengths": allowed_user_key_lengths,
        "algorithm_signer": algorithm_signer,
        "not_before_duration": not_before_duration,
    }
    return _role_present(name, "ca", ret, mount=mount, **payload)


def role_absent(name, mount="ssh"):
    """
    Ensure an SSH role is absent.

    name
        The name of the role.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The role is already absent",
        "changes": {},
    }

    try:
        try:
            __salt__["vault_ssh.read_role"](name, mount=mount)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Role `{name}` would have been deleted."
            return ret

        __salt__["vault_ssh.delete_role"](name, mount=mount)

        try:
            __salt__["vault_ssh.read_role"](name, mount=mount)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            ret["comment"] = f"Role `{name}` has been deleted."
            return ret
        raise CommandExecutionError(
            "There were no errors during role deletion, but it is still reported as present."
        )

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret
