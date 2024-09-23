"""
Manage the Vault SSH secret engine, request SSH credentials
and certificates.

.. versionadded:: 1.2.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from pathlib import Path

import salt.utils.json
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault
from saltext.vault.utils.vault.helpers import deserialize_csl

__virtualname__ = "vault_ssh"

log = logging.getLogger(__name__)


def __virtual__():
    return __virtualname__


def read_role(name, mount="ssh"):
    """
    Reads an existing SSH role.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.read_role sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["read"]
        }

    name
        The name of the SSH role.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("GET", f"{mount}/roles/{name}", __opts__, __context__)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write_role_otp(
    name,
    default_user,
    cidr_list=None,
    allowed_users=None,
    exclude_cidr_list=None,
    port=None,
    mount="ssh",
):
    """
    Create/update an SSH role (OTP type).

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.write_role_otp sre sre-user '["1.0.0.0/24"]'

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["create", "update"]
        }

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
    payload = {
        "default_user": default_user,
        "cidr_list": cidr_list,
        "allowed_users": allowed_users,
        "exclude_cidr_list": exclude_cidr_list,
        "port": int(port) if port else None,
    }
    for param in ("allowed_users", "cidr_list", "exclude_cidr_list"):
        payload[param] = deserialize_csl(payload[param])
    return _write_role(name, "otp", mount=mount, **payload)


def write_role_ca(
    name,
    default_user="",
    default_user_template=None,
    allowed_users=None,
    allowed_users_template=None,
    allowed_domains=None,
    allowed_domains_template=None,
    ttl=None,
    max_ttl=None,
    allowed_critical_options=None,
    allowed_extensions=None,
    default_critical_options=None,
    default_extensions=None,
    default_extensions_template=None,
    allow_user_certificates=None,
    allow_host_certificates=None,
    allow_bare_domains=None,
    allow_subdomains=None,
    allow_user_key_ids=None,
    key_id_format=None,
    allowed_user_key_lengths=None,
    algorithm_signer=None,
    not_before_duration=None,
    mount="ssh",
):
    """
    Create/update an SSH role (CA type).

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.write_role_ca sre allowed_users=[sre-user] allow_user_certificates=true

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["create", "update"]
        }

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
    if not (allow_user_certificates or allow_host_certificates):
        raise SaltInvocationError(
            "Either allow_user_certificates or allow_host_certificates must be true"
        )

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
    for param in (
        "allowed_users",
        "allowed_critical_options",
        "allowed_domains",
        "allowed_extensions",
    ):
        payload[param] = deserialize_csl(payload[param])

    for param in ("default_critical_options", "default_extensions", "allowed_user_key_lengths"):
        if payload[param] and not isinstance(payload[param], dict):
            raise SaltInvocationError(f"Parameter '{param}' must be specified as a mapping")
    return _write_role(name, "ca", mount=mount, **payload)


def _write_role(name, key_type, mount="ssh", **kwargs):
    endpoint = f"{mount}/roles/{name}"
    kwargs["key_type"] = key_type

    payload = {}
    for param, val in kwargs.items():
        if isinstance(val, list):
            payload[param] = ",".join(val)
        elif val is not None:
            payload[param] = val
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete_role(name, mount="ssh"):
    """
    Deletes an existing SSH role.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.delete_role sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["delete"]
        }

    name
        The name of the SSH role.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("DELETE", f"{mount}/roles/{name}", __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_roles(mount="ssh"):
    """
    Lists existing SSH roles.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.list_roles

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles" {
            capabilities = ["list"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        res = vault.query("LIST", f"{mount}/roles", __opts__, __context__)["data"]
    except vault.VaultNotFoundError:
        return {}
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    keys = res["key_info"]
    for key in res["keys"]:
        if key not in keys:
            keys[key] = {}
    return keys


def list_roles_ip(address, mount="ssh"):
    """
    Lists existing SSH roles associated with a given IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.list_roles_ip 10.1.0.1

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/lookup" {
            capabilities = ["create", "update"]
        }

    address
        The IP address to list roles for.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/lookup"
    payload = {"ip": address}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"][
            "roles"
        ]
    except vault.VaultInvocationError as err:
        if "Missing roles" not in str(err):
            raise
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_roles_zeroaddr(mount="ssh"):
    """
    Return the list of configured zero-address roles. These are roles
    that are allowed to request credentials for any IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.list_roles_zeroaddr

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/zeroaddress" {
            capabilities = ["read"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("GET", f"{mount}/config/zeroaddress", __opts__, __context__)["data"][
            "roles"
        ]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write_zeroaddr_roles(roles, mount="ssh"):
    """
    Write the list of configured zero-address roles. These are roles
    that are allowed to request credentials for any IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.write_roles_zeroaddr '[super, admin]'

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/zeroaddress" {
            capabilities = ["create", "update"]
        }

    roles
        The list of role names that should be marked as zero address roles.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/config/zeroaddress"
    payload = {"roles": roles}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete_zeroaddr_roles(mount="ssh"):
    """
    Delete the list of configured zero-address roles. These are roles
    that are allowed to request credentials for any IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.delete_roles_zeroaddr

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/zeroaddress" {
            capabilities = ["delete"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("DELETE", f"{mount}/config/zeroaddress", __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def get_creds(name, address, username="", mount="ssh"):
    """
    Generate credentials for a specific IP (and username) using an existing role.
    Returns a mapping with ``ip``, ``key``, ``key_type``, ``port`` and ``username``.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.get_creds sre 10.1.0.1
        salt '*' vault_ssh.get_creds sre 10.1.0.1 bob

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/creds/<role_name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the role.

    address
        The IP address of the host to generate credentials for.

    username
        The username on the remote host to generate credentials for.
        If empty, the default username of the role will be used.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/creds/{name}"
    payload = {"ip": address, "username": username}
    # TODO: cache lease!
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def create_ca(
    private_key=None,
    public_key=None,
    key_type="ssh-rsa",
    key_bits=0,
    mount="ssh",
):
    """
    Create a CA to be used for certificate authentication.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.create_ca

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/ca" {
            capabilities = ["create", "update"]
        }

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
    endpoint = f"{mount}/config/ca"

    if private_key and public_key:
        payload = {
            "generate_signing_key": False,
            "private_key": _get_file_or_data(private_key),
            "public_key": _get_file_or_data(public_key),
        }
    else:
        payload = {
            "generate_signing_key": True,
            "key_type": key_type,
            "key_bits": key_bits,
        }

    try:
        res = vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    try:
        return res["data"]["public_key"]
    except TypeError:
        # when keys have been imported, we just receive a boolean
        return read_ca(mount=mount)


def destroy_ca(mount="ssh"):
    """
    Destroy an existing CA on the mount.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.destroy_ca

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/ca" {
            capabilities = ["delete"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("DELETE", f"{mount}/config/ca", __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_ca(mount="ssh"):
    """
    Read the public key for an existing CA on the mount.
    This defaults to reading from the authenticated endpoint, but falls
    back to the unauthenticated one.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.read_ca

    Required policy: None for the unauthenticated endpoint or

    .. code-block:: vaultpolicy

        path "<mount>/config/ca" {
            capabilities = ["read"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("GET", f"{mount}/config/ca", __opts__, __context__)["data"]["public_key"]
    except vault.VaultPermissionDeniedError:
        log.info("Permission denied for the authenticated endpoint, trying unauthenticated one")
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    try:
        res = vault.query_raw("GET", f"{mount}/public_key", __opts__, __context__, is_unauthd=True)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if res.status_code == 200:
        return res.text
    res.raise_for_status()
    raise CommandExecutionError(
        f"Internal error, this should not have been hit. Response ({res.status_code}): {res.text}"
    )


def sign_key(
    name,
    public_key,
    ttl=None,
    valid_principals=None,
    cert_type="user",
    key_id=None,
    critical_options=None,
    extensions=None,
    mount="ssh",
):
    """
    Sign an SSH public key under an existing role on the mount.
    Returns a mapping with ``serial_number`` and ``signed_key``.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.sign_key sre $HOME/.ssh/id_me.pub

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/sign/<role_name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the SSH role.

    public_key
        The SSH public key that should be signed. Can be a file local to
        the minion or a PEM-encoded string.

    ttl
        Request a specific time to live for the certificate, limited by the
        role's TTL. If unspecified, will default to the role's TTL or system
        values.

    valid_principals
        List of usernames/hostnames the certificate should be signed for.

    cert_type
        The type of certificate to issue, either ``user`` or ``host``. Defaults
        to ``user``.

    key_id
        The key ID the created certificate should have. If unspecified, the display
        name of the creating token will be used.

    critical_options
        A map of critical options the certificate should carry.

    extensions
        A map of extensions the certificate should carry.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/sign/{name}"
    payload = {"public_key": _get_file_or_data(public_key), "cert_type": cert_type}

    if ttl is not None:
        payload["ttl"] = ttl
    if key_id is not None:
        payload["key_id"] = key_id

    if valid_principals is not None:
        if isinstance(valid_principals, list):
            valid_principals = ",".join(valid_principals)
        payload["valid_principals"] = valid_principals

    for param, val in [
        ("critical_options", critical_options),
        ("extensions", extensions),
    ]:
        if val is not None:
            payload[param] = {
                k: salt.utils.json.dumps(v) if isinstance(v, (dict, list)) else v
                for k, v in val.items()
            }

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def generate_key_cert(
    name,
    key_type="ssh-rsa",
    key_bits=0,
    ttl=None,
    valid_principals=None,
    cert_type="user",
    key_id=None,
    critical_options=None,
    extensions=None,
    mount="ssh",
):
    """
    Generate an SSH private key and accompanying signed certificate.
    Returns a mapping with keys ``private_key``, ``private_key_type``,
    ``serial_number``, ``signed_key``.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.generate_key_cert sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/sign/<role_name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the SSH role.

    key_type
        The desired key type for the generated SSH CA key.
        Valid: ``ssh-rsa`` (default), ``sha2-nistp256``,
        ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521``, or ``ssh-ed25519``.
        Can also specify an algorithm: ``rsa``, ``ec``, or ``ed25519``.

    key_bits
        The desired key bits for the generated SSH CA key.
        Only used for variable length keys (e.g. ``ssh-rsa``)
        or when ``ec`` was specified as ``key_type``, in which case this
        selects the NIST P-curve: ``256``, ``384``, ``521``.
        0 (default) will select 4096 bits for RSA or NIST P-256 for EC.

    ttl
        Request a specific time to live for the certificate, limited by the
        role's TTL. If unspecified, will default to the role's TTL or system
        values.

    valid_principals
        List of usernames/hostnames the certificate should be signed for.

    cert_type
        The type of certificate to issue, either ``user`` or ``host``. Defaults
        to ``user``.

    key_id
        The key ID the created certificate should have. If unspecified, the display
        name of the creating token will be used.

    critical_options
        A map of critical options the certificate should carry.

    extensions
        A map of extensions the certificate should carry.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/issue/{name}"
    payload = {"key_type": key_type, "cert_type": cert_type, "key_bits": key_bits}

    if ttl is not None:
        payload["ttl"] = ttl
    if key_id is not None:
        payload["key_id"] = key_id

    if valid_principals is not None:
        if isinstance(valid_principals, list):
            valid_principals = ",".join(valid_principals)
        payload["valid_principals"] = valid_principals

    for param, val in [
        ("critical_options", critical_options),
        ("extensions", extensions),
    ]:
        if val is not None:
            payload[param] = {
                k: salt.utils.json.dumps(v) if isinstance(v, (dict, list)) else v
                for k, v in val.items()
            }

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def _get_file_or_data(data):
    """
    Try to load a string as a file, otherwise return the string
    """
    try:
        # Check if the data can be interpreted as a Path at all
        Path(data)
    except TypeError:
        return data
    try:
        if __salt__["file.file_exists"](data):
            return __salt__["file.read"](data)
    except (OSError, TypeError, ValueError):
        pass
    return data
