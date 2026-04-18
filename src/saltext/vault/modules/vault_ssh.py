"""
.. versionadded:: 1.2.0

Manage the Vault (or OpenBao) SSH secret engine, request SSH credentials
and certificates.

.. versionadded:: 1.6.0
    You can specify this module as the ``backend`` parameter to the ``ssh_pki.certificate_managed``
    state introduced in Salt 3008 for stateful management of Vault-issued certificates.

    See :py:func:`create_certificate <saltext.vault.modules.vault_ssh.create_certificate>` for details.

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
        Name of the SSH role.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the SSH role.

    default_user
        Default username for which a credential should be generated.
        Required.

    cidr_list
        List of CIDR blocks to which the role is applicable.
        Required, unless the role is registered as a zero-address role.

    allowed_users
        List of usernames the client can request under this role.
        By default, **any usernames are allowed** (``*``).
        The ``default_user`` is always allowed.

    exclude_cidr_list
        List of CIDR blocks not accepted by the role.

    port
        Specifies the port number for SSH connections, which is returned to
        OTP clients as an informative value. Defaults to ``22``.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the SSH role.

    default_user
        Default username for which a credential should be generated.
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
        is always allowed.

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
        If unset (default), always takes the extensions
        from ``default_extensions`` only. If set to ``*``, allows
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
        the key ID always equals the token display name.
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
        Name of the mount point the SSH secret backend is mounted at.
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
        return vault.query(
            "POST", endpoint, __opts__, __context__, payload=payload, safe_to_retry=True
        )
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
        Name of the SSH role.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the mount point the SSH secret backend is mounted at.
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
        IP address to list roles for.

    mount
        Name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/lookup"
    payload = {"ip": address}
    try:
        return vault.query(
            "POST", endpoint, __opts__, __context__, payload=payload, safe_to_retry=True
        )["data"]["roles"]
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
        Name of the mount point the SSH secret backend is mounted at.
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
        List of role names that should be marked as zero address roles.

    mount
        Name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/config/zeroaddress"
    payload = {"roles": roles}
    try:
        return vault.query(
            "POST", endpoint, __opts__, __context__, payload=payload, safe_to_retry=True
        )
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
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the role.

    address
        IP address of the host to generate credentials for.

    username
        Username on the remote host to generate credentials for.
        If empty, the default username of the role is used.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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
        Private key part of the SSH CA key pair. Can be a file
        local to the minion or a PEM-encoded string.
        If this or ``public_key`` is unspecified, generates a pair
        on the Vault server.

    public_key
        Public key part of the SSH CA key pair. Can be a file
        local to the minion or a PEM-encoded string.
        If this or ``public_key`` is unspecified, generates a pair
        on the Vault server.

    key_type
        Desired key type for the generated SSH CA key when generating
        on the Vault server. Valid: ``ssh-rsa`` (default), ``sha2-nistp256``,
        ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521``, or ``ssh-ed25519``.
        Can also specify an algorithm: ``rsa``, ``ec``, or ``ed25519``.

    key_bits
        Desired key bits for the generated SSH CA key when generating
        on the Vault server. Only used for variable length keys (e.g. ``ssh-rsa``)
        or when ``ec`` was specified as ``key_type``, in which case this
        selects the NIST P-curve: ``256``, ``384``, ``521``.
        0 (default) selects 4096 bits for RSA or NIST P-256 for EC.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the SSH role.

    public_key
        SSH public key that should be signed. Can be a file local to
        the minion or a PEM-encoded string.

    ttl
        Request a specific time to live for the certificate, limited by the
        role's TTL. If unspecified, defaults to the role's TTL or system
        values.

    valid_principals
        List of usernames/hostnames the certificate should be signed for.

    cert_type
        Type of certificate to issue, either ``user`` or ``host``. Defaults
        to ``user``.

    key_id
        Key ID the created certificate should have. If unspecified, the display
        name of the creating token is used.

    critical_options
        Map of critical options the certificate should carry.

    extensions
        Map of extensions the certificate should carry.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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
        Name of the SSH role.

    key_type
        Desired key type for the generated SSH CA key.
        Valid: ``ssh-rsa`` (default), ``sha2-nistp256``,
        ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521``, or ``ssh-ed25519``.
        Can also specify an algorithm: ``rsa``, ``ec``, or ``ed25519``.

    key_bits
        Desired key bits for the generated SSH CA key.
        Only used for variable length keys (e.g. ``ssh-rsa``)
        or when ``ec`` was specified as ``key_type``, in which case this
        selects the NIST P-curve: ``256``, ``384``, ``521``.
        0 (default) selects 4096 bits for RSA or NIST P-256 for EC.

    ttl
        Request a specific time to live for the certificate, limited by the
        role's TTL. If unspecified, defaults to the role's TTL or system
        values.

    valid_principals
        List of usernames/hostnames the certificate should be signed for.

    cert_type
        Type of certificate to issue, either ``user`` or ``host``. Defaults
        to ``user``.

    key_id
        Key ID the created certificate should have. If unspecified, the display
        name of the creating token is used.

    critical_options
        Map of critical options the certificate should carry.

    extensions
        Map of extensions the certificate should carry.

    mount
        Name of the mount point the SSH secret backend is mounted at.
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


def create_certificate(
    ca_server=None,
    signing_policy=None,
    **kwargs,
):
    """
    .. versionadded:: 1.6.0

    Create an OpenSSH certificate and return an encoded version of it.
    This functions allows this module to be specified as the ``backend`` parameter to the
    ``ssh_pki.certificate_managed`` state introduced in Salt 3008.

    .. note::
        The following parameters from ``ssh_pki.create_certificate`` are ignored
        when using this backend: ``serial_number``, ``not_before``, ``not_after``,
        ``signing_private_key``, ``signing_private_key_passphrase``, ``copypath``,
        ``path``, ``overwrite``, ``raw``.

    .. hint::
        Since this is a compatibility layer, sometimes the parameter names do not
        describe their expected value.


    State example:

    .. code-block:: yaml

       Manage host cert:
         ssh_pki.certificate_managed:
           - name: /etc/ssh/host_ed_25519_cert
           - private_key: /etc/ssh/host_ed25519_key
           - backend: vault_ssh
           - signing_policy: ssh_role_name_in_vault
           - ca_server: mount_name_of_ssh_secret_engine
           - require:
             - ssh_pki: /etc/ssh/host_ed25519_key

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.create_certificate signing_policy=ssh_role_name private_key='/etc/pki/ssh/my.key'

    Required policy:

    .. code-block:: vaultpolicy

        # To issue the certificate (this function)
        path "<ca_server>/sign/<signing_policy>" {
            capabilities = ["create", "update"]
        }

        # When the certificate exists, to check for changes.
        # This is actually required by `get_signing_policy` below.
        path "<ca_server>/roles/<signing_policy>" {
                capabilities = ["read"]
        }

    ca_server
        Name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.

    signing_policy
        Name of the SSH role to use for issuance. Required.

        .. important::
            This needs to be a role with ``key_type`` of ``ca``.

    cert_type
        Certificate type to generate. Either ``user`` or ``host``.
        Required if not clear from the Vault role definition
        (either ``allow_user_certificates`` or ``allow_host_certificates`` set).

    private_key
        Private key corresponding to the public key the certificate should
        be issued for. Either this or ``public_key`` is required.

    private_key_passphrase
        If ``private_key`` is specified and encrypted, the passphrase to decrypt it.

    public_key
        Public key the certificate should be issued for.
        Either this or ``private_key`` is required.

    critical_options
        Mapping of critical option name to option value to set on the certificate.
        If an option does not take a value, specify it as ``true``.

        If the role's ``allowed_critical_options`` is empty, allows any option to be set.
        Otherwise, only options present in ``allowed_critical_options`` are set.
        In contrast to Vault's behavior, a role's ``default_critical_options`` are still set when
        this parameter is specified. To unset a default option, specify its value as ``false``.

        .. note::
            Currently, there's no explicit Vault role parameter that forces the value of an extension.
            It's possible to set a critical option in ``default_critical_options`` and ensure it is absent
            from ``allowed_critical_options`` though.

    extensions
        Mapping of extension name to extension value to set on the certificate.
        If an extension does not take a value, specify it as ``true``.

        If the role's ``allowed_extensions`` is empty, this parameter is ignored.
        Otherwise, only options present in ``allowed_extensions`` are set.
        In contrast to Vault's behavior, a role's ``default_extensions`` are still set when
        this parameter is specified. To unset a default extension, specify its value as ``false``.

        .. note::
            Currently, there's no explicit Vault role parameter that forces the value of an extension.
            It's possible to set an extension in ``default_extensions`` and ensure it is absent
            from ``allowed_extensions`` though.

    valid_principals
        List of valid principals.

        All specified principals must be in ``allowed_users``/``allowed_domains``.
        For user certificates, defaults to a role's ``default_user``.
        For host certificates, this is required.

        .. note::
            If a role specifies ``allowed_users_template``/``allowed_domains_template``/``allowed_subdomains``,
            stateful management via ``ssh_pki.certificate_managed`` cannot silently filter invalid principals
            since the ``ssh_pki`` modules cannot render the templates. Invalid principals result in state failure then.

    all_principals
        Allow any principals. Defaults to false.

        To truly allow any principals, requires ``*`` in a role's ``valid_principals``.
        Otherwise, defaults to all valid ones.

        .. note::
            If a role specifies ``allowed_users_template``/``allowed_domains_template``/``allowed_subdomains``,
            this defaulting fails since the ``ssh_pki`` modules cannot render the templates.

    key_id
        Specify a string-valued key ID for the signed public key.
        When the certificate is used for authentication, this value is
        logged in plaintext.

        Requires ``allow_user_key_ids`` to be set in the role.
    """
    ignored_params = (
        "signing_private_key",
        "signing_private_key_passphrase",
        "serial_number",
        "not_before",
        "not_after",
        "copypath",
        "path",
        "overwrite",
        "raw",
    )
    for ignored in ignored_params:
        if kwargs.get(ignored) is not None:
            log.warning("Ignoring '%s', this cannot be set for the Vault backend", ignored)
            kwargs.pop(ignored)

    if not signing_policy:
        raise SaltInvocationError(
            "Need 'signing_policy' specified, which actually refers to a role name"
        )

    if kwargs.get("valid_principals"):
        kwargs["valid_principals"] = ",".join(kwargs["valid_principals"])
    elif kwargs.get("all_principals"):
        kwargs["valid_principals"] = "*"
    # Otherwise uses default principals if available, or fails

    if kwargs.get("private_key"):
        pubkey = __salt__["ssh_pki.get_public_key"](
            kwargs["private_key"], passphrase=kwargs.get("private_key_passphrase")
        )
    elif kwargs.get("public_key"):
        pubkey = __salt__["ssh_pki.get_public_key"](kwargs["public_key"])
    else:
        raise SaltInvocationError(
            "Need a valid public key source, either 'private_key' or 'public_key'"
        )

    critical_options = {
        k: "" if v is True else v for k, v in (kwargs.get("critical_options") or {}).items() if v
    } or None
    extensions = {
        k: "" if v is True else v for k, v in (kwargs.get("extensions") or {}).items() if v
    } or None

    return sign_key(
        signing_policy,
        pubkey,
        ttl=kwargs.get("ttl"),
        valid_principals=kwargs.get("valid_principals"),
        cert_type=kwargs.get("cert_type"),
        key_id=kwargs.get("key_id"),
        critical_options=critical_options,
        extensions=extensions,
        mount=ca_server or "ssh",
    )["signed_key"]


def get_signing_policy(signing_policy, ca_server=None):
    """
    Returns an SSH role formatted as a signing policy.
    Compatibility layer between ``ssh_pki`` and this module.
    This currently does not support all functionality Vault offers,
    e.g. dynamic principals (templates/allow_subdomains),
    so ``ssh_pki.certificate_managed`` might always
    reissue a certificate in case these options are used.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.get_signing_policy www

    Required policy:

    .. code-block:: vaultpolicy

        path "<ca_server>/roles/<signing_policy>" {
                capabilities = ["read"]
        }

    signing_policy
        Name of the SSH role to return.

    ca_server
        Name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    ca_server = ca_server or "ssh"
    role = read_role(signing_policy, mount=ca_server)
    if role["key_type"] != "ca":
        raise SaltInvocationError("The specified Vault role is not a CA role")
    policy = {"allowed_valid_principals": []}

    user_type = host_type = False

    if role.get("allow_host_certificates"):
        if role.get("allowed_domains_template") or role.get("allow_subdomains"):
            # Patterns are unsupported by the current ssh_pki modules.
            # Ensure the certificate is not always recreated.
            allowed_domains = ["*"]
            # TODO: Render basic templates.
        else:
            allowed_domains = role.get("allowed_domains", "").split(",")
        policy["allowed_valid_principals"].extend(allowed_domains)
        host_type = True

    if role.get("allow_user_certificates"):
        if role.get("allowed_users_template"):
            # Patterns are unsupported by the current ssh_pki modules.
            # Ensure the certificate is not always recreated.
            allowed_users = ["*"]
            # TODO: Render basic templates via looking up metadata
        else:
            allowed_users = role.get("allowed_users", "").split(",")
        policy["allowed_valid_principals"].extend(allowed_users)
        user_type = True

    if "*" in policy["allowed_valid_principals"]:
        policy.pop("allowed_valid_principals")
        policy["all_principals"] = True

    if user_type is not host_type:
        policy["cert_type"] = "user" if user_type else "host"

    # allowed_critical_options defaults to allowing any
    policy["allowed_critical_options"] = (role.get("allowed_critical_options") or "*").split(",")
    # allowed_extensions_options defaults to denying all
    policy["allowed_extensions"] = (role.get("allowed_extensions") or "").split(",")
    policy["default_critical_options"] = {
        k: v or True for k, v in role.get("default_critical_options", {}).items()
    }
    policy["default_extensions"] = {
        k: v or True for k, v in role.get("default_extensions", {}).items()
    }
    policy["default_valid_principals"] = (
        [role["default_user"]] if user_type and role.get("default_user") else []
    )

    if role.get("ttl"):
        policy["ttl"] = role["ttl"]
    if role.get("max_ttl"):
        policy["max_ttl"] = role["max_ttl"]

    if not role.get("allow_user_key_ids"):
        policy["key_id"] = None

    policy["signing_public_key"] = read_ca(mount=ca_server)
    return policy


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
