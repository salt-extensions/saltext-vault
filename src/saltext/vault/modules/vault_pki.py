"""
Manage the Vault (or OpenBao) PKI secret engine, request X.509 certificates.

.. versionadded:: 1.1.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
import typing
from datetime import datetime
from datetime import timezone

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault
from saltext.vault.utils.vault import helpers as hlp

try:
    from salt.utils import x509 as x509util

    from saltext.vault.utils.vault import pki

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAS_CRYPTOGRAPHY = False


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

__virtualname__ = "vault_pki"


def __virtual__():
    return __virtualname__


VALID_CSR_ARGS = (
    "C",
    "ST",
    "L",
    "STREET",
    "O",
    "OU",
    "CN",
    "MAIL",
    "SN",
    "GN",
    "UID",
    "authorityKeyIdentifier",
    "basicConstraints",
    "certificatePolicies",
    "extendedKeyUsage",
    "inhibitAnyPolicy",
    "keyUsage",
    "nameConstraints",
    "noCheck",
    "policyConstraints",
    "subjectKeyIdentifier",
    "tlsfeature",
)


def list_roles(mount="pki"):
    """
    List configured PKI roles.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-roles>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles" {
            capabilities = ["list"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.list_roles

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/roles"
    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_role(name, mount="pki"):
    """
    Get configuration of specific PKI role.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-role>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_role my_role

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/roles/{name}"
    try:
        res = vault.query("GET", endpoint, __opts__, __context__)
        return res["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write_role(
    name,
    mount="pki",
    issuer_ref=None,
    ttl=None,
    max_ttl=None,
    allow_localhost=None,
    allowed_domains=None,
    server_flag=None,
    client_flag=None,
    key_usage=None,
    no_store=None,
    require_cn=None,
    **kwargs,
):
    """
    Create or update PKI role.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#create-update-role>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["create", "update", "patch"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.write_role myrole

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    issuer_ref
        Name or ID of the issuer which should be used with this role. If not set, the default issuer is used.

    ttl
        Specifies the Time To Live value to be used for the validity period of the requested certificate,
        provided as a string duration with time suffix. Hour is the largest suffix.
        The value specified is strictly used for future validity.
        If not set, uses the system default value or the value of ``max_ttl``, whichever is shorter.

    max_ttl
        Specifies the maximum Time To Live provided as a string duration with time suffix.
        Hour is the largest suffix. If not set, defaults to the system maximum lease TTL.

    allow_localhost
        Specifies if clients can request certificates for ``localhost`` as one of the requested common names.

    allowed_domains
        Specifies the domains this role is allowed to issue certificates for.
        This is used with the ``allow_bare_domains``, ``allow_subdomains``, and ``allow_glob_domains`` options to
        determine the type of matching between these domains and the values of common name, DNS-typed SAN entries, and Email-typed SAN entries.
        When ``allow_any_name`` is used, this attribute has no effect.

    server_flag
        Specifies if certificates are flagged for server authentication use.
        See `RFC 5280 Section 4.2.1.12 <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12>`__
        for information about the Extended Key Usage field.
        If not set, defaults to true.

    client_flag
        Specifies if certificates are flagged for client authentication use.
        See `RFC 5280 Section 4.2.1.12 <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12>`__
        for information about the Extended Key Usage field.
        If not set, defaults to true.

    key_usage
        Specifies the allowed key usage constraint on issued certificates.
        If unset, defaults to ``["DigitalSignature", "KeyAgreement", "KeyEncipherment"]``

    no_store
        If set, certificates issued/signed against this role are not stored in the storage backend.

    require_cn
        If set to false, makes the common_name field optional while generating a certificate. Defaults to true.

    kwargs:
        Any other params which can be understood by the Vault API.
    """

    endpoint = f"{mount}/roles/{name}"
    method = "POST"

    if read_role(name, mount=mount) is not None:
        method = "PATCH"

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    if issuer_ref is not None:
        payload["issuer_ref"] = issuer_ref
    if ttl is not None:
        payload["ttl"] = ttl
    if max_ttl is not None:
        payload["max_ttl"] = max_ttl
    if allow_localhost is not None:
        payload["allow_localhost"] = allow_localhost
    if allowed_domains is not None:
        if not isinstance(allowed_domains, list):
            allowed_domains = [allowed_domains]
        payload["allowed_domains"] = allowed_domains
    if server_flag is not None:
        payload["server_flag"] = server_flag
    if client_flag is not None:
        payload["client_flag"] = client_flag
    if key_usage is not None:
        if not isinstance(key_usage, list):
            key_usage = [key_usage]
        payload["key_usage"] = key_usage
    if no_store is not None:
        payload["no_store"] = no_store
    if require_cn is not None:
        payload["require_cn"] = require_cn

    try:
        vault.query(method, endpoint, __opts__, __context__, payload=payload, safe_to_retry=True)
        return True
    except vault.VaultUnsupportedOperationError as err:  # pragma: no cover
        raise CommandExecutionError(
            f"Vault version too old. Please upgrade to v1.11.0+: {err}"
        ) from err
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete_role(name, mount="pki"):
    """
    Delete PKI role from Vault.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#delete-role>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["delete"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.delete_role myrole

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/roles/{name}"

    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        return True
    except vault.VaultNotFoundError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_issuers(mount="pki"):
    """
    List issuers information.

    Returns ``{ "<issuer_id>" : { "is_default": False, "issuer_name": "...", "key_id": "...", "serial_number": "...."}}``

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/issuers" {
            capabilities = ["list"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.list_issuers

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/issuers"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__, is_unauthd=True)["data"][
            "key_info"
        ]
    except vault.VaultNotFoundError:
        return {}
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_issuer(ref="default", mount="pki"):
    """
    Read an issuer's information.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-certificate>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/issuer/<name>" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_issuer

    ref
        Reference of the issuer. Can be issuer ID, issuer name or literal ``default``
        which means default issuer. Defaults to ``default``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    """
    endpoint = f"{mount}/issuer/{ref}"

    try:
        return vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultServerError as err:
        if "unable to find PKI issuer for reference" in str(err):
            return None
        if ref == "default" and "no default issuer currently configured" in str(err):
            return None
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def update_issuer(
    ref="default",
    mount="pki",
    manual_chain=None,
    usage=None,
    aia_urls=None,
    crl_endpoints=None,
    ocsp_servers=None,
    name=None,
    aia_url_templating=None,
    delta_crl_endpoints=None,
):
    """
    Update issuer's information.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#update-issuer>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/issuer/<name>" {
            capabilities = ["patch"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.update_issuer ref usage=["crl-signing"]

    ref
        Reference of the issuer. Can be issuer ID, issuer name or literal ``default``,
        referring to the default issuer. Defaults to ``default``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    manual_chain
        Chain of issuer references to build this issuer's computed CAChain field from, when non-empty.

    usage
        Allowed usages for this issuer. Valid options are:

        * ``read-only`` - to allow this issuer to be read; implict; always allowed;
        * ``issuing-certificates`` - to allow this issuer to be used for issuing other certificates;
        * ``crl-signing`` -  to allow this issuer to be used for signing CRLs.
          This is separate from the CRLSign KeyUsage on the x509 certificate, but this usage cannot be set
          unless that KeyUsage is allowed on the x509 certificate;
        * ``ocsp-signing`` -  to allow this issuer to be used for signing OCSP responses.


    aia_urls
        Specifies the URL values for the Issuing Certificate field as an array.

    crl_endpoints
        Specifies the URL values for the CRL Distribution Points field as an array.

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as an array.

    name
        .. versionadded:: 1.9.0

        Custom name for the issuer. Must be unique and not equal to ``default``.

    aia_url_templating
        .. versionadded:: 1.9.0

        Render ``aia_urls``/``crl_endpoints``/``ocsp_servers``/``delta_crl_endpoints`` as templates.
        Supported variables: `{{issuer_id}}`, ``{{cluster_path}}``, ``{{cluster_aia_path}}``

    delta_crl_endpoints
        .. versionadded:: 1.9.0

        (Requires Vault 1.20+ or OpenBao)
        Specifies the URL values for the Delta CRL Distribution Points field.
        This can be an array or a comma- separated string list.
    """
    endpoint = f"{mount}/issuer/{ref}"
    payload = {}

    if manual_chain is not None:
        payload["manual_chain"] = manual_chain

    if usage:
        payload["usage"] = usage

    if aia_urls is not None:
        payload["issuing_certificates"] = aia_urls

    if crl_endpoints is not None:
        payload["crl_distribution_points"] = crl_endpoints

    if ocsp_servers is not None:
        payload["ocsp_servers"] = ocsp_servers

    if name is not None:
        payload["issuer_name"] = name

    if aia_url_templating is not None:
        payload["enable_aia_url_templating"] = aia_url_templating

    if delta_crl_endpoints is not None:
        payload["delta_crl_distribution_points"] = delta_crl_endpoints

    try:
        vault.query(
            "PATCH",
            endpoint,
            __opts__,
            __context__,
            payload=payload,
        )
        return True
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_issuer_certificate(name="default", mount="pki", include_chain=False):
    """
    Read an issuer's certificate.
    Returns certificate(s) in PEM format

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-certificate>`__.

    Required policy: See :func:`read_issuer`

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_issuer_certificate

    name
        Name of the issuer. Can be issuer ID, issuer name or literal ``default``
        which means default issuer. Defaults to ``default``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    include_chain
        If set to true, appends the CA chain to the certificate (in case of intermediate issuer)
    """
    cert_data = read_issuer(name, mount)
    if not cert_data:
        raise CommandExecutionError("Issuer does not exist")

    if include_chain:
        return "".join(cert_data["ca_chain"])
    return cert_data["certificate"]


def get_default_issuer(mount="pki"):
    """
    Return the issuer ID of the default issuer.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers>`__.

    Required policy: See :func:`list_issuers`

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.get_default_issuer

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    all_issuers = list_issuers(mount)

    for k, v in all_issuers.items():
        if v["is_default"]:
            return k
    # In case there is no default issuer
    return None


def set_default_issuer(name, mount="pki"):
    """
    Set the default issuer.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#set-issuers-configuration>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/issuers" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.set_default_issuer myca

    name
        Name or ID of the default issuer to set.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/issuers"
    payload = {"default": name}
    try:
        vault.query("POST", endpoint, __opts__, __context__, payload=payload, safe_to_retry=True)
        return True
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def get_key_id(ref, mount="pki"):
    """
    .. versionadded:: 1.9.0

    Get the key ID of a reference, which can be a key ID or a key name. Ensures the returned key ID exists.

    Required policy:  See :func:`list_keys`

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.get_key_id foobar

    ref
        Reference to a key. Either ``key_name`` or ``key_id``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    keys = list_keys(mount=mount)
    if ref in keys:
        return ref
    for key_id, info in keys.items():
        if info.get("key_name") == ref:
            return key_id
    raise CommandExecutionError(f"No key is associated with reference '{ref}' on mount '{mount}'")


def list_keys(mount="pki"):
    """
    .. versionadded:: 1.9.0

    Get a mapping of keys provisioned in this mount to some of their properties (currently only ``key_name``).

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-keys>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys" {
            capabilities = ["list"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.list_keys

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    try:
        res = vault.query("LIST", f"{mount}/keys", __opts__, __context__)["data"]
    except vault.VaultNotFoundError:
        return {}
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    keys = res["key_info"]
    for key in res["keys"]:
        if key not in keys:  # pragma: no cover
            keys[key] = {}
    return keys


def generate_key(
    key_type="internal",
    key_name=None,
    key_algo=None,
    key_bits=None,
    managed_key_name=None,
    managed_key_id=None,
    mount="pki",
):
    """
    .. versionadded:: 1.9.0

    Generate a new private key for use in the PKI mount.
    This key can be used with :func:`generate_root` and :func:`generate_intermediate`,
    using the ``key_type=existing`` variant by passing the returned ``key_id`` as ``key_ref``.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-key>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.generate_key key_name=my_rsa_key key_bits=4096
        salt '*' vault_pki.generate_key exported key_algo=ed25519

    key_type
        Key type to generate. Valid values are:

        * ``internal``: The private key is not returned and cannot be retrieved later.
        * ``exported``: The private key is returned in the response.
        * ``kms``: Request a key from a key management system. The private key is not returned and cannot be retrieved later.

        Defaults to ``internal``.

    key_name
        Specify a name for the generated key. Optional.

    key_algo
        Key algorithm. Either ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Number of bits to use for the generated key. Valid values depend on the ``key_type``:

        * ``rsa``: 2048 (default), 3072, 4096, 8192.
        * ``ec``: 224, 256 (default), 384, 521
        * ``ed25519``: ignored

        Defaults to ``0`` (universal default).

    managed_key_name
        When ``key_type`` is ``kms``, the managed key's configured name. Either this or ``managed_key_id`` is required then.

    managed_key_id
        When ``key_type`` is ``kms``, the managed key's UUID. Either this or ``managed_key_name`` is required then.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    key_type = hlp.in_vals(("exported", "internal", "kms"), key_type=key_type)
    if key_name == "default":
        raise SaltInvocationError("key_name cannot be `default`. This is a reserved word.")

    if key_type == "kms":
        hlp.one_of(
            _reason="key_type is `kms`",
            managed_key_name=managed_key_name,
            managed_key_id=managed_key_id,
        )
    else:
        hlp.none_of(
            _reason="key_type is not `kms`",
            managed_key_name=managed_key_name,
            managed_key_id=managed_key_id,
        )

    endpoint = f"{mount}/keys/generate/{key_type}"
    payload = hlp.filter_unset(
        {
            "key_name": key_name,
            "key_type": key_algo,
            "key_bits": key_bits,
            "managed_key_name": managed_key_name,
            "managed_key_id": managed_key_id,
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def generate_root(
    common_name,
    mount="pki",
    key_type="internal",
    issuer_name=None,
    key_name=None,
    ttl=None,
    key_algo="rsa",
    key_bits=0,
    max_path_length=-1,
    key_ref=None,
    managed_key_name=None,
    managed_key_id=None,
    **kwargs,
):
    """
    Generate a new root issuer.

    Returns ``{ "certificate" : "-----BEGIN CERTIFICATE...", "issuer_id": "...", "key_id": "...", }``.
    If key_type is ``exported``, also returns the private key.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-root>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/root/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.generate_root my-root

    common_name
        Common Name to be used for the CA.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    key_type
        .. versionchanged:: 1.9.0

            This parameter used to be called ``type``.

        Key type of the root to generate. Valid values are:

        * ``existing``: Use an existing key for the generated root, specified in ``key_ref``.
        * ``internal``: The private key is not returned and cannot be retrieved later.
        * ``exported``: The private key is returned in the response.
        * ``kms``: Request a key from a key management system. The private key is not returned and cannot be retrieved later.

        Defaults to ``internal``.

    issuer_name
        Provides a name to the specified issuer. The name must be unique across all issuers and not be the reserved value ``default``.

    key_name
        When a new key is created with this request, optionally specifies the name for this. The global ref ``default`` may not be used as a name.

    ttl
        Specifies the requested Time To Live (after which the certificate expires). This cannot be larger than the engine's max (or, if not set, the system max).

    key_algo
        .. versionchanged:: 1.9.0

            This parameter used to be called ``key_type``, which now refers to key generation/exportability instead.

        Specifies the desired key algorithm, either ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Number of bits to use for the generated key. Valid values depend on the ``key_type``:

        * ``rsa``: 2048 (default), 3072, 4096, 8192.
        * ``ec``: 224, 256 (default), 384, 521
        * ``ed25519``: ignored

        Defaults to ``0`` (universal default).

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit. Defaults to ``-1``.

    managed_key_name
        When ``key_type`` is ``kms``, the managed key's configured name. Either this or ``managed_key_id`` is required then.

    managed_key_id
        When ``key_type`` is ``kms``, the managed key's UUID. Either this or ``managed_key_name`` is required then.

    kwargs
        Unknown keyword arguments are passed through. See the API method docs linked above for details.
    """
    if key_type in ("rsa", "ec", "ed25519"):
        log.warning(
            "The `key_type` parameter to this function has changed meaning. To specify a key's algorithm, use ``key_algo`` instead."
        )
        key_algo = key_type
    if "type" in kwargs:
        log.warning(
            "The `type` parameter to this function is deprecated. Use ``key_type`` instead."
        )
        key_type = kwargs.pop("type")

    key_type = hlp.in_vals(("existing", "exported", "internal", "kms"), key_type=key_type)
    if key_type == "kms":
        hlp.one_of(
            _reason="key_type is `kms`",
            managed_key_name=managed_key_name,
            managed_key_id=managed_key_id,
        )
    else:
        hlp.none_of(
            _reason="key_type is not `kms`",
            managed_key_name=managed_key_name,
            managed_key_id=managed_key_id,
        )
        if key_type == "existing":
            if key_ref is None:
                raise SaltInvocationError("key_type `existing` requires `key_ref` to be set")
        else:
            hlp.none_of(_reason="key_type is not `existing`", key_ref=key_ref)

    if issuer_name == "default":
        raise SaltInvocationError("issuer_name cannot be `default`. This is a reserved word.")

    if key_name == "default":
        raise SaltInvocationError("key_name cannot be `default`. This is a reserved word.")

    endpoint = f"{mount}/root/generate/{key_type}"

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}
    payload["common_name"] = common_name

    if issuer_name is not None:
        payload["issuer_name"] = issuer_name
    if ttl is not None:
        payload["ttl"] = ttl
    if max_path_length > -1:
        payload["max_path_length"] = max_path_length

    if key_type == "existing":
        payload["key_ref"] = key_ref
    else:
        payload["key_type"] = key_algo
        if key_name is not None:
            payload["key_name"] = key_name
        if key_bits > 0:
            payload["key_bits"] = key_bits
        if managed_key_name is not None:
            payload["managed_key_name"] = managed_key_name
        if managed_key_id is not None:
            payload["managed_key_id"] = managed_key_id

    try:
        resp = vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
        ret = {
            "certificate": resp["certificate"],
            "issuer_id": resp["issuer_id"],
            "key_id": resp["key_id"],
        }

        if key_type == "exported":
            ret["private_key"] = resp["private_key"]

        return ret
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def generate_intermediate_csr(
    key_type="internal",
    key_name=None,
    key_algo=None,
    key_bits=None,
    key_ref=None,
    managed_key_name=None,
    managed_key_id=None,
    mount="pki",
    **kwargs,
):
    """
    .. versionadded:: 1.9.0

    Generate a new CSR for signing, optionally generating a new private key.
    To create an issuer, the CSR must be signed and the resulting certificate imported.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-intermediate-csr>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/intermediate/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.generate_root my-root

    key_type
        Key type of the (future) intermediate issuer to generate. Valid values are:

        * ``existing``: Use an existing key, specified in ``key_ref``.
        * ``internal``: The private key is not returned and cannot be retrieved later.
        * ``exported``: The private key is returned in the response.
        * ``kms``: Request a key from a key management system. The private key is not returned and cannot be retrieved later.

    Defaults to ``internal``.

    kwargs
        Unknown keyword arguments are passed through. See the API method docs linked above for details.
    """
    key_type = hlp.in_vals(("existing", "exported", "internal", "kms"), key_type=key_type)
    if key_type == "kms":
        hlp.one_of(
            _reason="key_type is `kms`",
            managed_key_name=managed_key_name,
            managed_key_id=managed_key_id,
        )
    else:
        hlp.none_of(
            _reason="key_type is not `kms`",
            managed_key_name=managed_key_name,
            managed_key_id=managed_key_id,
        )
        if key_type == "existing":
            if key_ref is None:
                raise SaltInvocationError("key_type `existing` requires `key_ref` to be set")
        else:
            hlp.none_of(_reason="key_type is not `existing`", key_ref=key_ref)
    if key_type in ("existing", "kms"):
        hlp.none_of(
            _reason="key_type is `existing` or `kms`",
            key_algo=key_algo,
            key_bits=key_bits,
        )
    if key_name == "default":
        raise SaltInvocationError("key_name cannot be `default`. This is a reserved word.")

    endpoint = f"{mount}/intermediate/generate/{key_type}"
    payload = hlp.filter_unset(
        {
            **kwargs,
            "key_name": key_name,
            "key_type": key_algo,
            "key_bits": key_bits,
            "key_ref": key_ref,
            "managed_key_name": managed_key_name,
            "managed_key_id": managed_key_id,
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def generate_intermediate(
    key_ref,
    common_name,
    max_path_length=0,
    mount="pki",
    **kwargs,
):
    """
    .. versionadded:: 1.9.0

    Generate an intermediate CA from an existing key by signing it
    via :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`.

    Required policy: see :func:`generate_intermediate_csr` and :func:`import_intermediate`

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.generate_intermediate my-existing-named-key "My Intermediate CA"

    key_ref
        Reference to an existing private key on this ``mount``, either ``key_name`` or ``key_id``.

    common_name
        Subject ``CN``. Required.

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit, unless the issuer certificate has a maximum path length,
        in which case it means one less than the issuer's pathlen.
        Defaults to ``0``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    kwargs
        Unknown keyword arguments are passed to :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`.
        See there for details.

        The following arguments are enforced by this function:

        * ``CN``
        * ``basicConstraints``
        * ``csr``
        * ``format``
        * ``private_key`` (empty)
        * ``public_key`` (empty)
        * ``raw`` (empty)

        These receive defaults if not specified:

        * ``keyUsage``: ``[critical, cRLSign, keyCertSign]``
        * ``subjectKeyIdentifier``: ``hash``
        * ``authorityKeyIdentifier``: ``keyid:always,issuer``
    """
    csr = generate_intermediate_csr("existing", key_ref=key_ref, mount=mount)  # source for pubkey
    basic_constraints = {"critical": True, "ca": True}
    if max_path_length >= 0:
        basic_constraints["pathlen"] = max_path_length
    kwargs["basicConstraints"] = basic_constraints
    kwargs["CN"] = common_name
    kwargs["csr"] = csr["csr"]
    kwargs["format"] = "pem"
    kwargs.pop("path", None)
    kwargs.pop("private_key", None)
    kwargs.pop("public_key", None)
    kwargs.setdefault("keyUsage", ["critical", "cRLSign", "keyCertSign"])
    kwargs.setdefault("subjectKeyIdentifier", "hash")
    kwargs.setdefault("authorityKeyIdentifier", "keyid:always,issuer")
    cert = __salt__["x509.create_certificate"](**kwargs)
    return import_issuer_intermediate(cert, mount=mount)


def delete_key(ref, mount="pki"):
    """
    Delete a private key from Vault.
    There must be no issuers depending on the key for this to succeed.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#delete-key>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/key/<ref>" {
            capabilities = ["delete"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.delete_key ref

    ref
        Reference to the key, either ``key_name`` or ``key_id``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/key/{ref}"
    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        return True
    # Don't need to catch VaultNotFoundError, it's not thrown for missing key
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete_issuer(ref, mount="pki", include_key=False):
    """
    Delete issuer from Vault.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#delete-issuer>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/issuer/<ref>" {
            capabilities = ["delete"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.delete_issuer ref

    ref
        Reference to the issuer, either ``issuer_name`` or ``issuer_id``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    include_key
        If set to true, also deletes the private key if imported.
        Defaults to false, i.e. the private key is preserved.
    """

    endpoint = f"{mount}/issuer/{ref}"
    key_id = None

    if include_key:
        issuer_info = read_issuer(ref, mount=mount)
        if issuer_info:
            key_id = issuer_info["key_id"]

    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        if key_id:
            delete_key(key_id, mount=mount)
        return True
    # Don't need to catch VaultNotFoundError, it's not thrown for missing issuer
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def import_issuer_intermediate(cert, chain=None, mount="pki"):
    """
    .. versionadded:: 1.9.0

    Import a CA certificate issued for an existing key on this mount.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#import-ca-certificates-and-keys>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/intermediate/set-signed" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.import_issuer_intermediate /etc/tls/my_intermediate_cert.pem

    cert
        Certificate to import. Any input accepted by the :py:mod:`x509_v2 modules <salt.modules.x509_v2>` is accepted.
        Included CA chain is respected when ``chain`` is not specified.

    chain
        CA chain for the certificate. Defaults to the chain in ``cert``, if present.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    if not HAS_CRYPTOGRAPHY:  # pragma: no cover
        raise CommandExecutionError(
            "Missing `cryptography` library, which is required for this operation"
        )
    endpoint = f"{mount}/intermediate/set-signed"
    if not chain:
        cert, chain = x509util.load_cert(cert, load_chain=True)
        # Ensure this works in the wrapper
        cert = x509util.to_pem(cert).decode()
        chain = [x509util.to_pem(chain_cert).decode() for chain_cert in chain]
    elif not isinstance(chain, list):
        chain = [chain]
    payload = {"certificate": _x509v2("encode_certificate", cert, append_certs=chain)}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def import_issuer(cert, chain=None, private_key=None, private_key_passphrase=None, mount="pki"):
    """
    .. versionadded:: 1.9.0

    Import a CA certificate and (optionally) corresponding private key.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#import-ca-certificates-and-keys>`__.

    Required policy:

    .. code-block:: vaultpolicy

        # without private_key
        path "<mount>/issuer/import/cert" {
            capabilities = ["create", "update"]
        }

        # with private_key
        path "<mount>/issuer/import/bundle" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.import_issuer /etc/tls/my_intermediate_cert.pem
        salt '*' vault_pki.import_issuer /etc/tls/my_intermediate_cert.pem private_key=/etc/tls/my_intermediate.key

    cert
        Certificate to import. Any input accepted by the :py:mod:`x509_v2 modules <salt.modules.x509_v2>` is accepted.
        Included CA chain is respected when ``chain`` is not specified.

    chain
        CA chain for the certificate. Defaults to the chain in ``cert``, if present.

    private_key
        Import corresponding private key for ``cert``. Optional.

    private_key_passphrase
        When ``private_key`` is specified and encrypted, the passphrase to decrypt it.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/issuers/import/"
    if not chain:
        cert, chain = x509util.load_cert(cert, load_chain=True)
        # Ensure this works in the wrapper
        cert = x509util.to_pem(cert).decode()
        chain = [x509util.to_pem(chain_cert).decode() for chain_cert in chain]
    payload = {"pem_bundle": _x509v2("encode_certificate", cert, append_certs=chain)}
    if private_key:
        endpoint += "bundle"
        payload["pem_bundle"] += "\n" + _x509v2(
            "encode_private_key", private_key, private_key_passphrase=private_key_passphrase
        )
    else:
        endpoint += "cert"
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_issuer_crl(ref="default", mount="pki", delta=False):
    """
    Get issuer CRL.

    .. note::
        If CA cannot sign CRLs, returns None.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-crl>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/issuer/<ref>" {
            capabilities = ["read"]
        }

        path "<mount>/issuer/<ref>/crl" {
            capabilities = ["read"]
        }

        path "<mount>/issuer/<ref>/crl/delta" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_issuer_crl ref

    ref
        Reference to the issuer, either ``issuer_name`` or ``issuer_id``.
        Defaults to ``default``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    delta
        If set to true, returns delta CRL instead of complete one.
    """
    # Check if issuer can sign CRLs at all. If not,
    # there is no point to check for CRL as this throws error
    try:
        issuer = vault.query(
            "GET", f"{mount}/issuer/{ref}", __opts__, __context__, is_unauthd=False
        )["data"]
    except vault.VaultServerError as err:
        if "unable to find PKI issuer" in str(err):
            return None
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    if "crl-signing" not in issuer["usage"].split(","):
        return None

    endpoint = f"{mount}/issuer/{ref}/crl"
    if delta:
        endpoint = endpoint + "/delta"

    try:
        return vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)["data"]["crl"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_revoked_certificates(mount="pki"):
    """
    List revoked certificates serial numbers

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-revoked-certificates>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/certs/revoked" {
            capabilities = ["list"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.list_revoked_certificates

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/certs/revoked"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_certificates(mount="pki"):
    """
    List issued certificates serial numbers

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/certs" {
            capabilities = ["list"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.list_certificates

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/certs"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_certificate(serial, mount="pki"):
    """
    Read issued certificate.
    Returns certificate in PEM format

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/cert/<serial>" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_certificate 7e:85:c5:d1:85:94:9a:46:08:b5:1b:9c:22:cb:35:e5:ea:f3:56:3f

    serial
        Specifies the serial of the key to read. Valid values are:

        * ``<serial>`` for the certificate with the given serial number, in hyphen-separated or colon-separated hexadecimal.
        * ``ca`` for the default issuer's CA certificate
        * ``crl`` for the default issuer's CRL
        * ``ca_chain`` for the default issuer's CA trust chain.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/cert/{serial}"

    try:
        return vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)["data"][
            "certificate"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_certificate_full(serial, mount="pki"):
    """
    .. versionadded:: 1.7.0

    Get full certificate information as a dictionary, including the certificate (`certificate`)
    and its CA chain certificates (`ca_chain`, a list of strings) in PEM format.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/cert/<serial>" {
            capabilities = ["read"]
        }

        path "<mount>/issuer/<name>" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_certificate_full 7e:85:c5:d1:85:94:9a:46:08:b5:1b:9c:22:cb:35:e5:ea:f3:56:3f

    serial
        Specifies the serial of the certificate to read. Valid values are:

        * ``<serial>`` for the certificate with the given serial number, in hyphen-separated or colon-separated hexadecimal.
        * ``ca`` for the default issuer's CA certificate
        * ``crl`` for the default issuer's CRL
        * ``ca_chain`` for the default issuer's CA trust chain.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/cert/{serial}"

    try:
        data = vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    # Ensure trailing newline so callers can concatenate certificate
    # and ca_chain entries without corrupting PEM boundaries.
    if not data["certificate"].endswith("\n"):
        data["certificate"] += "\n"

    if serial == "ca_chain":
        return data

    # Vault may omit issuer_id and the immediate issuer cert from ca_chain.
    # Resolve the signing issuer and rebuild a complete chain.
    if serial in ("ca", "crl"):
        # These special values always reference the default issuer
        issuer_ref = "default"
    else:
        # Prefer explicit issuer_id, which is only set for revoked certificates.
        # Otherwise, iterate over all issuers and find the most fitting one.
        # Newer Vault versions include authority_key_id in the response, OpenBao does not.
        issuer_ref = data.get("issuer_id") or _find_signing_issuer(
            data["certificate"], authority_key_id=data.get("authority_key_id"), mount=mount
        )
    # Do not fall back to default issuer, it has been checked already.
    if not issuer_ref:
        raise CommandExecutionError("Failed to determine cert issuer")
    issuer_data = read_issuer(ref=issuer_ref, mount=mount)
    if not issuer_data:
        raise CommandExecutionError(f"Failed to lookup issuer `{issuer_ref}`")
    chain = issuer_data["ca_chain"]
    issuer_cert = issuer_data["certificate"]
    if issuer_cert not in chain:
        chain.insert(0, issuer_cert)
    data["ca_chain"] = chain

    return data


def _find_signing_issuer(leaf_pem, authority_key_id=None, mount="pki"):
    """
    Find the configured issuer whose certificate SubjectKeyIdentifier matches the
    certificate's AuthorityKeyIdentifier. Returns the matching ``issuer_id`` or ``None``.
    """
    if not HAS_CRYPTOGRAPHY:  # pragma: no cover
        return None
    try:
        leaf = x509util.load_cert(leaf_pem)
    except (SaltInvocationError, CommandExecutionError):
        return None
    if not authority_key_id:
        try:
            authority_key_id = leaf.extensions.get_extension_for_class(
                x509util.cx509.AuthorityKeyIdentifier
            ).value.key_identifier
        except x509util.cx509.ExtensionNotFound:
            return None
    if not isinstance(authority_key_id, bytes):
        authority_key_id = bytes.fromhex(authority_key_id.replace(":", ""))
    try:
        issuers = list_issuers(mount=mount)
    except CommandExecutionError as err:
        log.error(str(err), exc_info_on_loglevel=logging.DEBUG)
        return None
    candidates = []
    now = datetime.now(tz=timezone.utc)
    for issuer_id in issuers:
        try:
            issuer_data = read_issuer(ref=issuer_id, mount=mount)
        except CommandExecutionError:
            continue
        if not issuer_data or "certificate" not in issuer_data:
            continue
        try:
            issuer_cert = x509util.load_cert(issuer_data["certificate"])
        except (SaltInvocationError, CommandExecutionError):
            continue
        try:
            issuer_ski = issuer_cert.extensions.get_extension_for_class(
                x509util.cx509.SubjectKeyIdentifier
            ).value.key_identifier
        except x509util.cx509.ExtensionNotFound:
            continue
        if issuer_ski != authority_key_id:
            continue
        try:
            leaf.verify_directly_issued_by(issuer_cert)  # requires cryptography >=40
        except (ValueError, TypeError, x509util.InvalidSignature):
            continue
        candidates.append((issuer_id, issuer_data, issuer_cert))

    for predicate in (
        lambda c: not c[1].get("revoked"),
        lambda c: c[2].not_valid_after_utc > now >= c[2].not_valid_before_utc,
    ):
        filtered = [c for c in candidates if predicate(c)]
        if filtered:
            candidates = filtered
    if len(candidates) > 1:
        default = read_issuer("default", mount=mount)
        if default:
            for cand in candidates:
                if cand[0] == default["issuer_id"]:
                    return cand[0]
    if candidates:
        return candidates[0][0]
    return None


def issue_certificate(
    role_name,
    common_name,
    mount="pki",
    issuer_ref=None,
    alt_names=None,
    ttl=None,
    format="pem",  # pylint: disable=redefined-builtin
    exclude_cn_from_sans=False,
    **kwargs,
):
    """
    Generate and issue a new certificate and private key.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate-and-key>`__.

    Required policy:

    .. code-block:: vaultpolicy

        # When not specifying issuer_ref
        path "<mount>/issue/<role_name>" {
            capabilities = ["create", "update"]
        }

        # When specifying issuer_ref
        path "<mount>/issuer/<issuer_ref>/issue/<role_name>" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.issue_certificate myrole common_name="www.example.com"

    role_name
        Name of the role to be used for issuing the certificate.

    common_name
        Common name to be set for the certificate.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    issuer_ref
        Specify an explicit issuer instead of taking it from the role definition.
        Can be issuer_name or issuer_id.

    alt_names
        Any alternative names to be added to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists(``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type>:<value>"]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

    ttl
        Specifies the requested Time To Live (after which the certificate expires).
        This cannot be larger than the engine's max (or, if not set, the system max).

    format
        Can be either ``pem`` or ``der``. Defaults to ``pem``.

    exclude_cn_from_sans
        If set to true, the Common Name is not part of the SANs.

    kwargs
        Any additional parameter accepted by the Vault API.
    """
    endpoint = f"{mount}/issue/{role_name}"
    if issuer_ref is not None:
        endpoint = f"{mount}/issuer/{issuer_ref}/issue/{role_name}"

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}
    payload["common_name"] = common_name

    if ttl is not None:
        payload["ttl"] = ttl

    payload["format"] = format
    payload["exclude_cn_from_sans"] = exclude_cn_from_sans

    if alt_names is not None:
        if not HAS_CRYPTOGRAPHY:  # pragma: no cover
            raise CommandExecutionError(
                "Missing `cryptography` library, which is required for this operation"
            )
        dns_sans, ip_sans, uri_sans, other_sans = pki.split_sans(pki.norm_sans(alt_names))
        payload["alt_names"] = ",".join(dns_sans)
        payload["ip_sans"] = ",".join(ip_sans)
        payload["uri_sans"] = ",".join(uri_sans)
        payload["other_sans"] = ",".join(other_sans)

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def sign_certificate(
    role_name,
    common_name,
    mount="pki",
    csr=None,
    private_key=None,
    private_key_passphrase=None,
    digest="sha256",
    issuer_ref=None,
    alt_names=None,
    ttl=None,
    sign_verbatim=False,
    encoding="pem",
    exclude_cn_from_sans=False,
    **kwargs,
):
    """
    Issue a new certificate from an existing private key or CSR.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate>`__.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-verbatim>`__

    Required policy:

    .. code-block:: vaultpolicy

        # When sign_verbatim is false and not specifying issuer_ref
        path "<mount>/sign/<role_name>" {
            capabilities = ["create", "update"]
        }

        # When sign_verbatim is false and specifying issuer_ref
        path "<mount>/issuer/<issuer_ref>/sign/<role_name>" {
            capabilities = ["create", "update"]
        }

        # When sign_verbatim is true and not specifying issuer_ref
        path "<mount>/sign-verbatim/<role_name>" {
            capabilities = ["create", "update"]
        }

        # When sign_verbatim is true and specifying issuer_ref
        path "<mount>/issuer/<issuer_ref>/sign-verbatim/<role_name>" {
            capabilities = ["create", "update"]
        }

        # When passing `private_key` and including otherName SANs
        path "<mount>/roles/<role_name>" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.sign_certificate myrole common_name="www.example.com" private_key=/private/key/path.key
        salt '*' vault_pki.sign_certificate myrole common_name="www.example.com" csr=/csr/path.csr

    role_name
        Name of the role to be used for issuing the certificate.

    common_name
        Common name to be set for the certificate.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    csr
        Pass the CSR which should be used for issuing the certificate.
        Either ``csr`` or ``private_key`` parameter can be set, not both.

    private_key
        Private key for which certificate should be issued. Can be text or path.
        Either ``csr`` or ``private_key`` parameter can be set, not both.

        .. note::
            This parameter requires the :py:mod:`x509_v2 execution module <salt.modules.x509_v2>` to be available.

    private_key_passphrase
        Passphrase for the ``private_key``, if encrypted. Not used in case of ``csr``.

    digest
        Digest to be used for generating the CSR. Not used in case of ``private_key``. Defaults to ``sha256``

    issuer_ref
        Specify an explicit issuer instead of taking it from the role definition.
        Can be issuer_name or issuer_id.

    alt_names
        Any alternative names to be added to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists(``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type>:<value>"]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

        .. note::
            As of writing this, otherName SANs require very recent releases of the
            :py:func:`x509_v2 module <salt.modules.x509_v2.create_csr>`, which is used to generate
            a CSR when ``csr`` is not specified. If you need to make this work, in the affected role,
            set ``use_csr_sans`` to ``false``, which circumvents this issue.

    ttl
        Specifies the requested Time To Live (after which the certificate be expire).
        This cannot be larger than the engine's max (or, if not set, the system max).

    sign_verbatim
        If set to true, the resulting certificate follows the CSR exactly.
        Otherwise, only ``CN`` can be set for the subject, any other subject parameter (like ``O``) is ignored.

        .. warning::
            This option is using a potentially dangerous endpoint. Be careful when using that option, as roles
            are not restricting what can be issued anymore.

    encoding
        Can be either ``pem`` or ``der``. Defaults to ``pem``.

    exclude_cn_from_sans
        If set to true, the Common Name is not part of the SANs.

    kwargs
        Any additional parameter accepted by the Vault API or the
        :py:func:`x509_v2 module <salt.modules.x509_v2.create_csr>`
    """
    hlp.one_of(csr=csr, private_key=private_key)

    sign = "sign-verbatim" if sign_verbatim else "sign"
    endpoint = f"{mount}/{sign}/{role_name}"
    if issuer_ref is not None:
        endpoint = f"{mount}/issuer/{issuer_ref}/{sign}/{role_name}"
    csr_args, extra_args = _split_csr_kwargs(kwargs)

    payload = {k: v for k, v in extra_args.items() if not k.startswith("_")}
    payload["common_name"] = common_name
    if ttl is not None:
        payload["ttl"] = ttl
    payload["format"] = encoding
    payload["exclude_cn_from_sans"] = exclude_cn_from_sans

    norm_sans = None
    if alt_names is not None:
        if not HAS_CRYPTOGRAPHY:  # pragma: no cover
            raise CommandExecutionError(
                "Missing `cryptography` library, which is required for this operation"
            )
        norm_sans = pki.norm_sans(alt_names)
        dns_sans, ip_sans, uri_sans, other_sans = pki.split_sans(norm_sans)
        payload["alt_names"] = ",".join(dns_sans)
        payload["ip_sans"] = ",".join(ip_sans)
        payload["uri_sans"] = ",".join(uri_sans)
        payload["other_sans"] = ",".join(other_sans)

    # In case private_key is passed, we're going to build a CSR in place.
    if private_key is not None:
        if norm_sans:
            csr_args["subjectAltName"] = [
                f"{k}:{vv}" if k.upper() in pki.SUPPORTED_SAN_TYPES else f"otherName:{k};UTF8:{vv}"
                for k, v in norm_sans.items()
                for vv in v
            ]
        csr_args["CN"] = common_name
        try:
            csr = _x509v2(
                "create_csr",
                private_key=private_key,
                private_key_passphrase=private_key_passphrase,
                digest=digest,
                **csr_args,
            )
        except SaltInvocationError as err:
            if not norm_sans or "otherName is currently not implemented" not in str(err):
                raise
            # otherName SAN support requires Salt 3006.28/3008.3 (likely, if merged forward in time)
            try:
                role = read_role(role_name, mount=mount)
            except CommandExecutionError as err2:
                raise CommandExecutionError(
                    "Cannot include otherName SANs when `private_key` is passed and the role "
                    "has `use_csr_sans` set to true. Tried checking role for `use_csr_sans` "
                    "but access was denied. Either permit access and ensure `use_csr_sans` "
                    "is disabled, remove the otherName SANs or pass `csr` instead of `private_key`."
                ) from err2
            if role is None:
                raise CommandExecutionError(
                    f"Role '{role_name}' on mount '{mount}' does not exist"
                ) from err
            if role.get("use_csr_sans", True):
                raise CommandExecutionError(
                    "Cannot include otherName SANs when `private_key` is passed and the role "
                    "has `use_csr_sans` set to true. Either set it to false, upgrade Salt, "
                    "remove the otherName SANs or pass `csr` instead of `private_key`."
                ) from err
            csr_args.pop("subjectAltName")
            csr = __salt__["x509.create_csr"](
                private_key=private_key,
                private_key_passphrase=private_key_passphrase,
                digest=digest,
                **csr_args,
            )

    payload["csr"] = csr

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def revoke_certificate(
    serial=None, certificate=None, private_key=None, private_key_passphrase=None, mount="pki"
):
    """
    Revoke an issued certificate.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#revoke-certificate>`__.

    Required policy:

    .. code-block:: vaultpolicy

        # when `private_key` is unspecified
        path "<mount>/revoke" {
            capabilities = ["create", "update"]
        }

        # when `private_key` is passed
        path "<mount>/revoke-with-key" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.revoke_certificate 7e:85:c5:d1:85:94:9a:46:08:b5:1b:9c:22:cb:35:e5:ea:f3:56:3f
        salt '*' vault_pki.revoke_certificate certificate=/etc/tls/my_cert.pem
        salt '*' vault_pki.revoke_certificate certificate=/etc/tls/my_cert.pem private_key=/etc/tls/my_key.pem

    serial
        Specifies the serial of the certificate to revoke. Either ``serial`` or ``certificate`` must be specified.

    certificate
        Specifies the certificate (PEM or path) to revoke. Either ``serial`` or ``certificate`` must be specified.

        .. note::
            This parameter requires the :py:mod:`x509_v2 execution module <salt.modules.x509_v2>` to be available.

    private_key
        .. versionadded:: 1.9.0

        Private key corresponding to the certificate issued by Vault that is attempted to be revoked.
        Optional. When this is passed, a different, less trusted API endpoint is used.

    private_key_passphrase
        .. versionadded:: 1.9.0

        Passphrase for ``private_key``, if specified and encrypted. Optional.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/revoke"
    payload = {}

    hlp.one_of(serial=serial, certificate=certificate)
    if private_key:
        endpoint += "-with-key"

    try:
        if certificate is not None:
            payload["certificate"] = _x509v2("encode_certificate", certificate)
        elif serial is not None:
            if isinstance(serial, int):
                serial = hlp.dec2hex(serial)
            payload["serial_number"] = serial
        else:  # pragma: no cover
            raise RuntimeError("This path should not have been hit")

        if private_key:
            payload["private_key"] = _x509v2(
                "encode_private_key", private_key, private_key_passphrase=private_key_passphrase
            )

        vault.query("POST", endpoint, __opts__, __context__, payload=payload, safe_to_retry=True)
        return True
    except vault.VaultInvocationError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_urls(mount="pki"):
    """
    Fetch the URLs to be encoded in generated certificates.
    No URL configuration is returned until the configuration is set.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-urls>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/urls" {
            capabilities = ["read"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.read_urls

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/urls"

    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write_urls(
    issuing_certificates=None,
    crl_endpoints=None,
    delta_crl_endpoints=None,
    ocsp_servers=None,
    aia_url_templating=None,
    mount="pki",
):
    """
    .. versionadded:: 1.9.0

    Set issuing certificate endpoints, CRL distribution points, and OCSP server
    endpoints that will be encoded into issued certificates. This behaves
    as PATCH. To unset a value, set it to an empty string.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#set-urls>`_.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/urls" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.set_urls ocsp_servers=ocsp.my.ca

    issuing_certificates
        Specifies the URL values for the Issuing Certificate field as a list.
        (see RFC 5280 Section 4.2.2.1 for details)

    crl_endpoints
        Specifies the URL values for the CRL Distribution Points field as a list.
        (see RFC 5280 Section 4.2.1.13 for details)

    delta_crl_endpoints
        (Requires Vault 1.20+ or OpenBao)
        Specifies the URL values for the Delta CRL Distribution Points field.
        (see RFC 5280 Section 4.2.1.15 for details)

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as a list.
        (see RFC 5280 Section 4.2.2.1 for details)

    aia_url_templating
        Render ``issuing_certificates``/``crl_endpoints``/``ocsp_servers``/``delta_crl_endpoints`` as templates.
        Supported variables: `{{issuer_id}}`, ``{{cluster_path}}``, ``{{cluster_aia_path}}``

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/urls"
    payload = hlp.filter_unset(
        {
            "issuing_certificates": issuing_certificates,
            "crl_distribution_points": crl_endpoints,
            "delta_crl_distribution_points": delta_crl_endpoints,
            "ocsp_servers": ocsp_servers,
            "enable_templating": aia_url_templating,
        }
    )
    if not payload:
        raise CommandExecutionError("You need to specify at least one parameter.")

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def _split_csr_kwargs(kwargs):
    csr_args = {}
    extra_args = {}
    for k, v in kwargs.items():
        if k in VALID_CSR_ARGS:
            csr_args[k] = v
        else:
            extra_args[k] = v
    return csr_args, extra_args


def _x509v2(fun, *args, **kwargs):
    try:
        func = __salt__[f"x509.{fun}"]
    except KeyError as err:  # pragma: no cover
        raise CommandExecutionError(
            f"Missing `x509.{fun}`, provided by the builtin `x509_v2` execution module"
        ) from err
    return func(*args, **kwargs)
