"""
.. _vault_pki:

Manage the Vault PKI secret engine.

.. versionadded:: 1.1.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from typing import Tuple

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault
from saltext.vault.utils.vault.pki import dec2hex

log = logging.getLogger(__name__)

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

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_roles

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/roles"
    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_role(name, mount="pki"):
    """
    Get configuration of specific PKI role.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-role>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.read_role

    name
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/roles/{name}"
    try:
        res = vault.query("GET", endpoint, __opts__, __context__)
        return res["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


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

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.write_role myrole

    name
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    issuer_ref
        Name or id of the issuer which will be used with this role. If not set, default issuer will be used.

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
        If set, certificates issued/signed against this role will not be stored in the storage backend.

    require_cn
        If set to false, makes the common_name field optional while generating a certificate. Defaults to true.

    kwargs:
        Any other params which can be understand by Vault API.

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
        vault.query(method, endpoint, __opts__, __context__, payload=payload)
        return True
    except vault.VaultUnsupportedOperationError as err:
        raise CommandExecutionError(
            f"Vault version too old. Please upgrade to v1.11.0+: {err}"
        ) from err
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def delete_role(name, mount="pki"):
    """
    Delete PKI role from Vault.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#delete-role>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.delete_role myrole

    name
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/roles/{name}"

    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        return True
    except vault.VaultNotFoundError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_issuers(mount="pki"):
    """
    List issuers information
    Returns ``{ "<issuer_id>" : { "is_default": False, "issuer_name": "...", "key_id": "...", "serial_number": "...."}}``


    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_issuers

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/issuers"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__, is_unauthd=True)["data"][
            "key_info"
        ]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_issuer(ref="default", mount="pki"):
    """
    Read an issuer's information.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-certificate>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.read_issuer

    ref
        Reference of the issuer. Can be issuer id, issuer name or literal ``default``
        which means default issuer. Defaults to ``default``.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    """
    endpoint = f"{mount}/issuer/{ref}"

    try:
        return vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def update_issuer(
    ref="default",
    mount="pki",
    manual_chain=None,
    usage=None,
    aia_urls=None,
    crl_endpoints=None,
    ocsp_servers=None,
):
    """
    Update issuer's information.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#update-issuer>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.update_issuer ref usage=["crl-signing"]

    ref
        Reference of the issuer. Can be issuer id, issuer name or literal ``default``
        which means default issuer. Defaults to ``default``.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

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
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_issuer_certificate(name="default", mount="pki", include_chain=False):
    """
    Read an issuer's certificate.
    Returns certificate(s) in PEM format

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-certificate>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.read_issuer_certificate

    name
        Name of the issuer. Can be issuer id, issuer name or literal ``default``
        which means default issuer. Defaults to ``default``.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    include_chain
        If set to true will append the CA chain to the certificate (in case of intermediate issuer)
    """
    cert_data = read_issuer(name, mount)

    if include_chain:
        return "".join(cert_data["ca_chain"])
    return cert_data["certificate"]


def get_default_issuer(mount="pki"):
    """
    Return the issuer ID of the default issuer.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.get_default_issuer

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
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

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.set_default_issuer myca

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/issuers"
    payload = {"default": name}
    try:
        vault.query("POST", endpoint, __opts__, __context__, payload=payload)
        return True
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def generate_root(
    common_name,
    mount="pki",
    type="internal",  # pylint: disable=redefined-builtin
    issuer_name=None,
    key_name=None,
    ttl=None,
    key_type="rsa",
    key_bits=0,
    max_path_length=-1,
    **kwargs,
):
    """
    Generate a new root issuer.
    Returns ``{ "certificate" : "-----BEGIN CERTIFICATE...", "issuer_id": "...", "key_id": "...", }``
    If type is ``exported`` it will also return the private key.


    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-root>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.generate_root my-root

    common_name
        The common name to be used for the CA

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    type
        Specifies the type of the root to create. If ``exported``, the private key will be returned in the response;
        if ``internal``, the private key will not be returned and cannot be retrieved later. Defaults to ``internal``.

    issuer_name
        Provides a name to the specified issuer. The name must be unique across all issuers and not be the reserved value ``default``.

    key_name
        When a new key is created with this request, optionally specifies the name for this. The global ref ``default`` may not be used as a name.

    ttl
        Specifies the requested Time To Live (after which the certificate will be expired). This cannot be larger than the engine's max (or, if not set, the system max).

    key_type
        Specifies the desired key type; must be ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Specifies the number of bits to use for the generated keys.
        Allowed values are 0 (universal default);
        with ``key_type=rsa``, allowed values are: 2048 (default), 3072, 4096 or 8192;
        with ``key_type=ec``, allowed values are: 224, 256 (default), 384, or 521;
        ignored with ``key_type=ed25519``.

    max_path_length
        Specifies the maximum path length to encode in the generated certificate. ``-1`` means no limit,
        unless the signing certificate has a maximum path length set, in which case the path length is set to one
        less than that of the signing certificate. A limit of 0 means a literal path length of zero.
    """

    if issuer_name == "default":
        raise SaltInvocationError("issuer_name cannot be `default`. This is a reserved word.")

    if key_name == "default":
        raise SaltInvocationError("key_name cannot be `default`. This is a reserved word.")

    endpoint = f"{mount}/root/generate/{type}"

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    payload["common_name"] = common_name
    payload["key_type"] = key_type

    if issuer_name is not None:
        payload["issuer_name"] = issuer_name
    if key_name is not None:
        payload["key_name"] = key_name
    if ttl is not None:
        payload["ttl"] = ttl

    if key_bits > 0:
        payload["key_bits"] = key_bits

    if max_path_length > -1:
        payload["max_path_length"] = max_path_length

    try:
        resp = vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
        ret = {
            "certificate": resp["certificate"],
            "issuer_id": resp["issuer_id"],
            "key_id": resp["key_id"],
        }

        if type == "exported":
            ret["private_key"] = resp["private_key"]

        return ret
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def delete_key(ref, mount="pki"):
    """
    Delete private key from Vault.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#delete-key>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.delete_key ref

    ref
        Ref of the key. Could be name or key_id.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    endpoint = f"{mount}/key/{ref}"
    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        return True
    except vault.VaultNotFoundError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def delete_issuer(ref, mount="pki", include_key=False):
    """
    Delete issuer from Vault.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#delete-issuer>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.delete_issuer ref

    ref
        Ref of the issuer. Could be name or issuer_id.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    include_key
        If set to true will also delete the private key if imported.
        Defaults to false, so private key will be preserved.
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
    except vault.VaultNotFoundError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_issuer_crl(ref="default", mount="pki", delta=False):
    """
    Get issuer CRL.

    .. note::
        If CA cannot sign CRLs will return None.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer-crl>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.read_issuer_crl ref

    ref
        Ref of the issuer. Could be name or issuer_id. Defaults to default issuer.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    delta
        If set to true, will return delta CRL instead of complete one.
    """
    # Check if issuer can sign CRLs at all. If not,
    # there is no point to check for CRL as this will throw error
    issuer = None
    try:
        issuer = vault.query(
            "GET", f"{mount}/issuer/{ref}", __opts__, __context__, is_unauthd=False
        )["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

    if issuer is None:
        return None

    if "crl-signing" not in issuer["usage"].split(","):
        return None

    endpoint = f"{mount}/issuer/{ref}/crl"
    if delta:
        endpoint = endpoint + "/delta"

    try:
        return vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)["data"]["crl"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_revoked_certificates(mount="pki"):
    """
    List revoked certificates serial numbers

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-revoked-certificates>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_revoked_certificates

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/certs/revoked"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_certificates(mount="pki"):
    """
    List issued certificates serial numbers

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_certificates

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/certs"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_certificate(serial, mount="pki"):
    """
    Read issued certificate.
    Returns certificate in PEM format

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate>`__.

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
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/cert/{serial}"

    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]["certificate"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


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
    Generate and issue a new certificate with private key.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate-and-key>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.issue_certificate myrole common_name="www.example.com"

    role_name
        Name of the role to be used for issuing the certificate.

    common_name
        Common name to be set for the certificate.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    issuer_ref
        Override role's issuer. Can be issuer_name or issuer_id.

    alt_names
        Any alternative names to be added to the certificate. Can be specified either as dict (``{ "<type>": "<value"}``)
        or list of SANs (``["<type>:<value>"]``).

    ttl
        Specifies the requested Time To Live (after which the certificate will be expired).
        This cannot be larger than the engine's max (or, if not set, the system max).

    format
        Can be either ``pem`` or ``der``. Defaults to ``pem``.

    exclude_cn_from_sans
        If set to true, Common name will not be part of the SANs.

    kwargs
        Any additional parameter accepted by Vault API.
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
        dns_sans, ip_sans, uri_sans, other_sans = _split_sans(alt_names)
        payload["alt_names"] = ",".join(dns_sans)
        payload["ip_sans"] = ",".join(ip_sans)
        payload["uri_sans"] = ",".join(uri_sans)
        payload["other_sans"] = ",".join(other_sans)

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


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
    Issue a new certificate from existing private key or CSR.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate>`__.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-verbatim>`__

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.issue_certificate myrole common_name="www.example.com"

    role_name
        Name of the role to be used for issuing the certificate.

    common_name
        Common name to be set for the certificate.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    csr
        Pass the CSR which will be used for issuing the certificate. Either ``csr`` or ``private_key`` parameter can be set, not both.

    private_key
        The private key for which certificate should be issued. Can be text or path.
        Either ``csr`` or ``private_key`` parameter can be set, not both.

        .. note::
            This parameter requires the :py:mod:`x509_v2 execution module <salt.modules.x509_v2>` to be available.

    private_key_passphrase
        The passphrase for the ``private_key`` if encrypted. Not used in case of ``csr``.

    digest
        Digest to be used for generating the CSR. Not used in case of ``private_key``. Defaults to ``sha256``

    issuer_ref
        Override role's issuer. Can be issuer_name or issuer_id.

    alt_names
        Any alternative names to be added to the certificate. Can be specified either as dict (``{ "<type>": "<value"}``)
        or list of SANs (``["<type>:<value>"]``).

    ttl
        Specifies the requested Time To Live (after which the certificate will be expired).
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
        If set to true, Common name will not be part of the SANs.

    kwargs
        Any additional parameter accepted by Vault API or
        `x509_v2 module <https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.x509_v2.html#salt.modules.x509_v2.create_csr>`__
    """

    if csr is None and private_key is None:
        raise SaltInvocationError("either csr or private_key must be passed.")

    if csr is not None and private_key is not None:
        raise SaltInvocationError("only one of csr or private_key must be passed, not both")

    csr_args, extra_args = _split_csr_kwargs(kwargs)

    sign = "sign-verbatim" if sign_verbatim else "sign"

    endpoint = f"{mount}/{sign}/{role_name}"
    if issuer_ref is not None:
        endpoint = f"{mount}/issuer/{issuer_ref}/{sign}/{role_name}"

    payload = {k: v for k, v in extra_args.items() if not k.startswith("_")}

    payload["common_name"] = common_name

    if ttl is not None:
        payload["ttl"] = ttl

    payload["format"] = encoding
    payload["exclude_cn_from_sans"] = exclude_cn_from_sans

    if alt_names is not None:
        dns_sans, ip_sans, uri_sans, other_sans = _split_sans(alt_names)
        payload["alt_names"] = ",".join(dns_sans)
        payload["ip_sans"] = ",".join(ip_sans)
        payload["uri_sans"] = ",".join(uri_sans)
        payload["other_sans"] = ",".join(other_sans)

    # In case private_key is passed we're going to build
    # CSR in place.
    if private_key is not None:
        if isinstance(alt_names, dict):
            alt_names = [f"{k}:{v}" for k, v in alt_names.items()]

        if alt_names:
            csr_args["subjectAltName"] = alt_names

        csr_args["CN"] = common_name

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
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def revoke_certificate(serial=None, certificate=None, mount="pki"):
    """
    Revoke issued certificate.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#revoke-certificate>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.revoke_certificate 7e:85:c5:d1:85:94:9a:46:08:b5:1b:9c:22:cb:35:e5:ea:f3:56:3f

    serial
        Specifies the serial of the certificate to revoke. Either ``serial`` or ``certificate`` must be specified.

    certificate
        Specifies the certificate (PEM or path) to revoke. Either ``serial`` or ``certificate`` must be specified.

        .. note::
            This parameter requires the :py:mod:`x509_v2 execution module <salt.modules.x509_v2>` to be available.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/revoke/"
    payload = {}

    if serial is None and certificate is None:
        raise SaltInvocationError("either serial or certificate must be passed.")

    if serial is not None and certificate is not None:
        raise SaltInvocationError("only one of serial or certificate must be passed, not both")

    try:
        if certificate is not None:
            payload["certificate"] = __salt__["x509.encode_certificate"](
                certificate, encoding="pem"
            )
        elif serial is not None:
            if isinstance(serial, int):
                serial = dec2hex(serial)
            payload["serial_number"] = serial

        vault.query("POST", endpoint, __opts__, __context__, payload=payload)
        return True
    except vault.VaultInvocationError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_urls(mount="pki"):
    """
    Fetch the URLs to be encoded in generated certificates.
    No URL configuration will be returned until the configuration is set.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#read-urls>`__.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.get_urls

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/urls"

    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def _split_sans(sans) -> Tuple[list, list, list, list]:
    dns_sans = []
    ip_sans = []
    uri_sans = []
    other_sans = []

    try:
        if isinstance(sans, list):
            sans = dict(map(lambda x: x.split(":", 1), sans))

        for k, v in sans.items():
            if k.upper() == "DNS" or k.upper() == "EMAIL":
                dns_sans.append(v)
            elif k.upper() == "IP":
                ip_sans.append(v)
            elif k.upper() == "URI":
                uri_sans.append(v)
            else:
                other_sans.append(f"{k};UTF8:{v}")
    except ValueError as err:
        raise CommandExecutionError(
            f"SAN is not in correct format. Must be in format <type>:<value>: {err}"
        ) from err

    return dns_sans, ip_sans, uri_sans, other_sans


def _split_csr_kwargs(kwargs):
    csr_args = {}
    extra_args = {}
    for k, v in kwargs.items():
        if k in VALID_CSR_ARGS:
            csr_args[k] = v
        else:
            extra_args[k] = v
    return csr_args, extra_args
