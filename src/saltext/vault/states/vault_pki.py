"""
Manage the Vault (or OpenBao) PKI secret engine and Vault-issued X.509 certificates.

.. versionadded:: 1.1.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

# pylint: disable=too-many-lines

import base64
import logging
import os
import re
import time
import typing
from collections.abc import Mapping
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault import helpers as hlp
from saltext.vault.utils.vault.helpers import timestring_map

try:
    from salt.utils import x509 as x509util

    from saltext.vault.utils.vault import pki

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAS_CRYPTOGRAPHY = False


if typing.TYPE_CHECKING:

    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltLow
    from saltext.vault.utils._types import SaltOpts
    from saltext.vault.utils._types import SaltStates

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __states__: SaltStates
    __low__: SaltLow

log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__virtualname__ = "vault_pki"

URL_EXTS_UNVERIFIED_NOTE = (
    "URL-derived certificate extensions (AIA) were not verified since "
    "the URL configuration of mount `{mount}` could not be read/rendered"
)

ROLE_ATTRS_UNVERIFIED_NOTE = (
    "Role-derived subject attributes and extensions were not verified "
    "since the role `{role_name}` on mount `{mount}` could not be read"
)


def __virtual__():
    try:
        __salt__["x509.encode_certificate"]  # pylint: disable=pointless-statement
    except KeyError:  # pragma: no cover
        return (
            False,
            "This state requires the x509_v2 execution module. "
            "x509_v2 needs to be explicitly enabled by setting `x509_v2: true` "
            "in the minion configuration value `features` until Salt 3008 (Argon).",
        )
    if not HAS_CRYPTOGRAPHY:  # pragma: no cover
        return (False, "Could not load cryptography")
    return __virtualname__


VALID_FILE_ARGS = (
    "user",
    "group",
    "mode",
    "attrs",
    "makedirs",
    "dir_mode",
    "backup",
    "create",
    "follow_symlinks",
    "check_cmd",
    "tmp_dir",
    "tmp_ext",
    "selinux",
    "file_encoding",
    "encoding_errors",
    "win_owner",
    "win_perms",
    "win_deny_perms",
    "win_inheritance",
    "win_perms_reset",
)


def certificate_managed(
    name,
    common_name=None,
    role_name=None,
    private_key=None,
    csr=None,
    mount="pki",
    ttl="720h",
    ttl_remaining="168h",
    issuer_ref=None,
    encoding="pem",
    append_ca_chain=False,
    sign_verbatim=False,
    private_key_passphrase=None,
    reissue=False,
    *,
    # Vault sign args
    alt_names=None,  # In theory sign-cert only, but the execution module syncs alt_names into subjectAltName
    exclude_cn_from_sans=False,  # sign-cert only
    not_after=None,
    serial_number=None,  # With sign-verbatim, needs to be specified in CSR
    user_ids=None,  # With sign-verbatim, needs to be specified in CSR, even though it's documented
    # Vault sign-verbatim only args
    key_usage=None,
    ext_key_usage=None,
    ext_key_usage_oids=None,
    # Args for file.managed and x509.create_csr (no CN/subjectAltName though)
    **kwargs,
):
    """
    Ensure an X.509 **leaf** certificate is present as specified.

    .. note::
        This state can use the ``sign-verbatim`` endpoint, which allows minute control of
        the certificate's subject name and most extensions (see ``sign_verbatim`` below).
        If not used, only CN is preserved from the CSR subject, any other subject name
        attributes are taken from the role instead.
        Check `this issue <https://github.com/hashicorp/vault/issues/17313>`__ for more information.

    .. versionchanged:: 1.9.0

        Now compares all certificate subject attributes and extensions, including those
        that are derived from PKI role parameters and issuer URL configuration.
        This requires read access to the role, issuer and mount default URL configuration.
        If read access to the URL configuration is denied, URL-derived extensions
        are not verified and a note is appended to the state's comment instead.
        The same graceful fallback applies to role-derived subject attributes and
        extensions when read access to the role is denied, but only if ``issuer_ref``
        is specified explicitly - otherwise, the role configuration is required
        to discover the signing issuer and the state fails, as it always has.

        Also, when ``issuer_ref`` is unspecified, now uses the generic ``<mount>/sign*``
        endpoints instead of the issuer-specific ``<mount>/issuer/<issuer_ref>/sign/<role_name>``
        with the explicit issuer_ref from the role.

    Required policy:

    .. code-block:: vaultpolicy

        # Need to read the role configuration in case of missing issuer_ref
        # and to more accurately predict changes.
        # Note: When issuer_ref is specified explicitly, failure to read
        # this does not cause reissuance, only a note.
        path "<mount>/roles/<role_name>" {
            capabilities = ["read"]
        }

        # Read mount default urls to account for cert extensions
        # if the issuer has no configured URLs.
        # Note: Failure to read this does not cause reissuance, only a note.
        path "<mount>/config/urls" {
            capabilities = ["read"]
        }

        # Read issuer for URL configuration and CA chain. issuer_ref becomes `default` if unspecified
        path "<mount>/issuer/<issuer_ref>" {
            capabilities = ["read"]
        }

        # When URLs use templating with `{{cluster_path}}`/`{{cluster_aia_path}}` variables
        # Note: Failure to read this does not cause reissuance, only a note.
        path "<mount>/config/cluster" {
            capabilities = ["read"]
        }

        # When sign_verbatim is false and not specifying issuer_ref
        path "<mount>/sign/<role_name>" {
            capabilities = ["update"]
        }

        # When sign_verbatim is false and specifying issuer_ref
        path "<mount>/issuer/<issuer_ref>/sign/<role_name>" {
            capabilities = ["update"]
        }

        # When sign_verbatim is true and neither specifying issuer_ref nor role_name
        path "<mount>/sign-verbatim" {
            capabilities = ["update"]
        }

        # When sign_verbatim is true and specifying role_name, but not issuer_ref
        path "<mount>/sign-verbatim/<role_name>" {
            capabilities = ["update"]
        }

        # When sign_verbatim is true and specifying issuer_ref, but not role_name
        path "<mount>/issuer/<issuer_ref>/sign-verbatim" {
            capabilities = ["update"]
        }

        # When sign_verbatim is true and specifying both issuer_ref and role_name
        path "<mount>/issuer/<issuer_ref>/sign-verbatim/<role_name>" {
            capabilities = ["update"]
        }

    name
        Path to the managed certificate file.

    common_name
        Subject common name (``CN``) for the certificate.
        Required, unless the role explicitly sets ``require_cn`` to false or
        ``sign_verbatim`` is true.
        Ignored (i.e. also not required) when a ``csr`` is passed that specifies
        it and the role's ``use_csr_common_name`` is true (the default value).

    role_name
        PKI role to use for issuing the certificate.
        Required, unless ``sign_verbatim`` is true.

    private_key
        Path or text of the private key to use for signing the CSR and thus
        as the private key for the certificate.
        Either this or ``csr`` is required.

    csr
        .. versionadded:: 1.9.0

        Path or text of the CSR to use for issuing the certificate.
        Either this or ``private_key`` is required.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    ttl
        Specifies the requested Time To Live (after which the certificate will be expired).
        Can be an integer, which is interpreted as seconds, or a time string such as ``1h``.
        Hour is the largest suffix. Defaults to ``720h`` or 30 days.

        .. note::

            The effective validity is capped by the role's ``max_ttl``, if a role is used.
            This is accounted for in change reports when the role is readable.

    ttl_remaining
        If an existing certificate's remaining Time To Live undercuts this period, renew it.
        Can be an integer, which is interpreted as seconds, or a time string such as ``1h``.
        Hour is the largest suffix. Defaults to ``168h`` or 7 days.

        .. note::

            Must be less than the role's ``max_ttl``, if a role is used, otherwise issued
            certificates would be immediately due for renewal. The same applies to the
            signing issuer's remaining validity, unless its ``leaf_not_after_behavior``
            is set to ``permit``.

    issuer_ref
        Override the specified role's issuer for the certificate.
        Defaults to the one specified in the role.

    encoding
        Encoding of the managed certificate file.
        Valid options are ``pem``, ``pkcs7_pem``, ``der``, ``pkcs7_der``.
        Defaults to ``pem``.

    append_ca_chain
        Whether to append the CA chain to the certificate.
        Defaults to ``false``.

        .. note::
            This appends all CA chain certificates of the selected issuer except self-signed (root) ones.

    sign_verbatim
        If set to true, the resulting certificate follows the CSR more or less exactly, including extensions.
        Otherwise, only ``CN`` can be set for the subject, any other subject parameters (like ``O``) are
        taken from the role.

        .. warning::
            This option uses a potentially dangerous endpoint. Be careful when using that option, as roles
            are not restricting what can be issued anymore.

    private_key_passphrase
        Password for the private key if encrypted.

    reissue
        Always reissue the certificate. Defaults to ``false``.

    alt_names
        Any alternative names to add to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists (``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type1>:<value1>", ...]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

        Ignored when a ``csr`` is passed and the role's ``use_csr_sans`` is true (the default value).

    exclude_cn_from_sans
        If set to true, the Common Name is not added to the SANs.
        Useful if the CN is not a hostname or email address.
        Has no effect when ``sign_verbatim`` is true.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``ttl`` is ignored. ``ttl_remaining`` is still validated, but falling below it causes
        state failure instead of a reissuance.

        .. note::

            Must not exceed the role's ``max_ttl``, if a role is specified, which enforces a hard cutoff during issuance.
            The same applies to the signing issuer's expiry, unless its ``leaf_not_after_behavior``
            is set to ``permit``.

    serial_number
        Single value for the **subject** SERIALNUMBER (OID: 2.5.4.5) name attribute (NOT the certificate's serial number!).

    user_ids
        List of User ID (``UID``) subject attributes.
        Each one is added to the generated CSR's subject Name as a distinct RDN.

    key_usage
        When ``sign_verbatim`` is true, list of key usages to encode onto the certificate if the
        CSR does not specify a ``keyUsage`` extension. For non-verbatim issuance, this parameter
        must not be specified because Vault takes it from the role.
        Valid values can be found at https://golang.org/pkg/crypto/x509/#KeyUsage - simply drop the
        ``KeyUsage`` part of the value. Values are case-insensitive. Pass an empty list to specify
        no constraints.

    ext_key_usage
        When ``sign_verbatim`` is true, list of extended key usages to encode onto the certificate if the
        CSR does not specify an ``extendedKeyUsage`` extension. For non-verbatim issuance, this parameter
        must not be specified because Vault takes it from the role.
        Valid values can be found at https://golang.org/pkg/crypto/x509/#ExtKeyUsage - simply drop the
        ``ExtKeyUsage`` part of the value. Values are case-insensitive. Pass an empty list to specify
        no constraints.

    ext_key_usage_oids
        When ``sign_verbatim`` is true, list of extended key usage oids to encode onto the certificate if the
        CSR does not specify an ``extendedKeyUsage`` extension.
        Useful for adding EKUs not supported by the Go standard library.
        For non-verbatim issuance, this parameter must not be specified because Vault takes it from the role.

    kwargs
        Most parameters for the :py:func:`file.managed <salt.states.file.managed>` state or any of the ones for
        the Vault PKI :py:func:`sign_certificate <saltext.vault.modules.vault_pki.sign_certificate>` execution module function
        are passed through.

        .. hint::

            This is a high-level state, which connects several different functions:

            * Vault API (`sign-certificate <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate>`__
              or `sign-verbatim <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-verbatim>`__, depending on
              the value of ``sign_verbatim``). Completely unknown keyword parameters end up there.
            * :py:func:`x509.create_csr <salt.modules.x509_v2.create_csr>`: Used to generate a CSR that Vault should sign.
              Any subject name attribute parameters (``O``, ``OU`` etc.) and most extension parameters
              (``certificatePolicies``, ``keyUsage``, ``extendedKeyUsage`` etc.) end up here. Note that Vault does not
              follow the CSR literally, even ``sign-verbatim`` e.g. prohibits ``basicConstraints`` with ``CA: true``.
              The ``CN`` and ``subjectAltName`` parameters are synced with ``common_name`` and ``alt_names`` respectively,
              so specifying them directly has no effect.
              Ignored when ``csr`` is defined.
            * :py:func:`file.managed <salt.states.file.managed>`: Parameters such as ``user``, ``group`` and ``mode``
              end up influencing the certificate file on disk.
              Note: ``encoding`` is a valid parameter for both this function and ``file.managed``. If you need to pass
              it to the latter, specify it as ``file_encoding`` instead.
    """

    if not sign_verbatim:
        try:
            if not role_name:
                raise SaltInvocationError("`role_name` is required when `sign_verbatim` is false")
            hlp.none_of(
                key_usage=key_usage,
                ext_key_usage=ext_key_usage,
                ext_key_usage_oids=ext_key_usage_oids,
                _reason="sign_verbatim is false",
            )
        except SaltInvocationError as err:
            return {"name": name, "result": False, "comment": str(err), "changes": {}}

    file_args, cert_args = _split_file_kwargs(
        hlp.filter_state_internal_kwargs(kwargs, ("check_cmd",))
    )
    # An empty role_name and thus role_info is allowed when signing verbatim
    role_info: dict[str, typing.Any] = {}
    role_unverified = False
    max_ttl = 0
    truncates_at = None

    def setup():
        nonlocal alt_names, issuer_ref, role_info, role_unverified
        if role_name is not None:
            try:
                role_info = __salt__["vault_pki.read_role"](role_name, mount=mount)
            except CommandExecutionError as err:
                if "PermissionDenied" not in str(err) or issuer_ref is None:
                    # Without an explicit issuer_ref, the role provides the reference
                    # for reading the issuer this state compares certificates against,
                    # hence a fallback would not be idempotent with non-default role issuers.
                    raise
                log.warning(
                    "Failed reading role '%s'. Consider allowing read access to `%s/roles/%s`. "
                    "Role-derived certificate attributes cannot be verified and the role's "
                    "`max_ttl` cannot be taken into account without it.",
                    role_name,
                    mount,
                    role_name,
                )
                role_unverified = True
            else:
                if role_info is None:
                    raise CommandExecutionError(f"Role {role_name} does not exist")

        if csr and alt_names and role_info.get("use_csr_sans", True):
            # SANs don't fall back to alt_names (we simulate that when generating a CSR on the fly).
            # This is in contrast to common_name.
            log.warning(
                "Ignoring passed `alt_names`: Received a pre-generated CSR and the role does not specify use_csr_sans=false"
            )
            alt_names = None

        if issuer_ref is None:
            issuer_ref = role_info.get("issuer_ref", "default")
        return issuer_ref

    def validate_cutoffs(issuer_info):
        nonlocal max_ttl, truncates_at
        if max_ttl := timestring_map(role_info.get("max_ttl") or 0, cast=int):
            # A max_ttl > 0 enforces a hard cutoff on the certificate lifetime.
            # Ensure that does not make this state always non-idempotent/fail.
            _validate_issuance_cutoff(
                datetime.now(tz=timezone.utc) + timedelta(seconds=max_ttl),
                "the role's `max_ttl`",
                not_after,
                timestring_map(ttl_remaining, cast=int),
            )
        if (behavior := issuer_info.get("leaf_not_after_behavior")) != "permit":
            # The signing issuer's own expiry enforces a hard cutoff during
            # issuance as well, by erroring out (default) or truncating.
            issuer_expiry = pki.not_valid_after(x509util.load_cert(issuer_info["certificate"]))
            _validate_issuance_cutoff(
                issuer_expiry,
                "the signing issuer's expiry",
                not_after,
                timestring_map(ttl_remaining, cast=int),
            )
            if behavior == "truncate":
                # Only a truncating issuer's expiry caps the effective validity,
                # otherwise exceeding requests error out during issuance instead.
                truncates_at = issuer_expiry
            elif not_after is None:
                # An explicit not_after beyond the expiry was refused above already.
                ttl_seconds = timestring_map(ttl, cast=int)
                effective_ttl = min(ttl_seconds, max_ttl) if max_ttl else ttl_seconds
                if datetime.now(tz=timezone.utc) + timedelta(seconds=effective_ttl) > issuer_expiry:
                    # Note: Without a role max_ttl, the mount's max_lease_ttl could
                    # still save the request by capping the effective validity below
                    # the issuer's expiry, but we don't have (guaranteed) access to
                    # that value. It's also smelly config, better surface it.
                    # A role's max_ttl overrides the mount's cap though,
                    # making this prediction exact when it is set.
                    return (
                        "Issuance would fail because the requested validity exceeds the "
                        f"signing issuer's expiry ({issuer_expiry.strftime(pki.TIME_FMT)}) "
                        f"and its `leaf_not_after_behavior` is set to `{behavior}`. "
                        "Reduce `ttl` or rotate the issuer"
                    )
        return None

    def check_cert(current, issuer_info, urls, ca_chain):
        ttl_seconds = timestring_map(ttl, cast=int)
        # The effective validity is capped by the role's max_ttl, if a role is used
        # (not required for sign_verbatim). Ensure we report that correctly.
        effective_ttl = min(ttl_seconds, max_ttl) if max_ttl else ttl_seconds
        if truncates_at is not None:
            # The same applies to the expiry of a signing issuer that truncates.
            effective_ttl = min(
                effective_ttl,
                int((truncates_at - datetime.now(tz=timezone.utc)).total_seconds()),
            )
        changes, unverified_url_exts, unverified_role_attrs = pki.check_cert_for_changes(
            current=current,
            issuer=issuer_info["certificate"],
            private_key=private_key,
            csr=csr,
            encoding=encoding,
            sign_verbatim=sign_verbatim,
            alt_names=alt_names,
            append_chain=ca_chain,
            common_name=common_name,
            exclude_cn_from_sans=exclude_cn_from_sans,
            expire_tolerance=ttl_remaining,
            ext_key_usage=ext_key_usage,
            ext_key_usage_oids=ext_key_usage_oids,
            key_usage=key_usage,
            not_after=not_after,
            private_key_passphrase=private_key_passphrase,
            role_info=None if role_unverified else role_info,
            serial_number=serial_number,
            ttl=effective_ttl,
            urls=urls,
            user_ids=user_ids,
            **cert_args,
        )
        notes = []
        if unverified_url_exts:
            notes.append(URL_EXTS_UNVERIFIED_NOTE.format(mount=mount))
        if unverified_role_attrs:
            notes.append(ROLE_ATTRS_UNVERIFIED_NOTE.format(role_name=role_name, mount=mount))
        return changes, notes

    def sign():
        issued_cert = __salt__["vault_pki.sign_certificate"](
            common_name=common_name,
            role_name=role_name,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            csr=csr,
            # Vault rejects requests specifying both ttl and not_after
            ttl=None if not_after else ttl,
            issuer_ref=issuer_ref,
            mount=mount,
            sign_verbatim=sign_verbatim,
            remove_roots_from_chain=False,
            alt_names=alt_names,
            exclude_cn_from_sans=exclude_cn_from_sans,
            not_after=not_after,
            serial_number=serial_number,
            user_ids=user_ids,
            key_usage=key_usage,
            ext_key_usage=ext_key_usage,
            ext_key_usage_oids=ext_key_usage_oids,
            **cert_args,
        )
        return issued_cert["certificate"]

    return _certificate_file_managed(
        name,
        private_key=private_key,
        csr=csr,
        mount=mount,
        ttl=ttl,
        ttl_remaining=ttl_remaining,
        not_after=not_after,
        encoding=encoding,
        append_ca_chain=append_ca_chain,
        file_args=file_args,
        setup=setup,
        validate_cutoffs=validate_cutoffs,
        check_cert=check_cert,
        sign=sign,
        reissue=reissue,
    )


def ca_certificate_managed(
    name,
    common_name=None,
    *,
    private_key=None,
    private_key_passphrase=None,
    csr=None,
    issuer_ref=None,
    sign_verbatim=False,
    ttl="4320h",  # 180d
    ttl_remaining="1440h",  # 60d
    encoding="pem",
    append_ca_chain=False,
    # Vault sign args
    alt_names=None,
    max_path_length=None,
    key_usage=None,
    exclude_cn_from_sans=False,
    permitted_alt_names=None,
    excluded_alt_names=None,
    ou=None,
    organization=None,
    country=None,
    locality=None,
    province=None,
    street_address=None,
    postal_code=None,
    serial_number=None,
    signature_bits=0,
    not_before_duration=30,
    not_after=None,
    mount="pki",
    # Args for file.managed and x509.create_csr (no CN/subjectAltName though)
    **kwargs,
):
    """
    .. versionadded:: 1.9.0

    Ensure an X.509 **CA** certificate is present as specified.

    Required policy:

    .. code-block:: vaultpolicy

        # Read mount default urls to account for cert extensions
        # if the issuer has no configured URLs.
        # Note: Failure to read this does not cause reissuance, only a note.
        path "<mount>/config/urls" {
            capabilities = ["read"]
        }

        # Read issuer for URL configuration and CA chain. issuer_ref becomes `default` if unspecified
        path "<mount>/issuer/<issuer_ref>" {
            capabilities = ["read"]
        }

        # When URLs use templating with `{{cluster_path}}`/`{{cluster_aia_path}}` variables
        # Note: Failure to read this does not cause reissuance, only a note.
        path "<mount>/config/cluster" {
            capabilities = ["read"]
        }

        # When issuer_ref is not specified
        path "<mount>/root/sign-intermediate" {
            capabilities = ["update"]
        }

        # When issuer_ref is specified
        path "<mount>/issuer/<issuer_ref>/sign-intermediate" {
            capabilities = ["update"]
        }

    name
        Path to the managed certificate file.

    common_name
        Subject common name (``CN``) for the certificate. Required, unless
        ``sign_verbatim`` is true.

    private_key
        Path or text of the private key to use for signing the CSR and thus
        as the private key for the certificate.
        Either this or ``csr`` is required.

    private_key_passphrase
        Password for the private key if encrypted.

    csr
        Path or text of the CSR to use for issuing the certificate.
        Either this or ``private_key`` is required.

    issuer_ref
        Specify issuer_name or issuer_id of intended issuer.
        Defaults to the mount default issuer.

    sign_verbatim
        If set to true, the resulting certificate follows the CSR more or less exactly, including
        the full subject and all extensions.

    ttl
        Specifies the requested Time To Live (after which the certificate will be expired).
        Can be an integer, which is interpreted as seconds, or a time string such as ``1h``.
        Hour is the largest suffix. Defaults to ``4320h`` or 180 days.

        .. hint::

            Translated into ``not_after``, hence not subject to the mount's ``max_lease_ttl``.

    ttl_remaining
        If an existing certificate's remaining Time To Live undercuts this period, renew it.
        Can be an integer, which is interpreted as seconds, or a time string such as ``1h``.
        Hour is the largest suffix. Defaults to ``1440h`` or 60 days.

        .. hint::

            This value should exceed the maximum validity of certificates issued
            by this CA, otherwise issuance close to its expiry can fail or yield
            certificates outliving it.

            It must also be less than the signing issuer's remaining validity
            when a Vault issuer signs this certificate, otherwise the certificate
            would be reissued during each run. This does not apply when the
            issuer's ``leaf_not_after_behavior`` is set to ``permit`` and
            ``enforce_leaf_not_after_behavior`` is passed.

    encoding
        Encoding of the managed certificate file.
        Valid options are ``pem``, ``pkcs7_pem``, ``der``, ``pkcs7_der``.
        Defaults to ``pem``.

    append_ca_chain
        Whether to append the CA chain to the certificate.
        Defaults to ``false``.

        .. note::

            This appends all CA chain certificates of the selected issuer except self-signed (root) ones.

    alt_names
        Any alternative names to add to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists (``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type1>:<value1>", ...]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

        Ignored when a ``csr`` is passed and ``sign_verbatim`` is true.

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit, unless the issuer certificate has a maximum path length,
        in which case it means one less than the issuer's pathlen.
        Defaults to ``-1``. Applies even when ``sign_verbatim`` is true:
        Vault does not allow a CSR to specify a basicConstraints extension with ``CA:true``.

    key_usage
        (Requires Vault 1.20+ or OpenBao)
        List of key usages to add to the existing set of key usages (CRLSign,CertSign).
        Per the CAB Forum requirements, Vault ignores values other than DigitalSignature.
        Ignored when a ``csr`` is passed and ``sign_verbatim`` is true.

    exclude_cn_from_sans
        If set to true, the Common Name is not added to the SANs.
        Useful if the CN is not a hostname or email address.
        Has no effect when ``sign_verbatim`` is true.

    permitted_alt_names
        List of alternative names for which certificates are allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.
        Ignored when a ``csr`` is passed and ``sign_verbatim`` is true.

        .. important::

            Types other than ``dns`` require Vault 1.19+.

    excluded_alt_names
        (Vault 1.19+ only)
        List of alternative names for which certificates are not allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.
        Ignored when a ``csr`` is passed and ``sign_verbatim`` is true.

    Subject DN fields
        Most of these can be single strings or lists of strings (for multiple values).
        Ignored when ``sign_verbatim`` is true.

        * ou
        * organization
        * country
        * locality
        * province
        * street_address
        * postal_code
        * serial_number (only a single value; NOT the certificate's serial number, just the SERIALNUMBER name attribute)

    signature_bits
        Number of bits to use in the signature algorithm.
        Valid: ``256`` (SHA-2-256), ``384`` (SHA-2-384), ``512`` (SHA-2-512).
        Defaults to ``0``, which automatically selects an algorithm based on
        the issuer's key length.

    not_before_duration
        Duration by which to backdate the NotBefore property. Defaults to ``30s``.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``ttl`` is ignored. ``ttl_remaining`` is still validated, but falling below it causes
        state failure instead of a reissuance.

        .. important::

            Must not exceed the signing issuer's own expiry, which enforces a hard cutoff
            during issuance, unless the issuer's ``leaf_not_after_behavior`` is set to
            ``permit`` and ``enforce_leaf_not_after_behavior`` is passed.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    kwargs
        Most parameters for the :py:func:`file.managed <salt.states.file.managed>` state or any of the ones for
        the Vault PKI :py:func:`sign_intermediate <saltext.vault.modules.vault_pki.sign_intermediate>` execution module function
        are passed through.

        .. hint::

            This is a high-level state, which connects several different functions:

            * Vault API (`sign-intermediate <https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-intermediate>`__).
              Completely unknown keyword parameters end up there.
            * :py:func:`x509.create_csr <salt.modules.x509_v2.create_csr>`: Used to generate a CSR that Vault should sign.
              Any subject name attribute parameters (``O``, ``OU`` etc.) and most extension parameters
              (``certificatePolicies``, ``keyUsage``, ``extendedKeyUsage`` etc.) end up here.
              Ignored when ``csr`` is defined or ``sign_verbatim`` is false (so by default).
            * :py:func:`file.managed <salt.states.file.managed>`: Parameters such as ``user``, ``group`` and ``mode``
              end up influencing the certificate file on disk.
              Note: ``encoding`` is a valid parameter for both this function and ``file.managed``. If you need to pass
              it to the latter, specify it as ``file_encoding`` instead.
    """

    file_args, cert_args = _split_file_kwargs(
        hlp.filter_state_internal_kwargs(kwargs, ("check_cmd",))
    )
    issuer_expiry = None

    def validate_cutoffs(issuer_info):
        nonlocal issuer_expiry
        behavior = issuer_info.get("leaf_not_after_behavior")
        enforced = cert_args.get("enforce_leaf_not_after_behavior")
        if behavior == "permit" and enforced:
            return None
        # The signing issuer's own expiry enforces a hard cutoff during issuance.
        # Vault truncates CA certificates regardless of the issuer's configured
        # `leaf_not_after_behavior`, unless enforcement is requested explicitly
        # or the behavior is `always_enforce_err`.
        issuer_expiry = pki.not_valid_after(x509util.load_cert(issuer_info["certificate"]))
        _validate_issuance_cutoff(
            issuer_expiry,
            "the signing issuer's expiry",
            not_after,
            timestring_map(ttl_remaining, cast=int),
        )
        if (behavior == "always_enforce_err" or (enforced and behavior == "err")) and (
            not_after is None
            # An explicit not_after beyond the expiry was refused above already.
            and datetime.now(tz=timezone.utc) + timedelta(seconds=timestring_map(ttl, cast=int))
            > issuer_expiry
        ):
            # In these cases, Vault errors out instead of truncating.
            # Since ttl is translated into not_after, this prediction is exact.
            return (
                "Issuance would fail because the requested validity exceeds the "
                f"signing issuer's expiry ({issuer_expiry.strftime(pki.TIME_FMT)}) "
                f"and its `leaf_not_after_behavior` is set to `{behavior}`. "
                "Reduce `ttl` or rotate the issuer"
            )
        return None

    def check_cert(current, issuer_info, urls, ca_chain):
        effective_ttl = ttl_seconds = timestring_map(ttl, cast=int)
        if issuer_expiry is not None:
            # The effective validity is capped by the signing issuer's expiry. Ensure we report that correctly.
            effective_ttl = min(
                ttl_seconds,
                int((issuer_expiry - datetime.now(tz=timezone.utc)).total_seconds()),
            )
        changes, unverified_url_exts = pki.check_ca_cert_for_changes(
            current=current,
            issuer=issuer_info["certificate"],
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            csr=csr,
            encoding=encoding,
            append_chain=ca_chain,
            sign_verbatim=sign_verbatim,
            alt_names=alt_names,
            common_name=common_name,
            country=country,
            exclude_cn_from_sans=exclude_cn_from_sans,
            excluded_alt_names=excluded_alt_names,
            ttl_remaining=ttl_remaining,
            key_usage=key_usage,
            locality=locality,
            max_path_length=max_path_length,
            not_after=not_after,
            not_before_duration=not_before_duration,
            organization=organization,
            ou=ou,
            permitted_alt_names=permitted_alt_names,
            postal_code=postal_code,
            province=province,
            serial_number=serial_number,
            signature_bits=signature_bits,
            street_address=street_address,
            ttl=effective_ttl,
            urls=urls,
            **cert_args,
        )
        notes = []
        if unverified_url_exts:
            notes.append(URL_EXTS_UNVERIFIED_NOTE.format(mount=mount))
        return changes, notes

    def sign():
        nonlocal not_after
        if not_after is None:
            # Requested TTLs are capped at the mount's max_lease_ttl (768h by default),
            # `not_after` is not. CA certificates usually exceed that limit, so translate.
            not_after = (
                datetime.now(tz=timezone.utc) + timedelta(seconds=timestring_map(ttl, cast=int))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        issued_cert = __salt__["vault_pki.sign_intermediate"](
            common_name=common_name,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            csr=csr,
            issuer_ref=issuer_ref,
            mount=mount,
            sign_verbatim=sign_verbatim,
            alt_names=alt_names,
            country=country,
            exclude_cn_from_sans=exclude_cn_from_sans,
            excluded_alt_names=excluded_alt_names,
            key_usage=key_usage,
            locality=locality,
            max_path_length=max_path_length,
            not_after=not_after,
            not_before_duration=not_before_duration,
            organization=organization,
            ou=ou,
            permitted_alt_names=permitted_alt_names,
            postal_code=postal_code,
            province=province,
            serial_number=serial_number,
            signature_bits=signature_bits,
            street_address=street_address,
            **cert_args,
        )
        return issued_cert["certificate"]

    return _certificate_file_managed(
        name,
        private_key=private_key,
        csr=csr,
        mount=mount,
        ttl=ttl,
        ttl_remaining=ttl_remaining,
        not_after=not_after,
        encoding=encoding,
        append_ca_chain=append_ca_chain,
        file_args=file_args,
        setup=lambda: issuer_ref,
        validate_cutoffs=validate_cutoffs,
        check_cert=check_cert,
        sign=sign,
    )


def _certificate_file_managed(
    name,
    *,
    private_key,
    csr,
    mount,
    ttl,
    ttl_remaining,
    not_after,
    encoding,
    append_ca_chain,
    file_args,
    setup,
    validate_cutoffs,
    check_cert,
    sign,
    reissue=False,
):
    """
    Shared implementation for managing a local certificate file whose certificate
    is signed by a Vault issuer, backing ``certificate_managed`` and
    ``ca_certificate_managed``. Parameters that are specific to this function:

    file_args
        Keyword arguments for the ``file.managed`` calls, split off the state's ``kwargs``.

    setup
        Callback gathering further requirements, run after the preliminary
        file checks. Returns the reference of the signing issuer, where None
        means the mount's default issuer.

    validate_cutoffs
        Callback ensuring hard cutoffs enforced remotely during issuance
        (such as a role's ``max_ttl`` or the signing issuer's expiry) do not
        interfere with the requested certificate lifecycle parameters.
        Receives the issuer info. Called before changes are checked.
        Can return a message describing why a new issuance is predetermined
        to fail remotely, which fails the state - even in test mode - if
        one turns out to be required. Otherwise, the message is appended
        to the comment as a note.

    check_cert
        Callback checking the current certificate against the desired state.
        Receives the (symlink-resolved) path of the current certificate file,
        the signing issuer's info, the mount's effective URL configuration and
        the CA chain to append, returns a tuple of (certificate changes,
        list of notes to append to the state's comment).

    sign
        Callback requesting the new certificate from Vault. Returns the certificate.

    reissue
        Unconditionally request a new certificate. Defaults to false.
    """

    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "The certificate is in the correct state",
    }

    changes = {}
    ca_chain = []
    verb = "create"
    msg = []
    notes = []

    try:
        hlp.one_of(private_key=private_key, csr=csr)
        encoding = hlp.in_vals(("der", "pem", "pkcs7_der", "pkcs7_pem"), encoding=encoding)
        if encoding == "der" and append_ca_chain:
            raise SaltInvocationError(
                "Cannot append the CA chain to DER-encoded certificates. "
                "Use pkcs7_der if you need a binary encoding including the chain"
            )

        _validate_ttl_params(
            timestring_map(ttl, cast=int), timestring_map(ttl_remaining, cast=int), not_after
        )

        # check file.managed changes early to avoid using unnecessary resources
        file_managed_test = _run_state("file.managed", name, test=True, replace=False, **file_args)
        if file_managed_test["result"] is False:
            ret["result"] = False
            return _ret(
                ret,
                "Problem while testing file.managed changes, see its output",
                notes,
                sub=file_managed_test,
            )
        if "is not present and is not set for creation" in file_managed_test["comment"]:
            return _ret(ret, sub=file_managed_test)

        file_exists = None
        # handle follow_symlinks
        if __salt__["file.is_link"](name):
            if file_args.get("follow_symlinks", True):
                name = os.path.realpath(name)
            else:
                if not __opts__["test"]:
                    # workaround https://github.com/saltstack/salt/issues/31802
                    __salt__["file.remove"](name)
                changes["replaced"] = True
                file_exists = False
        if file_exists is None:
            file_exists = __salt__["file.file_exists"](name)

        issuer_ref = setup()
        issuer_info = __salt__["vault_pki.read_issuer"](issuer_ref or "default", mount=mount)
        if issuer_info is None:
            raise CommandExecutionError(
                f"Issuer '{issuer_ref or 'default'}' does not exist on mount {mount}"
            )

        # Always ensure remote factors (issuer validity or role max_ttl) don't cause non-idempotency.
        # Without this, we would always report success and reissue a certificate on the next run
        # or always fail because Vault would deny issuance anyways, depending on the issuer's leaf_not_after_behavior.
        issuance_blocker = validate_cutoffs(issuer_info)

        if append_ca_chain:
            ca_chain = [x509util.load_cert(x) for x in issuer_info["ca_chain"]]
            # Filter self-signed CA, which shouldn't be in the chain.
            ca_chain = [
                cert
                for cert in ca_chain
                if cert.subject.rfc4514_string() != cert.issuer.rfc4514_string()
            ]

        if file_exists:
            if reissue:
                # No need to make any checks, just replace the cert
                changes["replaced"] = True
            else:
                urls = _get_urls(issuer_info, mount=mount)
                changes, check_notes = check_cert(name, issuer_info, urls, ca_chain)
                notes.extend(check_notes)

        else:
            changes["created"] = True

        if issuance_blocker:
            if set(changes) - {"ca_chain", "encoding"}:
                # A new certificate is required, but requesting it is predetermined
                # to fail remotely. Report this even in test mode.
                ret["result"] = False
                return _ret(ret, issuance_blocker, notes, changes=changes)
            # No new certificate is currently required, so only warn.
            notes.append(issuance_blocker)

        if not changes and file_managed_test["result"] and not file_managed_test["changes"]:
            return _ret(ret, notes=notes, sub=file_managed_test)

        ret["changes"] = changes
        if changes and file_exists:
            verb = "reissue"

        if __opts__["test"]:
            ret["result"] = None if changes else True
            return _ret(
                ret,
                f"The certificate would have been {verb}d" if changes else None,
                notes,
                sub=file_managed_test,
            )

        reissued_cert = None
        if changes:
            if not set(changes) - {
                "ca_chain",
                "encoding",
            }:
                verb = "recreate"
                cert_to_encode = name
            else:
                cert_to_encode = sign()
            reissued_cert = __salt__["x509.encode_certificate"](
                cert_to_encode,
                append_certs=ca_chain,
                encoding=encoding,
            )

            msg.append(f"The certificate has been {verb}d")

        # If we're here, we detected file.managed changes in the initial test above and/or reissued the certificate.
        # If we do not need the contents to change or if we have binary contents (not supported by file.managed),
        # just ensure the file exists in the correct state. PEM-encoded contents can be applied directly.
        # Note: `check_cmd` could fail with binary contents since we only write them after file.managed runs. Fix if someone asks. :)
        replace = bool(encoding in ("pem", "pkcs7_pem") and reissued_cert)
        contents = reissued_cert if replace else None
        file_managed_ret = _run_state(
            "file.managed", name, contents=contents, replace=replace, **file_args
        )
        _add_sub_state_run(ret, file_managed_ret)
        if not _check_file_ret(file_managed_ret, ret, file_exists):
            return ret
        if reissued_cert and not replace:
            # We reissued in some binary format. The file (and thus parent directories) exist for sure,
            # just add the contents that could not be written with file.managed earlier.
            hlp.safe_atomic_write(
                name,
                base64.b64decode(reissued_cert),
                __salt__["config.backup_mode"](file_args.get("backup", "")),
                __opts__["cachedir"],
            )

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        return _ret(ret, str(err), changes={})

    return _ret(ret, msg, notes)


def role_managed(name, mount="pki", issuer_ref=None, ttl=None, max_ttl=None, **kwargs):
    """
    Ensure a PKI role is present and configured as specified.

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    issuer_ref
        Issuer reference for the role. Can be name, id or literal ``default``.

    ttl
        Specifies the Time To Live value to be used for the validity period of the requested certificate,
        provided as a string duration with time suffix. Hour is the largest suffix.
        The value specified is strictly used for future validity.
        If not set, uses the system default value or the value of ``max_ttl``, whichever is shorter.

    max_ttl
        Specifies the maximum Time To Live provided as a string duration with time suffix.
        Hour is the largest suffix. If not set, defaults to the system maximum lease TTL.

    kwargs
        Any other parameter accepted by the Vault :py:func:`write_role <saltext.vault.modules.vault_pki.write_role>`
        execution module function or Vault update role API method.
    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The role is present as specified",
        "changes": {},
    }

    kwargs = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    def _diff_params(current):
        nonlocal issuer_ref, ttl, max_ttl, kwargs
        diff_params = (
            ("issuer_ref", issuer_ref),
            ("ttl", timestring_map(ttl, cast=int)),
            ("max_ttl", timestring_map(max_ttl, cast=int)),
        )
        changed = {}
        for param, arg in diff_params:
            if arg is None:
                continue
            if current[param] != arg:
                changed.update(
                    {
                        param: {
                            "old": current.get(param),
                            "new": arg,
                        }
                    }
                )
        for param, arg in kwargs.items():
            if param not in current:
                continue
            curr_val = current[param]
            # Compare normalized values: The API normalizes scalars for
            # list-type parameters and duration strings into seconds.
            if isinstance(curr_val, list) and isinstance(arg, str):
                arg = hlp.deserialize_csl(arg)
            elif (
                isinstance(curr_val, (int, float))
                and not isinstance(curr_val, bool)
                and isinstance(arg, str)
            ):
                try:
                    arg = timestring_map(arg, cast=type(curr_val))
                except SaltInvocationError:
                    pass
            if curr_val != arg:
                changed.update(
                    {
                        param: {
                            "old": curr_val,
                            "new": arg,
                        }
                    }
                )
        return changed

    changes = {}

    try:
        if current := __salt__["vault_pki.read_role"](name, mount=mount):
            if not (changes := _diff_params(current)):
                return ret
        else:
            changes["created"] = name

        ret["changes"] = changes

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                f"PKI role `{name}` would have been {'updated' if current else 'created'}"
            )
            return ret

        __salt__["vault_pki.write_role"](
            name=name, mount=mount, issuer_ref=issuer_ref, ttl=ttl, max_ttl=max_ttl, **kwargs
        )
        ret["comment"] = f"PKI role `{name}` has been {'updated' if current else 'created'}"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_absent(name, mount="pki"):
    """
    Ensure a PKI role is absent.

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    ret = {
        "name": name,
        "result": True,
        "comment": "",
        "changes": {},
    }

    try:
        current = __salt__["vault_pki.read_role"](name, mount=mount)
        if current is None:
            ret["comment"] = f"PKI role `{name}` is already absent."
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"PKI role `{name}` would have been deleted"
            return ret

        __salt__["vault_pki.delete_role"](name, mount=mount)
        ret["comment"] = f"PKI role `{name}` has been deleted."

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def intermediate_issuer_managed(  # pylint: disable=too-many-arguments,too-many-locals
    name,
    days_remaining=60,
    rotate_key=False,
    # Vault issuer config for this issuer's cert - if ref is unspecified, uses x509_v2
    issuer_ref=None,
    issuer_mount=None,
    # key params
    key_ref=None,
    key_type=None,
    key_algo=None,
    key_bits=None,
    managed_key_name=None,
    managed_key_id=None,
    # cert params valid for both issuance methods
    days_valid=180,
    not_after=None,
    # sign-intermediate params, when issuer_ref is specified, or as fallback when it is not
    not_before_duration=30,  # Vault signing only
    max_path_length=0,
    alt_names=None,
    exclude_cn_from_sans=False,  # Vault signing only
    key_usage=None,
    permitted_alt_names=None,
    excluded_alt_names=None,
    ou=None,
    organization=None,
    country=None,
    locality=None,
    province=None,
    street_address=None,
    postal_code=None,
    serial_number=None,
    signature_bits=0,  # Vault signing only
    # issuer params
    issuer_name=None,
    leaf_not_after_behavior=None,
    usage=None,
    revocation_signature_algorithm=None,
    aia_urls=None,
    crl_endpoints=None,
    delta_crl_endpoints=None,
    ocsp_servers=None,
    aia_url_templating=None,
    mount="pki",
    # params for x509.create_certificate (no issuer_ref) or vault_pki.sign_intermediate (with issuer_ref)
    **kwargs,
):
    """
    .. versionadded:: 1.9.0

    Ensure an issuer representing an intermediate CA is present **as the default issuer** on the mount.
    Rotates the issuer when necessary by generating a new certificate. Unlike :func:`root_issuer_managed`,
    the rotation always happens when the certificate does not match the configuration, not only when
    ``days_remaining`` indicates expiry.

    .. important::

        You need to prune keys and issuers manually, they are never deleted by this state.

    .. hint::

        When an issuer is rotated, the old one is kept with slightly adjusted configuration:

        1. If ``issuer_name`` is specified and matches the old one, it receives the current
           timestamp as a suffix, separated by a dash (``<issuer_name>-<timestamp>``).
        2. ``issuing-certificates`` is removed from its usages.

        Other issuers on the mount, e.g. manually cross-signed variants of the managed
        one, are ignored by this state and can coexist safely, as long as they are not
        assigned its ``issuer_name``.

    Signs the issuer certificate either via another Vault issuer or a Salt-internal CA.

    A Vault issuer is selected by specifying ``issuer_ref``. The resulting certificate can only
    be influenced by valid parameters to the endpoint used by :py:func:`vault_pki.sign_intermediate <saltext.vault.modules.vault_pki.sign_intermediate>`;
    passing ``sign_verbatim``, CSR generation arguments or a pre-generated CSR has no effect.

    When ``issuer_ref`` is unspecified, we rely on :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`.
    Any unknown keyword arguments to this function are passed through.
    Vault-style parameters like ``alt_names`` are translated transparently (into ``subjectAltName`` and its format, in this example).
    You can still pass x509_v2-style parameters directly, these translations only happen when the respective
    ``x509.create_certificate`` parameter is not found in ``kwargs``.
    Some ``x509.create_certificate`` parameters are enforced by this function, see ``kwargs`` below.
    The final certificate also depends on a ``signing_policy``, if passed. It can override any parameter without
    this state failing or reporting necessary changes, similar to ``x509.certificate_managed``.

    Does not support certificate import.

    Required policy:

    .. code-block:: vaultpolicy

        # Read default issuer to check for necessary changes
        path "<mount>/issuer/default" {
            capabilities = ["read"]
        }

        # When key_ref is not set, need to generate a key
        path "<mount>/keys/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

        # When key_ref is set, need to resolve names to ids
        path "<mount>/keys" {
            capabilities = ["list"]
        }

        # Generate a CSR to derive the public key
        path "<mount>/intermediate/generate/existing" {
            capabilities = ["create", "update"]
        }

        # When issuer_ref is specified, read the signing issuer to check for
        # necessary changes. issuer_mount defaults to the value of mount.
        path "<issuer_mount>/issuer/<issuer_ref>" {
            capabilities = ["read"]
        }

        # When issuer_ref is specified, we use that issuer to sign the certificate
        path "<issuer_mount>/issuer/<issuer_ref>/sign-intermediate" {
            capabilities = ["update"]
        }

        # Import the signed cert
        path "<mount>/intermediate/set-signed" {
            capabilities = ["create", "update"]
        }

        # Set default issuer
        path "<mount>/config/issuers" {
            capabilities = ["create", "update"]
        }

        # Update issuer configuration. Might also be exercised when
        # no issuer params are specified for config recovery after rotation.
        path "<mount>/issuer/<issuer_id>" {
            capabilities = ["patch"]
        }

        # When issuer_ref is specified, read the signing issuer's mount default urls
        # to account for cert extensions, unless the signing issuer overrides them
        # with its own AIA configuration.
        # Note: Failure to read this does not cause rotation, only a note.
        path "<issuer_mount>/config/urls" {
            capabilities = ["read"]
        }

        # When URLs use templating with `{{cluster_path}}`/`{{cluster_aia_path}}` variables
        # Note: Failure to read this does not cause rotation, only a note.
        path "<issuer_mount>/config/cluster" {
            capabilities = ["read"]
        }

    **Certificate/Key configuration:**

    name
        Common name (CN) of the certificate subject.

        .. note::

            When ``issuer_ref`` is unspecified, the final ``CN`` can differ from this value
            because of signing policy merging.

    days_remaining
        Attempt to recreate the certificate if its remaining validity
        falls below this number of days. Defaults to ``60``.

        .. hint::

            This value should exceed the maximum validity of certificates issued
            by this CA, otherwise issuance close to its expiry can fail or yield
            certificates outliving it.

            It must also be less than the signing issuer's remaining validity
            when a Vault issuer signs this certificate, otherwise the certificate
            would be reissued during each run. This does not apply when the
            issuer's ``leaf_not_after_behavior`` is set to ``permit`` and
            ``enforce_leaf_not_after_behavior`` is passed.

    rotate_key
        When rotating the default issuer, rotate its key along with it. Defaults to false.
        Not respected when ``key_ref`` is specified.

        .. important::

            Cross-signed variants of this issuer certify the old key, so they stop bridging
            anything issued under the new one. They are not re-established by this state,
            you need to cross-sign the new key manually.

        .. note::

            Key parameters are not managed statefully, meaning changes to ``key_type``, ``key_algo``
            and ``key_bits`` are only applied when generating a new key.
            ``key_ref`` changes are applied though.

    issuer_ref
        Issuer name/ID of the issuer that should sign this issuer's certificate.
        If unspecified, uses :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`
        to sign it instead.

    issuer_mount
        When ``issuer_ref`` is specified and the issuer is on a different mount,
        specify it here. Defaults to the value of ``mount``.

    key_ref
        Instead of managing the key, use the one associated with this key ID/name.
        When specified, disables key generation/rotation.

    key_type
        Type of key to generate when necessary and ``key_ref`` is not specified.
        Either ``internal``, ``exported`` or ``kms``.
        Defaults to ``internal``.

    key_algo
        Key algorithm. Either ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Number of bits to use for the generated keys. Valid values depend on the ``key_algo``.

        * ``rsa``: 2048 (default), 3072, 4096, 8192.
        * ``ec``: 224, 256 (default), 384, 521
        * ``ed25519``: ignored

        Defaults to ``0`` (universal default).

    managed_key_name
        When ``key_type`` is ``kms``, the managed key's configured name. Either this or ``managed_key_id`` is required then.

    managed_key_id
        When ``key_type`` is ``kms``, the managed key's UUID. Either this or ``managed_key_name`` is required then.

    days_valid
        Number of days the certificate should be valid for when (re-)issued.
        Not respected when ``not_after`` is set explicitly.
        Defaults to 180.

        .. hint::

            Translated into ``not_after`` when a Vault issuer signs the certificate,
            hence not subject to the mount's ``max_lease_ttl``.

    not_after
        Absolute value of the Not After field of the certificate in UTC format,
        either ``YYYY-MM-ddTHH:MM:SSZ`` or ``YYYY-MM-dd HH:MM:SS``.
        When set, ``days_valid`` is ignored. ``days_remaining`` is still validated, but falling below it causes
        state failure instead of a reissuance.

        .. note::

            This parameter is valid for both issuance methods and translated into the correct
            format automatically.

            Must not exceed the signing issuer's own expiry when a Vault issuer
            signs the certificate, which enforces a hard cutoff during issuance,
            unless the issuer's ``leaf_not_after_behavior`` is set to ``permit``
            and ``enforce_leaf_not_after_behavior`` is passed.

    not_before_duration
        Duration by which to backdate the NotBefore property. Defaults to ``30s``.

        Has no effect when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit, unless the issuer certificate has a maximum path length,
        in which case it means one less than the issuer's pathlen.
        Defaults to ``0``.

        Forcibly translated into ``basicConstraints`` when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    alt_names
        Any alternative names to add to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists (``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type1>:<value1>", ...]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

        Translated into ``subjectAltName`` when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    exclude_cn_from_sans
        If set to true, the Common Name is not added to the SANs.
        Useful if the CN is not a hostname or email address.

        Has no effect when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    key_usage
        (Requires Vault 1.20+ or OpenBao when ``issuer_ref`` is specified)
        List of key usages to add to the existing set of key usages (CRLSign,CertSign).
        Per the CAB Forum requirements, Vault ignores values other than DigitalSignature.

        Translated into ``keyUsage`` when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    permitted_alt_names
        List of alternative names for which certificates are allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.

        .. important::

            Types other than ``dns`` require Vault 1.19+ when ``issuer_ref`` is specified.

        Translated into ``nameConstraints`` when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    excluded_alt_names
        (Vault 1.19+ only when ``issuer_ref`` is specified)
        List of alternative names for which certificates are not allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.

        Translated into ``nameConstraints`` when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    Subject DN fields
        Most of these can be single strings or lists of strings (for multiple values).

        * ou
        * organization
        * country
        * locality
        * province
        * street_address
        * postal_code
        * serial_number (only a single value; NOT the certificate's serial number, just the SERIALNUMBER name attribute)

        Translated into ``subject`` when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

        .. note::

            The resulting ``subject`` format depends on whether a ``signing_policy`` was specified or not, because
            a signing policy that defines any subject attribute would override the default format completely.

            * If no ``signing_policy`` is specified, it becomes a string that faithfully recreates subjects as rendered by Vault.
            * When it is specified, it becomes a dictionary (e.g. ``{CN: Foo}``), which allows merging of attributes from
              a signing policy that defines ``subject`` as a dictionary itself (e.g. + ``{C: US}`` => ``CN=Foo,C=US``).
              There are several tradeoffs to using a dict: Parameters with more than one value are ignored, ``postal_code`` is ignored
              and the subject name's RDN order differs a bit from the one Vault renders.

            This translation is only meant as a helper, you can always specify ``subject`` yourself. It's possible to use
            a list of RDN strings here and in the signing policy, which results in the signing policy's list being prepended
            to the one passed in here (i.e. appended when visualizing its rfc4514 string representation).

    signature_bits
        Number of bits to use in the signature algorithm.
        Valid: ``256`` (SHA-2-256), ``384`` (SHA-2-384), ``512`` (SHA-2-512).
        Defaults to ``0``, which automatically selects an algorithm based on
        the issuer's key length.

        Has no effect when a Salt-internal CA issues the certificate (``issuer_ref`` is unspecified).

    kwargs
        Unknown keyword arguments are passed to the certificate signing function, which depends
        on whether ``issuer_ref`` is specified:

        * A non-empty ``issuer_ref`` means we rely on :py:func:`vault_pki.sign_intermediate <saltext.vault.modules.vault_pki.sign_intermediate>`.

          Note that its ``sign_verbatim`` parameter is forced to false and its ``csr``
          parameter is enforced by this function, so CSR generation arguments do not have any effect
          and you cannot pass a pre-generated CSR.

        * No ``issuer_ref`` means we rely on :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`.
          See there for details.

          The following arguments are enforced by this function:

          * ``basicConstraints`` (``{critical: true, ca: true, pathlen: <max_path_length>}``)
          * ``csr``
          * ``format`` (pem)
          * ``private_key``/``public_key``/``path``/``raw``/``serial_number`` (empty)

          These receive defaults from specified Vault-style parameters to this function:

          * ``subject``
          * ``subjectAltName`` (not critical)
          * ``nameConstraints`` (critical)
          * ``keyUsage`` (critical)

          These receive defaults if not specified at all:

          * ``keyUsage``: ``[critical, cRLSign, keyCertSign]``
          * ``subjectKeyIdentifier``: ``hash``
          * ``authorityKeyIdentifier``: ``keyid:always``

          .. note::

              Certificates passed to ``append_certs`` are imported together with the issuer certificate
              when it is (re-)issued, but not handled statefully themselves.

    **Issuer configuration:**

    .. note::

        Unspecified parameters are ignored during management and retain their current values in most cases.

        This state tries to recover them after rotating an issuer certificate, which
        would otherwise reset them to their defaults if they were configured manually.
        This does not apply to ``issuer_name``, which requires special handling,
        and ``manual_chain``, which is not handled in this state.
        When the key changes (different ``key_ref`` or ``rotate_key``), this also does
        not apply to ``revocation_signature_algorithm`` because a key algorithm change
        can make the previous value invalid.

    issuer_name
        Custom name for the issuer. Must be unique and not equal to ``default``.

        .. important::

            Never assign this name to issuers managed outside of this state
            (e.g. cross-signed variants). A conflicting issuer might be renamed
            under specific circumstances; in all other cases, this state fails.

    leaf_not_after_behavior
        Behavior of a leaf's ``NotAfter`` field during issuance when it exceeds the issuer's validity.
        Valid options:

        * ``err``: Error, unless during CA/ACME issuance. (default)
        * ``always_enforce_err``: Error, including during CA/ACME issuance. (Vault 1.18.2+ only)
        * ``truncate``: Silently truncate the requested NotAfter to that of the issuer.
        * ``permit``: Allow signed certificate validities to exceed that of the issuer.

    usage
        Allowed usages for this issuer. Valid options are:

        * ``read-only`` - to allow this issuer to be read; implicit; always allowed;
        * ``issuing-certificates`` - to allow this issuer to be used for issuing other certificates;
        * ``crl-signing`` -  to allow this issuer to be used for signing CRLs.
          This is separate from the CRLSign KeyUsage on the x509 certificate, but this usage cannot be set
          unless that KeyUsage is allowed on the x509 certificate;
        * ``ocsp-signing`` -  to allow this issuer to be used for signing OCSP responses.

    revocation_signature_algorithm
        Which signature algorithm to use when building CRLs.
        See Go's `x509.SignatureAlgorithm <https://pkg.go.dev/crypto/x509#SignatureAlgorithm>`__ constant for possible values.
        Default (empty string) is to autoselect.

    aia_urls
        Specifies the URL values for the Issuing Certificate field as an array.

    crl_endpoints
        Specifies the URL values for the CRL Distribution Points field as an array.

    delta_crl_endpoints
        (Requires Vault 1.20+ or OpenBao)
        Specifies the URL values for the Delta CRL Distribution Points field.
        This can be an array or a comma-separated string list.

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as an array.

    aia_url_templating
        Render ``aia_urls``/``crl_endpoints``/``ocsp_servers``/``delta_crl_endpoints`` as templates.
        Supported variables: ``{{issuer_id}}``, ``{{cluster_path}}``, ``{{cluster_aia_path}}``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    try:
        _validate_ttl_params(
            days_valid * 86400,
            days_remaining * 86400,
            not_after,
            ttl_param="days_valid",
            ttl_remaining_param="days_remaining",
        )
    except SaltInvocationError as err:
        return {"name": name, "result": False, "comment": str(err), "changes": {}}
    issuer_mount = issuer_mount or mount
    vault_signed = issuer_ref is not None
    # Arguments for either vault_pki.sign_intermediate (but not CSR generation args, so very few/none)
    # or x509.create_certificate, depending on issuer_ref being set or not.
    cert_args = hlp.filter_state_internal_kwargs(kwargs)

    signing_issuer: dict[str, typing.Any]
    signing_issuer_expiry: datetime | None = None
    issuance_blocker = None
    if vault_signed:
        try:
            signing_issuer = __salt__["vault_pki.read_issuer"](issuer_ref, mount=issuer_mount)
            if signing_issuer is None:
                raise CommandExecutionError(
                    f"Issuer '{issuer_ref}' does not exist on mount {issuer_mount}"
                )
            behavior = signing_issuer.get("leaf_not_after_behavior")
            enforced = cert_args.get("enforce_leaf_not_after_behavior")
            if not (behavior == "permit" and enforced):
                # The signing issuer's own expiry enforces a hard cutoff during issuance.
                # Vault truncates CA certificates regardless of the issuer's configured
                # `leaf_not_after_behavior`, unless enforcement is requested explicitly
                # or the behavior is `always_enforce_err`.
                signing_issuer_expiry = pki.not_valid_after(
                    x509util.load_cert(signing_issuer["certificate"])
                )
                _validate_issuance_cutoff(
                    signing_issuer_expiry,
                    "the signing issuer's expiry",
                    not_after,
                    days_remaining * 86400,
                    remaining_param="days_remaining",
                )
                if (behavior == "always_enforce_err" or (enforced and behavior == "err")) and (
                    not_after is None
                    # An explicit not_after beyond the expiry was refused above already.
                    and datetime.now(tz=timezone.utc) + timedelta(days=days_valid)
                    > signing_issuer_expiry
                ):
                    # In these cases, Vault errors out instead of truncating.
                    # Since days_valid is translated into not_after, this prediction is exact.
                    issuance_blocker = (
                        "Issuance would fail because the requested validity exceeds the "
                        f"signing issuer's expiry ({signing_issuer_expiry.strftime(pki.TIME_FMT)}) "
                        f"and its `leaf_not_after_behavior` is set to `{behavior}`. "
                        "Reduce `days_valid` or rotate the issuer"
                    )
        except (CommandExecutionError, SaltInvocationError) as err:
            return {"name": name, "result": False, "comment": str(err), "changes": {}}

    def check_cert(current, *, rotate_key, replace_key):
        nonlocal cert_args, not_after, alt_names, permitted_alt_names, excluded_alt_names
        # We need to correctly map/filter args for changes checking before passing to the utils func.
        # Reuse the result during generation to avoid duplicate warnings.
        cert_args, not_after, alt_names, permitted_alt_names, excluded_alt_names = (
            pki.norm_generate_intermediate_params(
                cert_args,
                vault_signed,
                country=country,
                province=province,
                locality=locality,
                street_address=street_address,
                postal_code=postal_code,
                organization=organization,
                ou=ou,
                common_name=name,
                serial_number=serial_number,
                alt_names=alt_names,
                key_usage=key_usage,
                permitted_alt_names=permitted_alt_names,
                excluded_alt_names=excluded_alt_names,
                max_path_length=max_path_length,
                not_after=not_after,
            )
        )

        notes = []
        if vault_signed:
            urls = _get_urls(signing_issuer, mount=issuer_mount)
            effective_days_valid = days_valid
            if signing_issuer_expiry is not None:
                # The effective validity is capped by the signing issuer's expiry
                effective_days_valid = min(
                    days_valid,
                    int(
                        (signing_issuer_expiry - datetime.now(tz=timezone.utc)).total_seconds()
                        // 86400
                    ),
                )
            cert_changes, unverified_url_exts = pki.check_int_issuer_cert_for_changes_vault_ca(
                current=current["certificate"],
                issuer=signing_issuer["certificate"],
                rotate_key=rotate_key,
                replace_key=replace_key,
                days_remaining=days_remaining,
                days_valid=effective_days_valid,
                common_name=name,
                country=country,
                exclude_cn_from_sans=exclude_cn_from_sans,
                key_usage=key_usage,
                locality=locality,
                max_path_length=max_path_length,
                normalized_sans=alt_names,
                norm_excluded_nc=excluded_alt_names,
                norm_permitted_nc=permitted_alt_names,
                not_after=not_after,
                not_before_duration=not_before_duration,
                organization=organization,
                ou=ou,
                postal_code=postal_code,
                province=province,
                serial_number=serial_number,
                signature_bits=signature_bits,
                street_address=street_address,
                urls=urls,
            )
            if unverified_url_exts:
                notes.append(URL_EXTS_UNVERIFIED_NOTE.format(mount=issuer_mount))
        else:
            if "signing_policy" in cert_args:
                x509_policy = __salt__["x509.get_signing_policy"](
                    cert_args["signing_policy"], ca_server=cert_args.get("ca_server")
                )
            else:
                x509_policy = {}
            cert_changes = pki.check_int_issuer_cert_for_changes_salt_ca(
                current=current["certificate"],
                rotate_key=rotate_key,
                replace_key=replace_key,
                signing_policy_contents=x509_policy,
                days_remaining=days_remaining,
                # these are common to both Vault and x509_v2
                days_valid=days_valid,
                not_after=not_after,
                **cert_args,
            )
        return cert_changes, notes

    def generate(key_ref):
        res = __salt__["vault_pki.generate_intermediate"](
            common_name=name,
            issuer_ref=issuer_ref,
            issuer_mount=issuer_mount,
            key_type="existing",
            key_ref=key_ref,
            days_valid=days_valid,
            not_after=not_after,
            not_before_duration=not_before_duration,
            max_path_length=max_path_length,
            alt_names=alt_names,
            exclude_cn_from_sans=exclude_cn_from_sans,
            key_usage=key_usage,
            permitted_alt_names=permitted_alt_names,
            excluded_alt_names=excluded_alt_names,
            ou=ou,
            organization=organization,
            country=country,
            locality=locality,
            province=province,
            street_address=street_address,
            postal_code=postal_code,
            serial_number=serial_number,
            signature_bits=signature_bits,
            mount=mount,
            **cert_args,
        )
        try:
            issuer_id = res["imported_issuers"][0]
        except (IndexError, KeyError) as err:  # pragma: no cover
            raise CommandExecutionError("Generated certificate, but failed importing it") from err
        return issuer_id, {"imported": res["imported_issuers"]}

    return _default_issuer_managed(
        name,
        kind="Intermediate CA",
        mount=mount,
        issuer_config={
            "issuer_name": issuer_name,
            "leaf_not_after_behavior": leaf_not_after_behavior,
            "usage": usage,
            "revocation_signature_algorithm": revocation_signature_algorithm,
            "aia_urls": aia_urls,
            "crl_endpoints": crl_endpoints,
            "delta_crl_endpoints": delta_crl_endpoints,
            "ocsp_servers": ocsp_servers,
            "aia_url_templating": aia_url_templating,
        },
        check_cert=check_cert,
        generate=generate,
        key_ref=key_ref,
        rotate_key=rotate_key,
        key_type=key_type,
        key_algo=key_algo,
        key_bits=key_bits,
        managed_key_name=managed_key_name,
        managed_key_id=managed_key_id,
        imports_cert=True,
        issuance_blocker=issuance_blocker,
    )


def root_issuer_managed(  # pylint: disable=too-many-arguments,too-many-locals
    name,
    days_remaining=365,
    allow_premature_rotation=False,
    # key params
    key_ref=None,
    rotate_key=False,
    key_type=None,
    key_algo=None,
    key_bits=None,
    managed_key_name=None,
    managed_key_id=None,
    # cert params
    alt_names=None,
    days_valid=3650,
    max_path_length=-1,
    key_usage=None,
    exclude_cn_from_sans=False,
    permitted_alt_names=None,
    excluded_alt_names=None,
    ou=None,
    organization=None,
    country=None,
    locality=None,
    province=None,
    street_address=None,
    postal_code=None,
    serial_number=None,
    signature_bits=0,
    not_before_duration=30,
    not_after=None,
    # issuer params
    issuer_name=None,
    leaf_not_after_behavior=None,
    usage=None,
    revocation_signature_algorithm=None,
    aia_urls=None,
    crl_endpoints=None,
    delta_crl_endpoints=None,
    ocsp_servers=None,
    aia_url_templating=None,
    mount="pki",
):
    """
    .. versionadded:: 1.9.0

    Ensure an issuer representing a root CA is present **as the default issuer** on the mount.
    Rotates the issuer certificate when necessary.

    By default, rotates the issuer certificate **only when days_remaining indicates expiry**.
    If the certificate would need to change before that, the state fails instead of rotating it.
    Set ``allow_premature_rotation: true`` to opt-in for stateful management of all parameters.
    When a rotation is triggered by expiry, any pending parameter changes are applied
    to the new certificate as well.

    .. important::

        **Issuer configuration** changes are always applied, even if the state
        refuses to rotate and fails. Reported **certificate changes** are only
        materialized when the state does not fail.

        You need to prune keys and issuers manually, they are never deleted by this state.

    .. hint::

        When an issuer is rotated, the old one is kept with slightly adjusted configuration:

        1. If ``issuer_name`` is specified and matches the old one, it receives the current
           timestamp as a suffix, separated by a dash (``<issuer_name>-<timestamp>``).
        2. ``issuing-certificates`` is removed from its usages.

        Other issuers on the mount, e.g. manually cross-signed variants of the managed
        one, are ignored by this state and can coexist safely, as long as they are not
        assigned its ``issuer_name``.

    Required policy:

    .. code-block:: vaultpolicy

        # Read default issuer to check for necessary changes
        path "<mount>/issuer/default" {
            capabilities = ["read"]
        }

        # When key_ref is not set, need to generate a key
        path "<mount>/keys/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

        # When key_ref is set, need to resolve names to ids
        path "<mount>/keys" {
            capabilities = ["list"]
        }

        # Generate the root issuer certificate using a separately managed key,
        # hence the key type is always `existing` here
        path "<mount>/root/generate/existing" {
            capabilities = ["create", "update"]
        }

        # Set default issuer
        path "<mount>/config/issuers" {
            capabilities = ["create", "update"]
        }

        # Update issuer configuration. Might also be exercised when
        # no issuer params are specified for config recovery after rotation.
        path "<mount>/issuer/<issuer_id>" {
            capabilities = ["patch"]
        }

        # Read mount default urls to account for cert extensions.
        # Note: Failure to read this or URL drift does not cause rotation, only a note.
        path "<mount>/config/urls" {
            capabilities = ["read"]
        }

        # When URLs use templating with `{{cluster_path}}`/`{{cluster_aia_path}}` variables,
        # but not `{{issuer_id}}` (URLs are always excluded from the issuer certificate in that case)
        # Note: Failure to read this or URL drift does not cause rotation, only a note.
        path "<mount>/config/cluster" {
            capabilities = ["read"]
        }

    **Certificate/Key configuration:**

    name
        Common name (CN) of the certificate subject.

    days_remaining
        Attempt to recreate the certificate if its remaining validity
        falls below this number of days. Defaults to ``365``.

        .. hint::

            This value should exceed the maximum validity of certificates issued
            by this CA (including intermediate ones), otherwise issuance close to
            its expiry can fail or yield certificates outliving it.

    allow_premature_rotation
        Always rotate the root issuer certificate when it does not meet its specification,
        even when it is not nearing its expiration date as defined by ``days_remaining``.
        Defaults to false, meaning this state fails instead of rotating the issuer
        and indicates necessary changes in the ``changes`` dict.

    key_ref
        Instead of managing the key, use the one associated with this key ID/name.
        When specified, disables key generation/rotation.

    rotate_key
        When rotating the default issuer, rotate its key along with it. Defaults to false.
        Not respected when ``key_ref`` is specified.

        .. important::

            Rotating the key is a hard cutover. A new root issuer key means nothing issued under
            the new root validates for clients that only trust the old one.

            The new root must be distributed to trust stores **before** dependent reissuance cascades.
            Consider creating a new mount with a new root issuer instead that you can introduce gradually.

            Cross-signed variants of this issuer certify the old key, so they stop bridging
            anything issued under the new one. They are not re-established by this state,
            you need to cross-sign the new key manually.

        .. note::

            Key parameters are not managed statefully, meaning changes to ``key_type``, ``key_algo``
            and ``key_bits`` are only applied when generating a new key.
            ``key_ref`` changes are applied though.

    key_type
        Type of key to generate when necessary and ``key_ref`` is not specified.
        Either ``internal``, ``exported`` or ``kms``.
        Defaults to ``internal``.

    key_algo
        Key algorithm. Either ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Number of bits to use for the generated keys. Valid values depend on the ``key_algo``.

        * ``rsa``: 2048 (default), 3072, 4096, 8192.
        * ``ec``: 224, 256 (default), 384, 521
        * ``ed25519``: ignored

        Defaults to ``0`` (universal default).

    managed_key_name
        When ``key_type`` is ``kms``, the managed key's configured name. Either this or ``managed_key_id`` is required then.

    managed_key_id
        When ``key_type`` is ``kms``, the managed key's UUID. Either this or ``managed_key_name`` is required then.

    signature_bits
        Number of bits to use in the signature algorithm.
        Valid: ``256`` (SHA-2-256), ``384`` (SHA-2-384), ``512`` (SHA-2-512).
        Defaults to ``0``, which automatically selects an algorithm based on
        ``key_algo`` and ``key_bits`` of the issuer's private key.

    days_valid
        Number of days the certificate should be valid for when (re-)issued.
        Not respected when ``not_after`` is set explicitly.
        Defaults to 3650 (10 years).

        .. hint::

            Translated into ``not_after``, hence not subject to the mount's ``max_lease_ttl``.

    not_before_duration
        Duration by which to backdate the NotBefore property. Defaults to ``30s``.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``days_valid`` is ignored. ``days_remaining`` is still validated, but falling below it causes
        state failure instead of a reissuance.

    alt_names
        Any alternative names to add to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists (``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type1>:<value1>", ...]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit. Defaults to ``-1``.

    key_usage
        (Requires Vault 1.20+ or OpenBao)
        List of key usages to add to the existing set of key usages (CRLSign,CertSign).
        Per the CAB Forum requirements, Vault ignores values other than DigitalSignature.

    exclude_cn_from_sans
        If set to true, the Common Name is not added to the SANs.
        Useful if the CN is not a hostname or email address.

    permitted_alt_names
        List of alternative names for which certificates are allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.

        .. important::

            Types other than ``dns`` require Vault 1.19+.

    excluded_alt_names
        (Vault 1.19+ only)
        List of alternative names for which certificates are not allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.

    Subject DN fields
        Most of these can be single strings or lists of strings (for multiple values).

        * ou
        * organization
        * country
        * locality
        * province
        * street_address
        * postal_code
        * serial_number (only a single value; NOT the certificate's serial number, just the SERIALNUMBER name attribute)

    **Issuer configuration:**

    .. note::

        Unspecified parameters are ignored during management and retain their current values in most cases.

        This state tries to recover them after rotating an issuer certificate, which
        would otherwise reset them to their defaults if they were configured manually.
        This does not apply to ``issuer_name``, which requires special handling,
        and ``manual_chain``, which is not handled in this state.
        When the key changes (different ``key_ref`` or ``rotate_key``), this also does
        not apply to ``revocation_signature_algorithm`` because a key algorithm change
        can make the previous value invalid.

    issuer_name
        Custom name for the issuer. Must be unique and not equal to ``default``.

        .. important::

            Never assign this name to issuers managed outside of this state
            (e.g. cross-signed variants). A conflicting issuer might be renamed
            under specific circumstances; in all other cases, this state fails.

    leaf_not_after_behavior
        Behavior of a leaf's ``NotAfter`` field during issuance when it exceeds the issuer's validity.
        Valid options:

        * ``err``: Error, unless during CA/ACME issuance. (default)
        * ``always_enforce_err``: Error, including during CA/ACME issuance. (Vault 1.18.2+ only)
        * ``truncate``: Silently truncate the requested NotAfter to that of the issuer.
        * ``permit``: Allow signed certificate validities to exceed that of the issuer.

    usage
        Allowed usages for this issuer. Valid options are:

        * ``read-only`` - to allow this issuer to be read; implicit; always allowed;
        * ``issuing-certificates`` - to allow this issuer to be used for issuing other certificates;
        * ``crl-signing`` -  to allow this issuer to be used for signing CRLs.
          This is separate from the CRLSign KeyUsage on the x509 certificate, but this usage cannot be set
          unless that KeyUsage is allowed on the x509 certificate;
        * ``ocsp-signing`` -  to allow this issuer to be used for signing OCSP responses.

    revocation_signature_algorithm
        Which signature algorithm to use when building CRLs.
        See Go's `x509.SignatureAlgorithm <https://pkg.go.dev/crypto/x509#SignatureAlgorithm>`__ constant for possible values.
        Default (empty string) is to autoselect.

    aia_urls
        Specifies the URL values for the Issuing Certificate field as an array.

    crl_endpoints
        Specifies the URL values for the CRL Distribution Points field as an array.

    delta_crl_endpoints
        (Requires Vault 1.20+ or OpenBao)
        Specifies the URL values for the Delta CRL Distribution Points field.
        This can be an array or a comma-separated string list.

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as an array.

    aia_url_templating
        Render ``aia_urls``/``crl_endpoints``/``ocsp_servers``/``delta_crl_endpoints`` as templates.
        Supported variables: ``{{issuer_id}}``, ``{{cluster_path}}``, ``{{cluster_aia_path}}``.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """

    try:
        _validate_ttl_params(
            days_valid * 86400,
            days_remaining * 86400,
            not_after,
            ttl_param="days_valid",
            ttl_remaining_param="days_remaining",
        )
    except SaltInvocationError as err:
        return {"name": name, "result": False, "comment": str(err), "changes": {}}

    def check_cert(current, *, rotate_key, replace_key):
        urls = _get_urls(None, mount=mount)
        cert_changes, url_ext_drift = pki.check_root_issuer_for_changes(
            "".join(current["ca_chain"]),
            alt_names=alt_names,
            common_name=name,
            country=country,
            days_remaining=days_remaining,
            days_valid=days_valid,
            exclude_cn_from_sans=exclude_cn_from_sans,
            excluded_alt_names=excluded_alt_names,
            key_usage=key_usage,
            locality=locality,
            max_path_length=max_path_length,
            not_after=not_after,
            not_before_duration=not_before_duration,
            organization=organization,
            ou=ou,
            permitted_alt_names=permitted_alt_names,
            postal_code=postal_code,
            province=province,
            replace_key=replace_key,
            rotate_key=rotate_key,
            serial_number=serial_number,
            signature_bits=signature_bits,
            street_address=street_address,
            urls=urls,
        )
        notes = []
        if url_ext_drift:
            # URL-derived extensions don't trigger a rotation, but their drift
            # (or our inability to verify them) should be reported.
            if urls is None:
                notes.append(URL_EXTS_UNVERIFIED_NOTE.format(mount=mount))
            else:
                notes.append(
                    "The issuer certificate's embedded AIA-related URLs do not match "
                    "the mount's URL configuration. They will converge on the next rotation"
                )
        return cert_changes, notes

    def generate(key_ref):
        expiry = not_after
        if expiry is None:
            not_after_dt = datetime.now(tz=timezone.utc) + timedelta(days=days_valid)
            expiry = not_after_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        dns_sans, ip_sans, uri_sans, other_sans = pki.split_sans(pki.norm_sans(alt_names or []))

        dns_nc_allowed = email_nc_allowed = ip_nc_allowed = uri_nc_allowed = None
        if permitted_alt_names is not None:
            dns_nc_allowed, email_nc_allowed, ip_nc_allowed, uri_nc_allowed = (
                pki.split_name_constraints(
                    pki.norm_sans(permitted_alt_names or [], allow_other_name=False)
                )
            )
        dns_nc_denied = email_nc_denied = ip_nc_denied = uri_nc_denied = None
        if excluded_alt_names is not None:
            dns_nc_denied, email_nc_denied, ip_nc_denied, uri_nc_denied = (
                pki.split_name_constraints(
                    pki.norm_sans(excluded_alt_names or [], allow_other_name=False)
                )
            )

        res = __salt__["vault_pki.generate_root"](
            common_name=name,
            mount=mount,
            key_type="existing",
            key_ref=key_ref,
            alt_names=dns_sans and ",".join(dns_sans) or None,
            ip_sans=ip_sans and ",".join(ip_sans) or None,
            uri_sans=uri_sans and ",".join(uri_sans) or None,
            other_sans=other_sans and ",".join(other_sans) or None,
            exclude_cn_from_sans=exclude_cn_from_sans,
            max_path_length=max_path_length,
            key_usage=key_usage,
            permitted_dns_domains=dns_nc_allowed,
            excluded_dns_domains=dns_nc_denied,
            permitted_ip_ranges=ip_nc_allowed,
            excluded_ip_ranges=ip_nc_denied,
            permitted_email_addresses=email_nc_allowed,
            excluded_email_addresses=email_nc_denied,
            permitted_uri_domains=uri_nc_allowed,
            excluded_uri_domains=uri_nc_denied,
            ou=ou,
            organization=organization,
            country=country,
            locality=locality,
            province=province,
            street_address=street_address,
            postal_code=postal_code,
            serial_number=serial_number,
            signature_bits=signature_bits,
            not_before_duration=not_before_duration,
            not_after=expiry,
        )
        return res["issuer_id"], {}

    return _default_issuer_managed(
        name,
        kind="Root CA",
        mount=mount,
        issuer_config={
            "issuer_name": issuer_name,
            "leaf_not_after_behavior": leaf_not_after_behavior,
            "usage": usage,
            "revocation_signature_algorithm": revocation_signature_algorithm,
            "aia_urls": aia_urls,
            "crl_endpoints": crl_endpoints,
            "delta_crl_endpoints": delta_crl_endpoints,
            "ocsp_servers": ocsp_servers,
            "aia_url_templating": aia_url_templating,
        },
        check_cert=check_cert,
        generate=generate,
        key_ref=key_ref,
        rotate_key=rotate_key,
        key_type=key_type,
        key_algo=key_algo,
        key_bits=key_bits,
        managed_key_name=managed_key_name,
        managed_key_id=managed_key_id,
        allow_premature_rotation=bool(allow_premature_rotation),
    )


def _default_issuer_managed(  # pylint: disable=too-many-statements,too-many-locals
    name,
    *,
    kind,
    mount,
    issuer_config,
    check_cert,
    generate,
    key_ref,
    rotate_key,
    key_type,
    key_algo,
    key_bits,
    managed_key_name,
    managed_key_id,
    allow_premature_rotation=None,
    imports_cert=False,
    issuance_blocker=None,
):
    """
    Shared implementation for managing the default issuer of a mount,
    backing ``intermediate_issuer_managed`` and ``root_issuer_managed``.
    Parameters that are specific to this function:

    kind
        Human-readable issuer kind for change reports, e.g. ``Root CA``.

    issuer_config
        Mapping of all issuer configuration parameters (``issuer_name``, ``usage``, ...),
        as accepted by ``_check_issuer_config_changes``.

    check_cert
        Callback checking the current default issuer's certificate against the desired state.
        Receives the current issuer info and the effective ``rotate_key``/``replace_key``
        values, returns a tuple of (certificate changes, notes to append to the comment).

    generate
        Callback generating the new issuer certificate. Receives the reference of the
        key to (re)use, returns a tuple of (new issuer_id, changes to merge into the report).

    allow_premature_rotation
        When a boolean, refuse to rotate an existing issuer certificate unless true
        or the rotation is caused by expiry. When None, always rotate when necessary.

    imports_cert
        Whether ``generate`` imports certificates, i.e. reports an ``imported`` list.
        Only used for test mode reports.

    issuance_blocker
        Optional message describing why generating a new certificate is
        predetermined to fail remotely. Fails the state - even in test mode -
        if a rotation (or creation) turns out to be required. Otherwise,
        the message is appended to the comment as a note.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": f"{kind} issuer is present as specified",
        "changes": {},
    }
    changes: dict[str, typing.Any] = {}
    cert_affected = issuer_needs_update = replace_key = refused_to_rotate = cert_rotated = False
    issuer_id = key_id = None
    msg, notes = [], []
    kind_lc = kind[0].lower() + kind[1:]  # lowercase for refusals
    # We can skip issuer updates during creation if none of the params are specified
    issuer_is_managed = any(val is not None for val in issuer_config.values())
    issuer_name = issuer_config.pop("issuer_name")

    # Handle issuer changes separately from applying them because cert rotation causes implicit changes.
    issuer_changes, issuer_rotation_effects, recover_fail_changes = {}, {}, {}
    # Unmanaged, non-default configs of current issuer that we try to apply to a rotated issuer
    recover_from_cur = {}

    try:
        key_type = hlp.in_vals(("internal", "exported", "kms", None), key_type=key_type)
        if key_ref is not None:
            key_type = "existing"
            rotate_key = False
        if not (current := __salt__["vault_pki.read_issuer"](mount=mount)):
            changes["created"] = {
                "issuer_id": "<TBD>",
                "issuer_name": issuer_name,
                "CN": name,
                "key_id": "<TBD>",
            }
        else:
            issuer_id = current["issuer_id"]
            if key_ref is None:
                key_ref = current.get("key_id")
                if key_ref is None:  # pragma: no cover
                    raise CommandExecutionError("Default issuer key_id not set")
            else:
                key_id = __salt__["vault_pki.get_key_id"](key_ref, mount=mount)
                replace_key = current["key_id"] != key_id

            cert_changes, notes = check_cert(
                current, rotate_key=rotate_key, replace_key=replace_key
            )
            if cert_changes:
                changes["cert"], cert_affected = cert_changes, True
                cert_rotated = cert_affected

            issuer_triggers, issuer_rotation_effects, recover_from_cur, recover_fail_changes = (
                _check_issuer_config_changes(
                    current,
                    cert_affected,
                    **issuer_config,
                    issuer_name=issuer_name,
                    rotate_key=rotate_key,
                    replace_key=replace_key,
                )
            )
            issuer_needs_update, issuer_changes = (
                bool(issuer_triggers),
                issuer_triggers | issuer_rotation_effects,
            )

        if issuance_blocker and current is not None and not cert_affected:
            # No new certificate is currently required, so only warn.
            notes.append(issuance_blocker)

        if not (changes or issuer_changes):
            return _ret(ret, notes=notes)

        if (
            allow_premature_rotation is not None
            and not allow_premature_rotation
            and current is not None
            and cert_affected
        ):
            if refused_to_rotate := "expiration" not in changes["cert"]:
                cert_rotated = False
                # We report these changes because we don't preserve them during rotation, which is not happening.
                issuer_changes = {
                    k: v for k, v in issuer_changes.items() if k not in issuer_rotation_effects
                }

        if issuance_blocker and not refused_to_rotate and (current is None or cert_affected):
            # A new certificate is required, but generating it is predetermined
            # to fail remotely. Report this even in test mode.
            ret["result"] = False
            ret["changes"].update(changes)
            return _ret(ret, issuance_blocker, notes)

        # Ensure the issuer name is not taken before going any further
        if (
            issuer_name is not None
            and (current is None or current["issuer_name"] != issuer_name)
            and (name_collision := __salt__["vault_pki.read_issuer"](issuer_name, mount=mount))
        ):
            if current is None or cert_affected or current["issuer_name"]:
                # Unlikely to be an artifact of update_issuer causing an exception after rotation
                raise CommandExecutionError(
                    f"Another issuer with name '{issuer_name}' exists on mount '{mount}' "
                    f"(issuer_id: {name_collision['issuer_id']})"
                )
            # Assume this is an artifact from a previous run having failed to rename the old issuer and try again.
            log.warning(
                "Another issuer with name '%s' exists on mount '%s' (issuer_id: %s). "
                "Renaming it since it's likely an artifact from a previous failed run",
                issuer_name,
                mount,
                name_collision["issuer_id"],
            )
            if not (
                old_changes := _rotate_out(name_collision, issuer_name, mount)
            ):  # pragma: no cover
                raise CommandExecutionError(  # defensive coding: names must match and the update call raises
                    f"Another issuer with name '{issuer_name}' exists on mount '{mount}' "
                    f"(issuer_id: {name_collision['issuer_id']}). Tried renaming it, but somehow failed."
                )
            ret["changes"]["old_issuer"] = old_changes

        if __opts__["test"]:
            ret["result"] = False if refused_to_rotate else None
            if issuer_changes:
                changes["issuer"] = issuer_changes

            if refused_to_rotate:
                msg.append(
                    f"Would have refused to rotate {kind_lc} certificate. "
                    "Set `allow_premature_rotation=true` to proceed with the rotation"
                )
            elif current is None or cert_affected:
                msg.append(
                    f"{kind} certificate would have been {'rotated' if current else 'created'}"
                )
                if imports_cert:
                    changes["imported"] = ["<TBD>"]

            if current is None or issuer_changes:
                msg.append(f"{kind} issuer would have been {'updated' if current else 'created'}")

            if current is not None and cert_affected:
                changes["issuer_id"] = {"old": current["issuer_id"], "new": "<TBD>"}
                if old_changes := _rotate_out(current, issuer_name, mount):
                    changes["old_issuer"] = old_changes
                if rotate_key or replace_key:
                    changes["key_id"] = {"old": current["key_id"], "new": "<TBD>"}

            return _ret(ret, msg, notes, changes=changes)

        if refused_to_rotate:
            msg.append(
                f"Refused to rotate {kind_lc} certificate. "
                "Set `allow_premature_rotation=true` to proceed with the rotation"
            )
            ret["changes"]["cert"] = changes["cert"]
            ret["changes"]["issuer_id"] = {"old": current["issuer_id"], "new": "<TBD>"}
            if old_changes := _rotate_out(current, issuer_name, mount, test=True):
                ret["changes"]["old_issuer"] = old_changes
            if rotate_key or replace_key:
                ret["changes"]["key_id"] = {"old": current["key_id"], "new": "<TBD>"}

        elif current is None or cert_affected:
            if key_ref is None or rotate_key:
                key_ref = key_id = __salt__["vault_pki.generate_key"](
                    key_type or "internal",
                    key_algo=key_algo,
                    key_bits=key_bits,
                    managed_key_name=managed_key_name,
                    managed_key_id=managed_key_id,
                    mount=mount,
                )["key_id"]

            issuer_id, gen_changes = generate(key_ref)
            msg.append(f"Generated issuer `{issuer_id}`")
            ret["changes"].update(gen_changes)

            try:
                __salt__["vault_pki.set_default_issuer"](issuer_id, mount=mount)
            except CommandExecutionError as err:
                ret["result"] = False
                if not gen_changes:
                    ret["changes"]["generated"] = issuer_id
                msg.append(f"Failed to set `{issuer_id}` as default issuer: {err}")
                return _ret(ret, msg, notes)

            if current is not None:
                ret["changes"]["issuer_id"] = {"old": current["issuer_id"], "new": issuer_id}
                # When we rotate a named issuer, we need to rename the previous one since names must be unique
                if old_changes := _rotate_out(current, issuer_name, mount):
                    ret["changes"]["old_issuer"] = old_changes

                # Correctly report new subjectKeyIdentifier, it's "<TBD>" right now
                if rotate_key or replace_key:
                    changes = _report_ski(changes, mount=mount)
                    key_id = key_id or __salt__["vault_pki.get_key_id"](key_ref, mount=mount)
                    ret["changes"]["key_id"] = {"old": current["key_id"], "new": key_id}
                ret["changes"]["cert"] = changes["cert"]
            msg.append(f"{kind} certificate has been {'rotated' if current else 'created'}")

        if (
            # Run when we have a fresh issuer and need to apply config.
            # Would be unnecessary when all equal the defaults, but that's too specific to save one request.
            (current is None and issuer_is_managed)
            # Of course run when we need to apply config changes.
            or issuer_needs_update
            # Also run when we DID rotate (not denied) and need to re-apply and/or recover config.
            # Would be unnecessary when all managed params equal the defaults, but that's too specific to save one request.
            or (cert_rotated and (issuer_is_managed or recover_from_cur))
        ):
            try:
                __salt__["vault_pki.update_issuer"](
                    ref=issuer_id,
                    name=issuer_name,
                    mount=mount,
                    **(issuer_config | recover_from_cur),
                )
            except CommandExecutionError as err:
                if not recover_from_cur:
                    # We did not cause this for sure by trying to preserve unmanaged config.
                    raise
                fail_msg = (
                    "Failed to recover unspecified non-default issuer config from the previous default issuer:\n"
                    + "\n".join(f"  {k} (= `{v!r}`)" for k, v in recover_from_cur.items())
                    + f"\nReason: {err}"
                )
                log.warning(fail_msg)
                notes.append(fail_msg)
                ret["changes"]["issuer"] = recover_fail_changes
                # Retry setting managed config only, otherwise don't fail for trying to manage unmanaged config
                if issuer_is_managed:
                    __salt__["vault_pki.update_issuer"](
                        ref=issuer_id, name=issuer_name, mount=mount, **issuer_config
                    )

        # Reporting changes needs to be independent from applying issuer config (implicit changes)
        if current is None or issuer_changes:
            msg.append(f"{kind} issuer has been {'updated' if current else 'created'}")
        if current is not None and issuer_changes:
            ret["changes"].setdefault("issuer", {}).update(issuer_changes)

        if current is None:
            changes["created"]["issuer_id"] = issuer_id
            changes["created"]["key_id"] = key_id or __salt__["vault_pki.get_key_id"](
                key_ref, mount=mount
            )
            ret["changes"]["created"] = changes["created"]
        elif refused_to_rotate:
            ret["result"] = False

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        msg.append(f"Received an exception later: {err}" if msg else str(err))

    return _ret(ret, msg, notes)


def _check_issuer_config_changes(
    current,
    cert_affected: bool,
    *,
    issuer_name: str | None = None,
    leaf_not_after_behavior: str | None = None,
    usage: list[str] | str | None = None,
    revocation_signature_algorithm: str | None = None,
    aia_urls: list[str] | str | None = None,
    crl_endpoints: list[str] | str | None = None,
    delta_crl_endpoints: list[str] | str | None = None,
    ocsp_servers: list[str] | str | None = None,
    aia_url_templating: bool | None = None,
    rotate_key: bool,
    replace_key: bool,
) -> tuple[
    dict[str, typing.Any], dict[str, typing.Any], dict[str, typing.Any], dict[str, typing.Any]
]:
    """
    Check for issuer changes. Returns a tuple of (changes, report_only, rotation_recovery, rotation_changes).

    report_only contains changes like the changes dict, but they are a side effect of rotation.
    Affects an unspecified ``issuer_name`` and ``revocation_signature_algorithm`` when the key changes.

    rotation_recovery is a dict of unspecified parameters with their current values
    that differ from their defaults on the current issuer that should be recovered.
    We try not to touch issuer configuration that was unspecified, but they would be
    reset when we rotate the certificate, exactly the opposite of the usual contract.

    rotation_changes is a dict of changes to report when applying rotation_recovery is unsuccessful.
    """
    changes, report_only, rotation_recovery, rotation_changes = {}, {}, {}, {}

    # Unlike most other params, do not retain issuer_name when rotating.
    # We only rename non-default issuers when the default issuer is unnamed and has the correct cert.
    # That heuristic is for recovery when the update_issuer call crashes after successful rotation.
    # Otherwise, we fail because taking a name by force is highly unexpected.
    if issuer_name is not None and current["issuer_name"] != issuer_name:
        changes["issuer_name"] = {"old": current["issuer_name"], "new": issuer_name}
    elif issuer_name is None and cert_affected and current["issuer_name"]:
        report_only["issuer_name"] = {"old": current["issuer_name"], "new": ""}

    if "enable_aia_url_templating" not in current:
        # At least on OpenBao and older Vault releases, this is not reported if no URLs are set
        current["enable_aia_url_templating"] = False

    for vault_param, saltext_param, val, default in (
        ("leaf_not_after_behavior", "leaf_not_after_behavior", leaf_not_after_behavior, "err"),
        (
            "revocation_signature_algorithm",
            "revocation_signature_algorithm",
            revocation_signature_algorithm,
            None,
        ),
        ("enable_aia_url_templating", "aia_url_templating", aia_url_templating, False),
    ):
        if val is None:
            if cert_affected:
                # Try to preserve manual config during rotation
                if vault_param == "revocation_signature_algorithm":
                    # Here, the default and valid values depend on the key algo.
                    if replace_key or rotate_key:
                        # Don't recover when the key changes, or we risk breaking stuff.
                        report_only[saltext_param] = {
                            "old": current[vault_param],
                            "new": "<key default>",
                        }
                    else:
                        # Always recover when the key stays though, we don't know the default.
                        rotation_recovery[saltext_param] = current[vault_param]
                        rotation_changes[saltext_param] = {
                            "old": current[vault_param],
                            "new": "<key default>",
                        }
                elif current[vault_param] != default:
                    rotation_recovery[saltext_param] = current[vault_param]
                    rotation_changes[saltext_param] = {"old": current[vault_param], "new": default}
            continue
        if current[vault_param] != val:
            changes[saltext_param] = {"old": current[vault_param], "new": val}

    current_usage = set(hlp.deserialize_csl(current["usage"]))
    current_usage.add("read-only")  # always allowed, in case it's dropped from response
    default_usage = {
        "read-only",
        "issuing-certificates",
        "crl-signing",
        "ocsp-signing",
    }
    if usage is not None:
        wanted_usage = set(hlp.deserialize_csl(usage))
        wanted_usage.add("read-only")
        if current_usage != wanted_usage:
            change = {
                "added": list(sorted(wanted_usage - current_usage)),
                "removed": list(sorted(current_usage - wanted_usage)),
            }
            changes["usage"] = change
    elif cert_affected and current_usage != default_usage:
        rotation_recovery["usage"] = current["usage"]
        rotation_changes["usage"] = {
            "added": list(sorted(default_usage - current_usage)),
            "removed": list(sorted(current_usage - default_usage)),
        }

    for vault_param, saltext_param, val in (
        ("issuing_certificates", "aia_urls", hlp.deserialize_csl(aia_urls)),
        ("crl_distribution_points", "crl_endpoints", hlp.deserialize_csl(crl_endpoints)),
        (
            "delta_crl_distribution_points",
            "delta_crl_endpoints",
            hlp.deserialize_csl(delta_crl_endpoints),
        ),
        ("ocsp_servers", "ocsp_servers", hlp.deserialize_csl(ocsp_servers)),
    ):
        # At least on OpenBao and older Vault releases, none of these are reported if all are unset
        if vault_param not in current:
            current[vault_param] = []
        if val is None:
            if cert_affected and current[vault_param]:
                rotation_recovery[saltext_param] = current[vault_param]
                rotation_changes[saltext_param] = {
                    "added": [],
                    "removed": hlp.deserialize_csl(current[vault_param]),
                }
            continue
        if current[vault_param] != val:
            changes[saltext_param] = {
                "added": list(sorted(set(val) - set(current[vault_param]))),
                "removed": list(sorted(set(current[vault_param]) - set(val))),
            }
    return changes, report_only, rotation_recovery, rotation_changes


def _validate_ttl_params(
    ttl: int,
    ttl_remaining: int,
    not_after: str | None,
    *,
    ttl_param: str = "ttl",
    ttl_remaining_param: str = "ttl_remaining",
) -> None:
    """
    Ensure requested certificate validity parameters are consistent before
    creating anything, avoiding certificates that immediately require
    renewal or fail validation on subsequent runs.
    """
    if not_after is None:
        if ttl_remaining >= ttl:
            raise SaltInvocationError(
                f"The `{ttl_remaining_param}` cannot be larger than or equal to `{ttl_param}`."
            )
        return
    not_after_dt = pki._strptime_loose(not_after, "not_after")
    tolerance = timedelta(seconds=ttl_remaining)
    if not_after_dt < datetime.now(tz=timezone.utc) + tolerance:
        expires_in = not_after_dt - datetime.now(tz=timezone.utc)
        raise SaltInvocationError(
            f"The specified `not_after` undercuts `{ttl_remaining_param}`. Update or remove `not_after`. "
            + f"The certificate {hlp.pretty_td(expires_in, now=('expires', 'expired'))}, "
            + f"which is less than the tolerance of {hlp.pretty_td(tolerance)}"
        )


def _validate_issuance_cutoff(
    cutoff: datetime,
    cutoff_desc: str,
    not_after: str | None,
    remaining: int,
    remaining_param: str = "ttl_remaining",
) -> None:
    """
    Ensure a hard cutoff enforced during issuance does not conflict with the
    requested certificate lifecycle parameters. A statically requested expiry
    beyond the cutoff would be truncated silently, a renewal tolerance undercut
    by it would make issued certificates immediately due for renewal - both
    resulting in repeated changes that cannot converge.
    """
    if not_after is not None:
        if pki._strptime_loose(not_after, "not_after") > cutoff:
            raise SaltInvocationError(
                f"The specified `not_after` exceeds {cutoff_desc}, which enforces a hard cutoff "
                f"of {cutoff.strftime(pki.TIME_FMT)} during issuance. Reduce or remove `not_after`."
            )
        # The remaining tolerance is validated against `not_after` separately
        return
    if cutoff <= datetime.now(tz=timezone.utc) + timedelta(seconds=remaining):
        raise CommandExecutionError(
            f"The specified `{remaining_param}` is undercut by {cutoff_desc}, which enforces "
            f"a hard cutoff of {cutoff.strftime(pki.TIME_FMT)} during issuance. "
            "Certificates would be reissued during each run."
        )


def _split_file_kwargs(kwargs):
    file_args = {"show_changes": False}
    extra_args = {}
    for k, v in kwargs.items():
        if k in VALID_FILE_ARGS:
            file_args[k] = v
        else:
            extra_args[k] = v

    if "file_encoding" in file_args:
        file_args["encoding"] = file_args.pop("file_encoding")
    return file_args, extra_args


def _add_sub_state_run(ret, sub):
    sub["low"] = {
        "name": ret["name"],
        "state": "file",
        "__id__": __low__["__id__"],
        "fun": "managed",
    }
    ret.setdefault("sub_state_run", []).append(sub)


def _run_state(func, name, test=None, **kwargs):
    if test not in (None, True):  # pragma: no cover
        raise SaltInvocationError("test param can only be None or True")
    test = test or __opts__["test"]
    res = __salt__["state.single"](func, name, test=test, concurrent=True, **kwargs)
    if not isinstance(res, dict):
        raise CommandExecutionError(f"Failed running {func}: {res}")
    return res[next(iter(res))]


def _ret(ret, msg=None, notes=None, *, changes=None, sub=None):
    """
    Render the state comment from a list of messages and append supplementary
    notes, separated by blank lines. Without messages, keeps the current
    comment as the base.
    Also allows to overwrite changes and add a sub-staterun.
    Returns the state return dict for convenience.
    """
    if sub:
        _add_sub_state_run(ret, sub)
    if changes:
        ret["changes"].update(changes)
    if msg:
        ret["comment"] = ".\n".join(msg if isinstance(msg, list) else [msg]) + "."
    ret["comment"] += "".join(f"\n\nNote: {note}." for note in notes or ())
    return ret


def _check_file_ret(fret, ret, current):
    if fret["result"] is False:
        ret["result"] = False
        ret["comment"] = (
            f"Could not {'create' if not current else 'update'} file, see file.managed output"
        )
        ret["changes"] = {}
        return False
    return True


class LazyAIAContext:
    def __init__(self, issuer_id: str | None, mount: str):
        self.issuer_id = issuer_id
        self.mount = mount
        self.cluster_config: dict[str, typing.Any] | None = None

    def __getitem__(self, key: str) -> str:
        if key == "issuer_id" and self.issuer_id is not None:
            return self.issuer_id
        if key in ("cluster_path", "cluster_aia_path"):
            if self.cluster_config is None:
                self.cluster_config = __salt__["vault_pki.read_cluster_config"](mount=self.mount)
            if key == "cluster_path":
                return self.cluster_config["path"]
            return self.cluster_config["aia_path"]
        raise KeyError(key)


def _get_urls(issuer_info: Mapping[str, typing.Any] | None, mount: str) -> "pki.URLConfigs | None":
    url_config_keys = (
        "issuing_certificates",
        "crl_distribution_points",
        "delta_crl_distribution_points",
        "ocsp_servers",
    )
    enable_templating = (issuer_info or {}).get("enable_aia_url_templating", False)
    if issuer_info is None or not any(
        issuer_info.get(url_config) for url_config in url_config_keys
    ):
        try:
            # Mount default AIA URLs
            url_configs = __salt__["vault_pki.read_urls"](mount=mount)
        except CommandExecutionError as err:  # pragma: no cover
            if "PermissionDenied" not in str(err):
                raise
            log.warning(
                "Failed reading default AIA url config. Consider allowing read access to "
                "`%s/config/urls`. URL-derived certificate extensions cannot be verified without it.",
                mount,
            )
            return None
        # The mount default config reports `enable_templating`,
        # issuer-specific configuration `enable_aia_url_templating`.
        enable_templating = url_configs.get("enable_templating", False)
    else:
        # Issuer-specific AIA URLs
        url_configs = issuer_info

    urls: pki.URLConfigs | None = {
        url: hlp.deserialize_csl(url_configs.get(url, [])) for url in url_config_keys
    }
    if enable_templating:
        urls = _render_aia_templating(
            urls,
            issuer_id=issuer_info["issuer_id"] if issuer_info is not None else None,
            mount=mount,
        )
    return urls


def _render_aia_templating(
    urls: "pki.URLConfigs", *, issuer_id: str | None, mount: str
) -> "pki.URLConfigs | None":
    ctx = LazyAIAContext(issuer_id=issuer_id, mount=mount)

    def _sub_id(match):
        tgt = match.group(1).strip()
        return str(ctx[tgt])

    res = {}
    for conf, vals in urls.items():
        res[conf] = []
        for url in hlp.deserialize_csl(vals):
            try:
                rendered = re.sub(r"{{(issuer_id|cluster_(?:aia_)?path)}}", _sub_id, url)
            except KeyError:
                # If any template is invalid, all URLs are dropped - usual case: issuer_id referenced in root issuer
                return {}
            except CommandExecutionError as err:  # pragma: no cover
                if "PermissionDenied" not in str(err):
                    raise
                log.warning(
                    "Failed reading performance cluster config. Consider allowing read access to "
                    "`%s/config/cluster`. URL-derived certificate extensions cannot be verified without it.",
                    mount,
                )
                return None
            res[conf].append(rendered)
    return res


def _report_ski(changes: dict[str, typing.Any], mount: str) -> dict[str, typing.Any]:
    # Correctly report new subjectKeyIdentifier, it's "<TBD>" right now
    new_issuer = __salt__["vault_pki.read_issuer"](mount=mount)
    new_ski = pki.get_ski(new_issuer["certificate"])
    if "subjectKeyIdentifier" in changes["cert"]["extensions"]["added"]:  # pragma: no cover
        changes["cert"]["extensions"]["added"]["subjectKeyIdentifier"]["value"] = new_ski
    else:
        changes["cert"]["extensions"]["changed"]["subjectKeyIdentifier"]["value"]["new"] = new_ski
    return changes


def _rotate_out(issuer_info, issuer_name, mount, *, test=None):
    test = test or __opts__["test"]
    upd_params, rename_changes = {}, {}
    if issuer_name and issuer_info["issuer_name"] == issuer_name:
        upd_params["name"] = f"{issuer_info['issuer_name']}-{'<TBD>' if test else int(time.time())}"
        rename_changes["issuer_name"] = {
            "old": issuer_info["issuer_name"],
            "new": upd_params["name"],
        }
    if "issuing-certificates" in issuer_info["usage"]:
        if not test:
            upd_params["usage"] = [
                usage
                for usage in hlp.deserialize_csl(issuer_info["usage"])
                if usage != "issuing-certificates"
            ]
        rename_changes["usage"] = {"removed": ["issuing-certificates"]}
    if upd_params and not test:
        __salt__["vault_pki.update_issuer"](ref=issuer_info["issuer_id"], **upd_params, mount=mount)
    if rename_changes:
        rename_changes["issuer_id"] = issuer_info["issuer_id"]
    return rename_changes
