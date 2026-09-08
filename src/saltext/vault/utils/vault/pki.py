"""
Vault PKI helpers

.. versionadded:: 1.1.0
"""

import json
import logging
import typing
from collections.abc import Mapping
from collections.abc import Sequence
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import salt.utils.x509 as x509util
from cryptography import x509 as cx509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.extensions import ExtensionTypeVar
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from salt.utils import dictdiffer as dd
from salt.utils import immutabletypes

from saltext.vault.utils.vault.helpers import deserialize_csl
from saltext.vault.utils.vault.helpers import filter_unset
from saltext.vault.utils.vault.helpers import timestring_map

log = logging.getLogger(__name__)

Privkey: typing.TypeAlias = (
    ec.EllipticCurvePrivateKey
    | ed448.Ed448PrivateKey
    | ed25519.Ed25519PrivateKey
    | rsa.RSAPrivateKey
)

Pubkey: typing.TypeAlias = (
    ec.EllipticCurvePublicKey | ed448.Ed448PublicKey | ed25519.Ed25519PublicKey | rsa.RSAPublicKey
)

Encoding: typing.TypeAlias = (
    typing.Literal["pem"]
    | typing.Literal["pkcs7_pem"]
    | typing.Literal["der"]
    | typing.Literal["pkcs7_der"]
)

ExtensionChange: typing.TypeAlias = (
    typing.Literal["added"] | typing.Literal["changed"] | typing.Literal["removed"]
)
ExtensionListChange: typing.TypeAlias = typing.Literal["added"] | typing.Literal["removed"]

URLConfigs: typing.TypeAlias = Mapping[
    typing.Literal["issuing_certificates"]
    | typing.Literal["crl_distribution_points"]
    | typing.Literal["delta_crl_distribution_points"]
    | typing.Literal["ocsp_servers"],
    list[str],
]

SUPPORTED_SAN_TYPES = ("DNS", "EMAIL", "IP", "URI")
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"

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
    "SERIALNUMBER",
    "basicConstraints",
    "certificatePolicies",
    "extendedKeyUsage",
    "inhibitAnyPolicy",
    "keyUsage",
    "nameConstraints",
    "noCheck",
    "policyConstraints",
    "subjectAltName",
    "subjectKeyIdentifier",
    "tlsfeature",
)

# https://github.com/golang/go/blob/72aa6db7943024b48c4d41c1fbc32b57b9fa036e/src/crypto/x509/x509.go
EXTENDED_KEY_USAGE_OID = immutabletypes.freeze(
    {
        "Any": cx509.ObjectIdentifier("2.5.29.37.0"),
        "ServerAuth": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
        "ClientAuth": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
        "CodeSigning": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.3"),
        "EmailProtection": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.4"),
        "IPSECEndSystem": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.5"),
        "IPSECTunnel": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.6"),
        "IPSECUser": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.7"),
        "TimeStamping": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.8"),
        "OCSPSigning": cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.9"),
        "MicrosoftServerGatedCrypto": cx509.ObjectIdentifier("1.3.6.1.4.1.311.10.3.3"),
        "NetscapeServerGatedCrypto": cx509.ObjectIdentifier("2.16.840.1.113730.4.1"),
        "MicrosoftCommercialCodeSigning": cx509.ObjectIdentifier("1.3.6.1.4.1.311.2.1.22"),
        "MicrosoftKernelCodeSigning": cx509.ObjectIdentifier("1.3.6.1.4.1.311.61.1.1"),
    }
)

# Mostly same as x509util.NAME_ATTRS_OID, but SERIALNUMBER and UID are swapped because that's how Vault encodes it
NAME_ATTRS_OID = immutabletypes.freeze(
    {
        "C": cx509.NameOID.COUNTRY_NAME,
        "ST": cx509.NameOID.STATE_OR_PROVINCE_NAME,
        "L": cx509.NameOID.LOCALITY_NAME,
        "STREET": cx509.NameOID.STREET_ADDRESS,
        "O": cx509.NameOID.ORGANIZATION_NAME,
        "OU": cx509.NameOID.ORGANIZATIONAL_UNIT_NAME,
        "CN": cx509.NameOID.COMMON_NAME,
        "MAIL": cx509.NameOID.EMAIL_ADDRESS,
        "SN": cx509.NameOID.SURNAME,
        "GN": cx509.NameOID.GIVEN_NAME,
        "SERIALNUMBER": cx509.NameOID.SERIAL_NUMBER,
        "UID": cx509.NameOID.USER_ID,
    }
)


def check_cert_for_changes(
    current: str,
    issuer: str,
    private_key: str | None,
    csr: str | None,
    encoding: Encoding = "pem",
    sign_verbatim: bool = False,
    *,
    alt_names: dict[str, str | list[str]] | list[str] | None,
    append_chain: list[cx509.Certificate] | None,
    common_name: str | None,
    exclude_cn_from_sans: bool,
    expire_tolerance: int | str | None,
    ext_key_usage: list[str] | str | None,
    ext_key_usage_oids: list[str] | str | None,
    key_usage: list[str] | str | None,
    not_after: str | None,
    private_key_passphrase: str | None,
    role_info: dict[str, typing.Any],
    serial_number: str | None,
    ttl: int,
    urls: URLConfigs,
    user_ids: list[str] | str | None,
    **kwargs,
) -> dict[str, typing.Any]:
    """
    Check whether an existing on-disk leaf certificate matches expected parameters.

    current
        Path of the existing certificate on disk.

    issuer
        Issuer certificate.

    private_key
        Path of the private key on disk/encoded private key.

    csr
        Path of the CSR on disk/encoded CSR.

    encoding
        Requested certificate encoding. Defaults to ``pem``.

    sign_verbatim
        Whether the ``sign-verbatim`` endpoint is used. Defaults to false.

    alt_names
        Requested Subject Alternative Names.

    append_chain
        List of certificates to append. Fails with ``der`` encoding.

    common_name
        Subject CN name attribute.

    exclude_cn_from_sans
        Whether the subject CN should be included in the SANs (either as ``email`` or ``dns`` type).
        Has no effect when ``sign_verbatim`` is true.

    expire_tolerance
        Otherwise called ``ttl_remaining``, minimum TTL to allow
        before requesting a fresh certificate.

    ext_key_usage
        When ``sign_verbatim`` is true, default Extended Key Usages if the CSR carries none.

    ext_key_usage_oids
        When ``sign_verbatim`` is true, additional OIDs for the default Extended Key Usages if the CSR carries none.

    key_usage
        When ``sign_verbatim`` is true, default Key Usages if the CSR carries none.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``ttl`` is ignored.

    private_key_passphrase
        Passphrase for ``private_key``

    role_info
        Return value of :py:func:`read_role <saltext.vault.modules.vault_pki.read_role>`.

    serial_number
        Single value for the **subject** SERIALNUMBER (OID: 2.5.4.5) name attribute (NOT the certificate's serial number!).

    ttl
        Requested Time To Live, already normalized to integer-valued seconds.

    urls
        Dictionary of issuer/mount-default authority URLs, which end up in the AuthorityInformationAccess,
        CRLDistributionPoints and FreshestCRL extensions.

    user_ids
        List of User ID (``UID``) subject attributes.
        Each one is added to the generated CSR's subject Name as a distinct RDN.

    kwargs
        All other kwargs passed to the cert signing endpoint or as CSR generation params.
    """
    changes: dict[str, typing.Any] = {}
    expire_tolerance = expire_tolerance or 0

    try:
        cert, current_encoding, current_chain = _load_cert_and_chain(current)
    except CommandExecutionError as err:  # pragma: no cover
        if "Invalid cert bundle" not in str(err):
            raise
        changes["replaced"] = True
        return changes
    except SaltInvocationError as err:
        if any(
            (
                "Could not deserialize binary data" in str(err),
                "Could not load PEM-encoded" in str(err),
            )
        ):
            changes["replaced"] = True
            return changes
        raise

    if not _compare_ca_chain(
        current_chain or [], append_chain or [], unordered="pkcs7" in current_encoding
    ):
        changes["ca_chain"] = True

    if encoding != current_encoding:
        changes["encoding"] = {
            "old": current_encoding,
            "new": encoding,
        }

    ca = x509util.load_cert(issuer)
    csr_loaded: cx509.CertificateSigningRequest | None = None
    pk_loaded: Privkey | None = None

    if private_key:
        pk_loaded: Privkey = x509util.load_privkey(private_key, passphrase=private_key_passphrase)
        pubkey = pk_loaded.public_key()
    else:
        csr_loaded: cx509.CertificateSigningRequest = x509util.load_csr(csr)
        pubkey = csr_loaded.public_key()

    changes.update(
        _compare_cert_signing(
            current=cert,
            signing_ca=ca,
            public_key=pubkey,
        )
    )

    # CN is synced by the execution module.
    csr_args, _ = split_csr_kwargs(kwargs)
    if common_name is not None:
        if not csr_loaded:
            csr_args["CN"] = common_name
        elif role_info.get(
            "use_csr_common_name", True
        ) and csr_loaded.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"]):
            log.warning(
                "Ignoring passed `common_name`: Received a pre-generated CSR with CN and "
                "the role does not specify use_csr_common_name=false"
            )
    elif sign_verbatim or not role_info.get("require_cn", True):
        csr_args.pop("CN", None)
    elif (
        csr_loaded
        and role_info.get("use_csr_common_name", True)
        and csr_loaded.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])
    ):
        pass
    else:
        raise CommandExecutionError(
            "`common_name` is required: Not signing verbatim and role does not specify require_cn=false"
            + (" and passed csr does not specify CN" if csr_loaded else "")
        )

    if csr_loaded and csr_args:
        log.warning(
            "A pre-generated CSR was passed, but received CSR generation arguments. Ignoring: %s",
            ", ".join(f"`{arg}`" for arg in csr_args),
        )
        csr_args = {}

    # subjectAltName is always synced with alt_names by the execution module.
    # We currently rely on a workaround for otherName SANs, which would break if we passed them to create_csr.
    # Ensure the result is the same.
    csr_args.pop("subjectAltName", None)

    not_before_duration = timestring_map(role_info.get("not_before_duration", 30))
    if sign_verbatim:
        builder = _build_verbatim_cert(
            ca,
            alt_names=alt_names,
            csr=csr_loaded,
            ext_key_usage=ext_key_usage,
            ext_key_usage_oids=ext_key_usage_oids,
            key_usage=key_usage,
            not_after=not_after,
            not_before_duration=not_before_duration,
            private_key=pk_loaded,
            serial_number=serial_number,
            ttl=ttl,
            urls=urls,
            user_ids=user_ids,
            **csr_args,
        )
    else:
        builder = _build_regular_cert(
            ca,
            alt_names=alt_names,
            common_name=common_name,
            csr=csr_loaded,
            exclude_cn_from_sans=exclude_cn_from_sans,
            not_after=not_after,
            not_before_duration=not_before_duration,
            private_key=pk_loaded,
            role_info=role_info,
            serial_number=serial_number,
            ttl=ttl,
            urls=urls,
            user_ids=user_ids,
            **csr_args,
        )

    # Check if certificate should be renewed due to close to expiration
    try:
        curr_not_valid_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover
        curr_not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if curr_not_valid_after < datetime.now(timezone.utc) + timedelta(
        seconds=timestring_map(expire_tolerance, cast=int)
    ):
        changes["expiration"] = {
            "expire_in": (curr_not_valid_after - datetime.now(timezone.utc)).total_seconds(),
            "toleration": timestring_map(expire_tolerance, cast=int),
        }

    if _getattr_safe(builder, "_subject_name") != cert.subject:
        changes["subject_name"] = {
            "old": cert.subject.rfc4514_string(),
            "new": _getattr_safe(builder, "_subject_name").rfc4514_string(),
        }

    ext_changes = _compare_exts(cert, builder)
    if any(ext_changes.values()):
        changes["extensions"] = ext_changes
    return changes


def _build_regular_cert(
    issuer: cx509.Certificate,
    *,
    alt_names: dict[str, str | list[str]] | list[str] | None,
    common_name: str | None,
    csr: cx509.CertificateSigningRequest | None,
    exclude_cn_from_sans: bool,
    not_after: str | None,
    not_before_duration: str | int,
    private_key: Privkey | None,
    role_info: dict[str, typing.Any],
    serial_number: str | None,
    ttl: int,
    urls: URLConfigs,
    user_ids: list[str] | str | None,
    **csr_args,
) -> cx509.CertificateBuilder:
    if private_key is not None:
        public_key = private_key.public_key()
        csr_eff, _ = typing.cast(
            tuple[cx509.CertificateSigningRequestBuilder, typing.Any],
            x509util.build_csr(private_key, **csr_args),
        )
    elif csr is not None:
        csr_eff = csr
        public_key = csr.public_key()
    else:  # pragma: no cover
        raise TypeError("Either csr or private_key must be set")
    builder = cx509.CertificateBuilder(public_key=public_key)

    try:
        csr_subject = csr_eff.subject  # ty: ignore[unresolved-attribute]
    except AttributeError:
        # CSRBuilder (created by x509util.build_csr())
        csr_subject = _getattr_safe(csr_eff, "_subject_name")

    if role_info.get("use_csr_common_name", True):
        # NOTE: There is also `serial_number_source` (`json-csr`, `json`)
        try:
            common_name = csr_subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)[
                0
            ].value  # ty: ignore[invalid-assignment]
        except IndexError:
            pass
    subject_dn = _build_subject(
        country=role_info.get("country"),
        province=role_info.get("province"),
        locality=role_info.get("locality"),
        street_address=role_info.get("street_address"),
        postal_code=role_info.get("postal_code"),
        organization=role_info.get("organization"),
        ou=role_info.get("ou"),
        common_name=common_name,
        serial_number=serial_number,
        user_ids=deserialize_csl(user_ids),
    )
    builder = builder.subject_name(subject_dn).issuer_name(issuer.subject)

    # Validity
    not_before = datetime.now(tz=timezone.utc) - timedelta(
        seconds=timestring_map(not_before_duration)
    )
    not_after_dt = _strptime(not_after, "not_after") or (
        datetime.now(tz=timezone.utc) + timedelta(seconds=ttl)
    )
    builder = builder.not_valid_before(not_before).not_valid_after(not_after_dt)

    try:
        csr_exts: cx509.Extensions = csr_eff.extensions  # ty: ignore[unresolved-attribute]
    except AttributeError:
        csr_exts = cx509.Extensions(_getattr_safe(csr_eff, "_extensions"))

    # subjectAlternativeName
    builder = _add_sans(
        builder,
        common_name,
        alt_names,
        exclude_cn_from_sans=exclude_cn_from_sans,
        # csr_exts should only be passed when we received an actual csr.
        # Our on-the-fly CSR for change checking intentionally does not contain a SAN extension to enable our otherName workaround,
        # but Vault ignores `alt_names` when a CSR is passed and the role does not set use_csr_sans to false.
        # Once we don't need the workaround anymore and can include a SAN ext, `csr and` can be removed here.
        csr_exts=csr_exts if csr and role_info.get("use_csr_sans", True) else None,
    )

    # basicConstraints
    if role_info.get("basic_constraints_valid_for_non_ca"):
        builder = builder.add_extension(
            cx509.BasicConstraints(False, None),
            critical=True,
        )

    # keyUsage
    # Role always reports defaults. Setting key_usage to an empty list drops the extension
    builder = _add_key_usage_non_ca(builder, deserialize_csl(role_info.get("key_usage") or []))

    # extKeyUsage
    eku_names = deserialize_csl(role_info.get("ext_key_usage") or [])
    if role_info.get("server_flag", True):
        eku_names.append("serverauth")
    if role_info.get("client_flag", True):
        eku_names.append("clientauth")
    if role_info.get("code_signing_flag"):
        eku_names.append("codesigning")
    if role_info.get("email_protection_flag"):
        eku_names.append("emailprotection")
    builder = _add_ekus(
        builder, eku_names, deserialize_csl(role_info.get("ext_key_usage_oids", []))
    )

    # certificatePolicies
    builder = _add_certificate_policies(
        builder, deserialize_csl(role_info.get("policy_identifiers") or [])
    )

    # AuthorityInformationAccess/CRLDistributionPoints/FreshestCRL
    builder = _add_authority_info(builder, urls)

    # SubjectKeyIdentifier
    builder = _add_ski(builder, public_key)

    # AuthorityKeyIdentifier
    builder = _add_aki(builder, issuer=issuer)

    return builder


def _build_verbatim_cert(
    issuer: cx509.Certificate,
    *,
    # Not actually a parameter for sign-verbatim, but the execution module mimics it when a private_key is passed
    alt_names: dict[str, str | list[str]] | list[str] | None,
    csr: cx509.CertificateSigningRequest | None,
    ext_key_usage: list[str] | str | None,
    ext_key_usage_oids: list[str] | str | None,
    key_usage: list[str] | str | None,
    not_after: str | None,
    not_before_duration: str | int,
    private_key: Privkey | None,
    serial_number: str | None,
    ttl: int,
    urls: URLConfigs,
    user_ids: list[str] | str | None,
    **csr_args,
) -> cx509.CertificateBuilder:
    if private_key is not None:
        public_key = private_key.public_key()
        # Leaving alt_names out here to not break otherName workaround.
        # SANs are added as an extension explicitly below.
        csr_args = sync_verbatim_csr_subject(
            csr_args, user_ids=user_ids, serial_number=serial_number
        )
        csr_eff, _ = typing.cast(
            tuple[cx509.CertificateSigningRequestBuilder, typing.Any],
            x509util.build_csr(private_key, **csr_args),
        )
    elif csr is not None:
        csr_eff = csr
        public_key = csr.public_key()
    else:  # pragma: no cover
        raise TypeError("Either csr or private_key must be set")

    # Subject Name
    try:
        csr_subject = csr_eff.subject  # ty: ignore[unresolved-attribute]
    except AttributeError:
        # CSRBuilder (created by x509util.build_csr())
        csr_subject = _getattr_safe(csr_eff, "_subject_name")

    builder = (
        cx509.CertificateBuilder(public_key=public_key)
        .subject_name(csr_subject)
        .issuer_name(issuer.subject)
    )

    # Validity
    not_before = datetime.now(tz=timezone.utc) - timedelta(
        seconds=timestring_map(not_before_duration)
    )
    not_after_dt = _strptime(not_after, "not_after") or (
        datetime.now(tz=timezone.utc) + timedelta(seconds=ttl)
    )
    builder = builder.not_valid_before(not_before).not_valid_after(not_after_dt)

    # Verbatim copy extensions from CSR
    try:
        csr_exts: cx509.Extensions = csr_eff.extensions  # ty: ignore[unresolved-attribute]
    except AttributeError:
        csr_exts = cx509.Extensions(_getattr_safe(csr_eff, "_extensions"))
    for ext in csr_exts:
        builder = builder.add_extension(ext.value, ext.critical)

    try:
        csr_exts.get_extension_for_class(cx509.KeyUsage)
    except cx509.ExtensionNotFound:
        builder = _add_key_usage_non_ca(
            builder,
            (
                deserialize_csl(key_usage)
                if key_usage is not None
                else ["digitalsignature", "keyagreement", "keyencipherment"]
            ),
        )

    # Default ExtendedKeyUsage
    try:
        csr_exts.get_extension_for_class(cx509.ExtendedKeyUsage)
    except cx509.ExtensionNotFound:
        builder = _add_ekus(
            builder, deserialize_csl(ext_key_usage or []), deserialize_csl(ext_key_usage_oids or [])
        )

    # SubjectAlternativeName simulation (for otherName workaround, this would actually be in the generated CSR)
    try:
        csr_exts.get_extension_for_class(cx509.SubjectAlternativeName)
    except cx509.ExtensionNotFound:
        builder = _add_sans(
            builder,
            None,
            alt_names,
            exclude_cn_from_sans=True,
            verbatim=True,
        )

    # AuthorityInformationAccess/CRLDistributionPoints/FreshestCRL
    builder = _add_authority_info(builder, urls)

    # Default SubjectKeyIdentifier
    try:
        csr_exts.get_extension_for_class(cx509.SubjectKeyIdentifier)
    except cx509.ExtensionNotFound:
        builder = _add_ski(builder, public_key)

    # AuthorityKeyIdentifier
    builder = _add_aki(builder, issuer=issuer)

    return builder


def _add_authority_info(builder: cx509.CertificateBuilder, urls):
    # AuthorityInformationAccess
    if urls.get("ocsp_servers") or urls.get("issuing_certificates"):
        descriptions = []
        for ocsp_server in urls.get("ocsp_servers") or []:
            descriptions.append({"OCSP": f"uri:{ocsp_server}"})
        for issuer in urls.get("issuing_certificates") or []:
            descriptions.append({"caIssuers": f"uri:{issuer}"})
        aia, _ = x509util._create_authority_info_access(descriptions)
        builder = builder.add_extension(aia, critical=False)

    # CRLDistributionPoints
    if urls.get("crl_distribution_points"):
        points = [{"fullname": f"uri:{point}"} for point in urls["crl_distribution_points"]]
        cdp, _ = x509util._create_crl_distribution_points(points)
        builder = builder.add_extension(cdp, critical=False)

    # FreshestCRL
    if urls.get("delta_crl_distribution_points"):
        points = [{"fullname": f"uri:{point}"} for point in urls["delta_crl_distribution_points"]]
        dcdp, _ = x509util._create_freshest_crl(points)
        builder = builder.add_extension(dcdp, critical=False)

    return builder


def _add_ski(builder, public_key):
    return builder.add_extension(
        cx509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )


@typing.overload
def _add_aki(
    builder: cx509.CertificateBuilder,
    *,
    issuer: cx509.Certificate,
): ...
@typing.overload
def _add_aki(
    builder: cx509.CertificateBuilder,
    *,
    public_key: CertificateIssuerPublicKeyTypes,
): ...
def _add_aki(
    builder: cx509.CertificateBuilder,
    *,
    issuer: cx509.Certificate | None = None,
    public_key: CertificateIssuerPublicKeyTypes | None = None,
):
    if issuer is None:
        aki = cx509.AuthorityKeyIdentifier.from_issuer_public_key(
            typing.cast(CertificateIssuerPublicKeyTypes, public_key)
        )
    else:
        try:
            aki = cx509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier).value
            )
        except cx509.ExtensionNotFound:
            aki = cx509.AuthorityKeyIdentifier.from_issuer_public_key(
                typing.cast(CertificateIssuerPublicKeyTypes, issuer.public_key())
            )
    builder = builder.add_extension(aki, critical=False)

    return builder


def _add_sans(
    builder: cx509.CertificateBuilder,
    common_name: str | None,
    alt_names: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
    *,
    exclude_cn_from_sans: bool,
    csr_exts: cx509.Extensions | None = None,
    verbatim: bool = False,
) -> cx509.CertificateBuilder:
    def _cn_san_typ(common_name: str):
        if "@" in common_name:
            # Vault checks emails the same way
            try:
                _parse_general_names([("EMAIL", common_name)])
            except CommandExecutionError as err:
                allowed_msgs = ("Codepoint", "Email address username must not")
                if all(msg not in str(err) for msg in allowed_msgs):
                    raise
                return None
            return "EMAIL"
        try:
            _parse_general_names([("DNS", common_name)])
        except CommandExecutionError as err:
            if "Codepoint" not in str(err):
                raise
            return None
        return "DNS"

    sans, sans_critical = None, False
    if csr_exts is not None:
        # This only happens when an actual CSR was passed, not when alt_names is translated on the fly
        try:
            sans_ext = csr_exts.get_extension_for_class(cx509.SubjectAlternativeName)
        except cx509.ExtensionNotFound:
            pass
        else:
            sans, sans_critical = sans_ext.value, verbatim and sans_ext.critical
        if not verbatim and (not exclude_cn_from_sans and common_name is not None):
            cn_san = _cn_san_typ(common_name)
            if cn_san:
                sans_gns = _parse_general_names([(cn_san, common_name)]) + list(sans or [])
                sans = cx509.SubjectAlternativeName(sans_gns)
    else:
        if alt_names or (not exclude_cn_from_sans and common_name is not None):
            normalized_sans = norm_sans(alt_names or [])
            if common_name is not None and not exclude_cn_from_sans:
                cn_san = _cn_san_typ(common_name)
                if cn_san:
                    normalized_sans.setdefault(cn_san, []).insert(0, common_name)
            # x509util needs another format still
            flattened_sans = []
            # We can also ensure the order is the same as Vault's, but it does not affect idempotency
            ordered_san_typs = ("DNS", "EMAIL", "IP", "URI")
            for san_typ in ordered_san_typs:
                for val in normalized_sans.get(san_typ, []):
                    flattened_sans.append((san_typ, val))
            flattened_other_sans = [
                ("otherName", {"oid": oid, "value": v})
                for oid, val in normalized_sans.items()
                for v in val
                if oid not in ordered_san_typs
            ]

            try:
                sans_gns = _parse_general_names(flattened_other_sans + flattened_sans)
            except SaltInvocationError as err:  # pragma: no cover
                if "otherName is currently not implemented" not in str(err):
                    raise
                try:
                    othername_gns = [
                        cx509.OtherName(_get_oid(spec["oid"]), asn1.encode_der(spec["value"]))
                        for _, spec in flattened_other_sans
                    ]
                except TypeError:
                    log.warning(
                        "Salt core x509_v2 does not support otherName. "
                        "Consider updating it. "
                        "The state will not be idempotent."
                    )
                    sans_gns = _parse_general_names(flattened_sans)
                else:
                    sans_gns = othername_gns + _parse_general_names(flattened_sans)
            if sans_gns:
                # can happen when alt_names is not specified, exclude_cn_from_sans is true and CN is an invalid email/domain
                sans = cx509.SubjectAlternativeName(sans_gns)
    if sans is not None:
        builder = builder.add_extension(cx509.SubjectAlternativeName(sans), critical=sans_critical)

    return builder


def _add_name_constraints(
    builder,
    *,
    permitted: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
    excluded: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
):
    if permitted or excluded:
        nc_subtrees = {
            "permitted_subtrees": None,
            "excluded_subtrees": None,
        }
        # we also need to ensure the order is the same as Vault's, which is different than for SANs
        ordered_nc_typs = ("DNS", "IP", "EMAIL", "URI")
        if permitted:
            normalized_permitted_nc = norm_sans(permitted, allow_other_name=False)
            flattened_permitted_nc = []
            for nc_typ in ordered_nc_typs:
                for val in normalized_permitted_nc.get(nc_typ, []):
                    flattened_permitted_nc.append((nc_typ, val))
            nc_subtrees["permitted_subtrees"] = _parse_general_names(
                flattened_permitted_nc, name_constraints=True
            )
        if excluded:
            normalized_excluded_nc = norm_sans(excluded, allow_other_name=False)
            flattened_excluded_nc = []
            for nc_typ in ordered_nc_typs:
                for val in normalized_excluded_nc.get(nc_typ, []):
                    flattened_excluded_nc.append((nc_typ, val))
            nc_subtrees["excluded_subtrees"] = _parse_general_names(
                flattened_excluded_nc, name_constraints=True
            )
        name_constraints = cx509.NameConstraints(**nc_subtrees)
        builder = builder.add_extension(name_constraints, critical=True)
    return builder


def _add_key_usage_non_ca(
    builder: cx509.CertificateBuilder, usages: list[str]
) -> cx509.CertificateBuilder:
    if usages:
        usages = [usage.lower() for usage in usages]
        key_usages = {
            "digital_signature": "digitalsignature" in usages,
            "content_commitment": "contentcommitment" in usages,
            "key_encipherment": "keyencipherment" in usages,
            "data_encipherment": "dataencipherment" in usages,
            "key_agreement": "keyagreement" in usages,
            "key_cert_sign": False,  # forced to false
            "crl_sign": "crlsign" in usages,  # this is valid
            # Vault allows these without keyagreement, but cryptography fails
            "encipher_only": "keyagreement" in usages and "encipheronly" in usages,
            "decipher_only": "keyagreement" in usages and "decipheronly" in usages,
        }
        builder = builder.add_extension(cx509.KeyUsage(**key_usages), critical=True)
    return builder


def _add_key_usage_ca(
    builder: cx509.CertificateBuilder, usages: list[str]
) -> cx509.CertificateBuilder:
    key_usages = {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": True,
        "crl_sign": True,
        "encipher_only": False,
        "decipher_only": False,
    }
    key_usage = [usage.lower() for usage in usages]  # it's case-insensitive
    key_usages["digital_signature"] = "digitalsignature" in key_usage
    builder = builder.add_extension(cx509.KeyUsage(**key_usages), critical=True)
    return builder


def _add_ekus(
    builder: cx509.CertificateBuilder,
    usages: Sequence[str] | set[str],
    oids: Sequence[str] | set[str],
) -> cx509.CertificateBuilder:
    if usages or oids:
        eku_names = {val.lower() for val in usages}
        ext_key_usages = []
        for name, oid in EXTENDED_KEY_USAGE_OID.items():
            if name.lower() in eku_names:
                ext_key_usages.append(oid)

        for oid_str in oids:
            oid = _get_oid(oid_str)
            if oid not in ext_key_usages:
                ext_key_usages.append(oid)
        builder = builder.add_extension(cx509.ExtendedKeyUsage(ext_key_usages), critical=False)

    return builder


def _add_certificate_policies(
    builder: cx509.CertificateBuilder, policies: Sequence[str]
) -> cx509.CertificateBuilder:
    policy_identifiers = []

    for poldef in policies:
        if "{" in poldef:
            try:
                policy = json.loads(poldef)
            except json.JSONDecodeError as err:  # pragma: no cover
                raise CommandExecutionError(
                    f"Failed decoding JSON policy_identifier from role: {err}"
                ) from err
        else:
            policy = {"oid": poldef}
        policy_identifiers.append(policy)

    if policy_identifiers:
        policy_info = []
        for polid in policy_identifiers:
            qualifiers = None
            if "cps" in polid:  # CA practice statement pointer
                qualifiers = qualifiers or []
                qualifiers.append(polid["cps"])
            if "notice" in polid:
                qualifiers = qualifiers or []
                qualifiers.append(
                    cx509.UserNotice(notice_reference=None, explicit_text=polid["notice"])
                )
            policy_info.append(
                cx509.PolicyInformation(
                    policy_identifier=_get_oid(polid["oid"]),
                    policy_qualifiers=qualifiers,
                )
            )
        builder = builder.add_extension(cx509.CertificatePolicies(policy_info), critical=False)

    return builder


def check_root_issuer_for_changes(
    current,
    *,
    alt_names: dict[str, str | list[str]] | list[str] | None,
    common_name: str,
    country: list[str] | str | None,
    days_remaining: int,
    days_valid: int,
    exclude_cn_from_sans: bool,
    excluded_alt_names: dict[str, str | list[str]] | list[str] | None,
    key_usage: list[str] | str | None,
    locality: list[str] | str | None,
    max_path_length: int,
    not_after: str | None,
    not_before_duration: str | int,
    organization: list[str] | str | None,
    ou: list[str] | str | None,
    permitted_alt_names: dict[str, str | list[str]] | list[str] | None,
    postal_code: list[str] | str | None,
    province: list[str] | str | None,
    replace_key: bool,
    rotate_key: bool,
    signature_bits: int,
    street_address: list[str] | str | None,
    serial_number: str | None,
    urls: URLConfigs,
):
    """
    Check whether an existing root CA issuer certificate matches expected parameters.

    current
        Existing certificate text.

    alt_names
        Requested Subject Alternative Names.

    common_name
        Subject CN (commonName) name attribute.

    country
        Subject C (countryName) name attribute(s).

    days_remaining
        Minimum TTL in days to allow before requesting a fresh certificate.

    days_valid
        Requested Time To Live in integer days.

    exclude_cn_from_sans
        Whether the subject CN should be included in the SANs (either as ``email`` or ``dns`` type).

    excluded_alt_names
        List of alternative names for which certificates are not allowed to be issued
        or signed by this CA certificate.

    key_usage
        List of key usages to add to the existing set of key usages (CRLSign,CertSign).

    locality
        Subject L (localityName) name attribute(s).

    max_path_length
        Basic Constraints ``pathlen`` parameter.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``days_valid`` is ignored.

    not_before_duration
        Duration by which to backdate the NotBefore property.

    organization
        Subject O (organizationName) name attribute(s).

    ou
        Subject OU (organizationalUnitName) name attribute(s).

    permitted_alt_names
        List of alternative names for which certificates are allowed to be issued
        or signed by this CA certificate.

    postal_code
        Subject postalCode name attribute(s).

    province
        Subject ST (stateOrProvinceName) name attribute(s).

    signature_bits
        Number of bits to use in the signature algorithm.
        Valid: ``256`` (SHA-2-256), ``384`` (SHA-2-384), ``512`` (SHA-2-512).

    street_address
        Subject street (streetAddress) name attribute(s).

    serial_number
        Single value for the **subject** SERIALNUMBER (OID: 2.5.4.5) name attribute (NOT the certificate's serial number!).

    urls
        Dictionary of issuer/mount-default authority URLs, which end up in the AuthorityInformationAccess,
        CRLDistributionPoints and FreshestCRL extensions.
    """
    changes: dict[str, typing.Any] = {}
    # Since we load a cert from Vault, we must assume loading it works, no error handling necessary
    cert = typing.cast(cx509.Certificate, x509util.load_cert(current, passphrase=None))
    pubkey = cert.public_key()

    changes.update(
        _compare_cert_signing(
            current=cert,
            signing_ca=None,
            public_key=pubkey,
            signature_bits=signature_bits,
        )
    )

    builder = _build_root_issuer_cert(
        common_name=common_name,
        alt_names=alt_names,
        days_valid=days_valid,
        max_path_length=max_path_length,
        key_usage=key_usage,
        exclude_cn_from_sans=exclude_cn_from_sans,
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
        not_before_duration=not_before_duration,
        not_after=not_after,
        urls=urls,
        public_key=pubkey,  # type: ignore
    )
    try:
        curr_not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover
        # naive datetime object, release <42 (it's always UTC)
        curr_not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    new_not_after = _getattr_safe(builder, "_not_valid_after").replace(tzinfo=timezone.utc)

    if (not_after is not None and curr_not_after != new_not_after) or (
        not_after is None
        and curr_not_after < datetime.now(tz=timezone.utc) + timedelta(days=days_remaining)
    ):
        changes["expiration"] = {
            "old": curr_not_after.strftime(TIME_FMT),
            "new": new_not_after.strftime(TIME_FMT),
        }

    if _getattr_safe(builder, "_subject_name") != cert.subject:
        changes["subject_name"] = {
            "old": cert.subject.rfc4514_string(),
            "new": _getattr_safe(builder, "_subject_name").rfc4514_string(),
        }

    ext_changes = _compare_exts(cert, builder)
    if (
        ext_changes
        and "freshestCRL" in ext_changes["added"]
        and not urls.get("crl_distribution_points")
    ):
        # OpenBao does not add a freshestCRL extension without a cRLDistributionPoints one.
        # Vault only warns about it.
        ext_changes["added"].pop("freshestCRL")
    if any(ext_changes.values()):
        changes["extensions"] = ext_changes

    if (changes and rotate_key) or replace_key:
        changes["private_key"] = True
        ext_changes = changes.setdefault("extensions", {"added": {}, "changed": {}, "removed": {}})
        if "subjectKeyIdentifier" not in ext_changes["changed"]:
            try:
                ski = cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier)
            except cx509.ExtensionNotFound:  # pragma: no cover
                ext_changes["added"]["subjectKeyIdentifier"] = {
                    "critical": False,
                    "value": "<TBD>",
                }
            else:
                ext_changes["changed"]["subjectKeyIdentifier"] = {
                    "value": {"old": _render_extension(ski)["value"], "new": "<TBD>"}
                }
    return changes


def _build_root_issuer_cert(
    *,
    common_name: str,
    alt_names: dict[str, str | list[str]] | list[str] | None = None,
    days_valid: int,
    max_path_length: int,
    key_usage: list[str] | str | None,
    exclude_cn_from_sans: bool,
    permitted_alt_names: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
    excluded_alt_names: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
    ou: list[str] | str | None,
    organization: list[str] | str | None,
    country: list[str] | str | None,
    locality: list[str] | str | None,
    province: list[str] | str | None,
    street_address: list[str] | str | None,
    postal_code: list[str] | str | None,
    serial_number: str | None,
    not_before_duration: str | int,
    not_after: str | None,
    urls: URLConfigs,
    public_key: CertificateIssuerPublicKeyTypes,
) -> cx509.CertificateBuilder:
    builder = cx509.CertificateBuilder(public_key=public_key)

    # Subject/Issuer DN
    subject_dn = _build_subject(
        country=country,
        province=province,
        locality=locality,
        street_address=street_address,
        postal_code=postal_code,
        organization=organization,
        ou=ou,
        common_name=common_name,
        serial_number=serial_number,
    )
    builder = builder.subject_name(subject_dn).issuer_name(subject_dn)

    # Validity
    not_before = datetime.now(tz=timezone.utc) - timedelta(
        seconds=timestring_map(not_before_duration)
    )
    not_after_dt = _strptime(not_after, "not_after") or (
        datetime.now(tz=timezone.utc) + timedelta(days=days_valid)
    )
    builder = builder.not_valid_before(not_before).not_valid_after(not_after_dt)

    # basicConstraints
    builder = builder.add_extension(
        cx509.BasicConstraints(
            True, max_path_length if max_path_length is not None and max_path_length >= 0 else None
        ),
        critical=True,
    )

    # keyUsage
    builder = _add_key_usage_ca(builder, deserialize_csl(key_usage) or [])

    # subjectAlternativeName
    builder = _add_sans(
        builder,
        common_name,
        alt_names,
        exclude_cn_from_sans=exclude_cn_from_sans,
    )

    # nameConstraints
    builder = _add_name_constraints(
        builder, permitted=permitted_alt_names, excluded=excluded_alt_names
    )

    # AuthorityInformationAccess/CRLDistributionPoints/FreshestCRL
    builder = _add_authority_info(builder, urls)

    # SubjectKeyIdentifier
    builder = _add_ski(builder, public_key)

    # AuthorityKeyIdentifier
    builder = _add_aki(builder, public_key=public_key)

    return builder


def check_ca_cert_for_changes(  # pylint: disable=too-many-locals
    current: str,
    issuer: str,
    private_key: str | None,
    private_key_passphrase: str | None,
    csr: str | None,
    sign_verbatim: bool,
    *,
    alt_names: dict[str, str | list[str]] | list[str] | None,
    append_chain: list[cx509.Certificate] | None,
    common_name: str | None,
    country: list[str] | str | None,
    encoding: Encoding,
    exclude_cn_from_sans: bool,
    excluded_alt_names: dict[str, str | list[str]] | list[str] | None,
    key_usage: list[str] | str | None,
    locality: list[str] | str | None,
    max_path_length: int | None,
    not_after: str | None,
    not_before_duration: str | int,
    organization: list[str] | str | None,
    ou: list[str] | str | None,
    permitted_alt_names: dict[str, str | list[str]] | list[str] | None,
    postal_code: list[str] | str | None,
    province: list[str] | str | None,
    serial_number: str | None,
    signature_bits: int,
    street_address: list[str] | str | None,
    ttl: int,
    ttl_remaining: str | int,
    urls: URLConfigs,
    **kwargs,
):
    """
    Check whether an existing on-disk CA certificate matches expected parameters.

    current
        Path of the existing certificate on disk.

    issuer
        Issuer certificate.

    private_key
        Path of the private key on disk/encoded private key.

    private_key_passphrase
        Passphrase for ``private_key``

    csr
        Path of the CSR on disk/encoded CSR.

    sign_verbatim
        Whether the ``sign-verbatim`` endpoint is used. Defaults to false.

    alt_names
        Requested Subject Alternative Names.

    append_chain
        List of certificates to append. Fails with ``der`` encoding.

    common_name
        Subject CN name attribute.

    country
        Subject C (countryName) name attribute(s).

    encoding
        Requested certificate encoding. Defaults to ``pem``.

    exclude_cn_from_sans
        Whether the subject CN should be included in the SANs (either as ``email`` or ``dns`` type).
        Has no effect when ``sign_verbatim`` is true.

    excluded_alt_names
        List of alternative names for which certificates are not allowed to be issued
        or signed by this CA certificate.

    key_usage
        List of key usages to add to the existing set of key usages (CRLSign,CertSign).

    locality
        Subject L (localityName) name attribute(s).

    max_path_length
        Basic Constraints ``pathlen`` parameter.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``ttl`` is ignored.

    not_before_duration
        Duration by which to backdate the NotBefore property.

    organization
        Subject O (organizationName) name attribute(s).

    ou
        Subject OU (organizationalUnitName) name attribute(s).

    permitted_alt_names
        List of alternative names for which certificates are allowed to be issued
        or signed by this CA certificate.

    postal_code
        Subject postalCode name attribute(s).

    province
        Subject ST (stateOrProvinceName) name attribute(s).

    serial_number
        Single value for the **subject** SERIALNUMBER (OID: 2.5.4.5) name attribute (NOT the certificate's serial number!).

    signature_bits
        Number of bits to use in the signature algorithm.
        Valid: ``256`` (SHA-2-256), ``384`` (SHA-2-384), ``512`` (SHA-2-512).

    street_address
        Subject street (streetAddress) name attribute(s).

    ttl
        Requested Time To Live, already normalized to integer-valued seconds.

    ttl_remaining
        Minimum TTL to allow before requesting a fresh certificate.

    urls
        Dictionary of issuer/mount-default authority URLs, which end up in the AuthorityInformationAccess,
        CRLDistributionPoints and FreshestCRL extensions.

    kwargs
        All other kwargs passed to the cert signing endpoint or as CSR generation params.
    """
    changes: dict[str, typing.Any] = {}
    ttl_remaining = ttl_remaining or 0

    try:
        cert, current_encoding, current_chain = _load_cert_and_chain(current)
    except CommandExecutionError as err:  # pragma: no cover
        if "Invalid cert bundle" not in str(err):
            raise
        changes["replaced"] = True
        return changes
    except SaltInvocationError as err:
        if any(
            (
                "Could not deserialize binary data" in str(err),
                "Could not load PEM-encoded" in str(err),
            )
        ):
            changes["replaced"] = True
            return changes
        raise

    if not _compare_ca_chain(
        current_chain or [], append_chain or [], unordered="pkcs7" in current_encoding
    ):
        changes["ca_chain"] = True

    if encoding != current_encoding:
        changes["encoding"] = {
            "old": current_encoding,
            "new": encoding,
        }

    ca = x509util.load_cert(issuer)
    csr_loaded: cx509.CertificateSigningRequest | None = None
    pk_loaded: Privkey | None = None

    if private_key:
        pk_loaded: Privkey = x509util.load_privkey(private_key, passphrase=private_key_passphrase)
        pubkey = pk_loaded.public_key()
    else:
        csr_loaded: cx509.CertificateSigningRequest = x509util.load_csr(csr)
        pubkey = csr_loaded.public_key()

    changes.update(
        _compare_cert_signing(
            current=cert,
            signing_ca=ca,
            public_key=pubkey,
            signature_bits=signature_bits,
        )
    )

    # Validate max_path_length, if it was passed, otherwise derive its default.
    try:
        ca_bc = ca.extensions.get_extension_for_class(cx509.BasicConstraints)
        issuer_pathlen = ca_bc.value.path_length
    except cx509.ExtensionNotFound:  # pragma: no cover
        # All issuers should have a basicConstraints extension. If they somehow don't, treat as unconstrained.
        issuer_pathlen = None
    if issuer_pathlen is None:
        if max_path_length is None:
            max_path_length = -1
    elif issuer_pathlen < 1:  # pragma: no cover
        raise CommandExecutionError(
            "Issuer is not allowed to sign other CA certificates, its `max_path_length` is 0."
        )
    elif max_path_length is None:
        max_path_length = issuer_pathlen - 1
    elif max_path_length < 0:
        raise CommandExecutionError(
            "An unconstrained `max_path_length` is not allowed with current issuer: "
            f"Issuer is limited to chains of length `{issuer_pathlen}` or less "
            f"(i.e. only `{issuer_pathlen - 1}` or less can be requested)"
        )
    elif max_path_length >= issuer_pathlen:
        raise CommandExecutionError(
            f"Requested `max_path_length` of `{max_path_length}` exceeds the maximum allowed value for current issuer: "
            f"Issuer is limited to chains of length `{issuer_pathlen}` or less "
            f"(i.e. only `{issuer_pathlen - 1}` or less can be requested)"
        )

    csr_args, _ = split_csr_kwargs(kwargs)
    csr_args, normalized_sans, norm_permitted_nc, norm_excluded_nc = norm_intermediate_params(
        csr_args,
        csr=csr,
        sign_verbatim=sign_verbatim,
        country=country,
        province=province,
        locality=locality,
        street_address=street_address,
        postal_code=postal_code,
        organization=organization,
        ou=ou,
        common_name=common_name,
        serial_number=serial_number,
        alt_names=alt_names,
        key_usage=key_usage,
        permitted_alt_names=permitted_alt_names,
        excluded_alt_names=excluded_alt_names,
    )

    if sign_verbatim:
        builder = _build_verbatim_ca_cert(
            ca,
            csr=csr_loaded,
            private_key=pk_loaded,
            key_usage=key_usage,
            max_path_length=max_path_length,
            norm_excluded_nc=norm_excluded_nc,
            norm_permitted_nc=norm_permitted_nc,
            normalized_sans=normalized_sans,
            not_after=not_after,
            not_before_duration=not_before_duration,
            serial_number=serial_number,
            ttl=ttl,
            urls=urls,
            **csr_args,
        )
    else:
        builder = _build_regular_ca_cert(
            ca,
            csr=csr_loaded,
            private_key=pk_loaded,
            common_name=common_name,
            country=country,
            exclude_cn_from_sans=exclude_cn_from_sans,
            key_usage=key_usage,
            locality=locality,
            max_path_length=max_path_length,
            norm_excluded_nc=norm_excluded_nc,
            norm_permitted_nc=norm_permitted_nc,
            normalized_sans=normalized_sans,
            not_after=not_after,
            not_before_duration=not_before_duration,
            organization=organization,
            ou=ou,
            postal_code=postal_code,
            province=province,
            serial_number=serial_number,
            street_address=street_address,
            ttl=ttl,
            urls=urls,
            **csr_args,
        )

    # Check if certificate should be renewed due to close to expiration
    try:
        curr_not_valid_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover
        curr_not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if curr_not_valid_after < datetime.now(timezone.utc) + timedelta(
        seconds=timestring_map(ttl_remaining, cast=int)
    ):
        changes["expiration"] = {
            "expire_in": (curr_not_valid_after - datetime.now(timezone.utc)).total_seconds(),
            "toleration": timestring_map(ttl_remaining, cast=int),
        }

    if _getattr_safe(builder, "_subject_name") != cert.subject:
        changes["subject_name"] = {
            "old": cert.subject.rfc4514_string(),
            "new": _getattr_safe(builder, "_subject_name").rfc4514_string(),
        }

    ext_changes = _compare_exts(cert, builder)
    if any(ext_changes.values()):
        changes["extensions"] = ext_changes
    return changes


def _build_regular_ca_cert(
    issuer: cx509.Certificate,
    csr: cx509.CertificateSigningRequest | None,
    private_key: Privkey | None,
    *,
    common_name: str | None,
    country: list[str] | str | None,
    exclude_cn_from_sans: bool,
    key_usage: list[str] | str | None,
    locality: list[str] | str | None,
    max_path_length: int,
    norm_excluded_nc: dict[str, list[str]],
    norm_permitted_nc: dict[str, list[str]],
    normalized_sans: dict[str, list[str]],
    not_after: str | None,
    not_before_duration: str | int,
    organization: list[str] | str | None,
    ou: list[str] | str | None,
    postal_code: list[str] | str | None,
    province: list[str] | str | None,
    serial_number: str | None,
    street_address: list[str] | str | None,
    ttl: int,
    urls: URLConfigs,
):
    if private_key is not None:
        public_key = private_key.public_key()
        csr_eff, _ = typing.cast(
            tuple[cx509.CertificateSigningRequestBuilder, typing.Any],
            x509util.build_csr(private_key),
        )
    elif csr is not None:
        csr_eff = csr
        public_key = csr.public_key()
    else:  # pragma: no cover
        raise TypeError("Either csr or private_key must be set")
    builder = cx509.CertificateBuilder(public_key=public_key)

    try:
        csr_subject = csr_eff.subject  # ty: ignore[unresolved-attribute]
    except AttributeError:
        # CSRBuilder (created by x509util.build_csr())
        csr_subject = _getattr_safe(csr_eff, "_subject_name")

    # CSR common name is only used when it's not provided otherwise here
    if not common_name:
        try:
            common_name = csr_subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)[
                0
            ].value  # ty: ignore[invalid-assignment]
        except IndexError:
            pass
    subject_dn = _build_subject(
        country=country,
        province=province,
        locality=locality,
        street_address=street_address,
        postal_code=postal_code,
        organization=organization,
        ou=ou,
        common_name=common_name,
        serial_number=serial_number,
    )
    builder = builder.subject_name(subject_dn).issuer_name(issuer.subject)

    # Validity
    not_before = datetime.now(tz=timezone.utc) - timedelta(
        seconds=timestring_map(not_before_duration)
    )
    not_after_dt = _strptime(not_after, "not_after") or (
        datetime.now(tz=timezone.utc) + timedelta(seconds=ttl)
    )
    builder = builder.not_valid_before(not_before).not_valid_after(not_after_dt)

    # basicConstraints
    builder = builder.add_extension(
        cx509.BasicConstraints(True, max_path_length if max_path_length >= 0 else None),
        critical=True,
    )
    # keyUsage
    builder = _add_key_usage_ca(builder, deserialize_csl(key_usage) or [])
    # subjectAlternativeName
    builder = _add_sans(
        builder,
        common_name,
        normalized_sans,
        exclude_cn_from_sans=exclude_cn_from_sans,
    )
    # nameConstraints
    builder = _add_name_constraints(builder, permitted=norm_permitted_nc, excluded=norm_excluded_nc)
    # AuthorityInformationAccess/CRLDistributionPoints/FreshestCRL
    builder = _add_authority_info(builder, urls)
    # SubjectKeyIdentifier
    builder = _add_ski(builder, public_key)
    # AuthorityKeyIdentifier
    builder = _add_aki(builder, issuer=issuer)

    return builder


def _build_verbatim_ca_cert(
    issuer: cx509.Certificate,
    csr: cx509.CertificateSigningRequest | None,
    private_key: Privkey | None,
    *,
    max_path_length: int,
    norm_excluded_nc: dict[str, list[str]],
    norm_permitted_nc: dict[str, list[str]],
    normalized_sans: dict[str, list[str]],
    not_after: str | None,
    not_before_duration: str | int,
    ttl: int,
    urls: URLConfigs,
    **csr_args,
):
    if private_key is not None:
        public_key = private_key.public_key()
        if norm_permitted_nc or norm_excluded_nc:
            # There's a minor bug in x509.create_csr, we need to filter non-empty values
            csr_args["nameConstraints"] = filter_unset(
                {
                    "critical": True,
                    "permitted": [f"{k}:{vv}" for k, v in norm_permitted_nc.items() for vv in v]
                    or None,
                    "excluded": [f"{k}:{vv}" for k, v in norm_excluded_nc.items() for vv in v]
                    or None,
                }
            )
        # Leaving alt_names out here to not break otherName workaround.
        # SANs are added as an extension explicitly below.
        # KeyUsage is already added to csr_args and subject already rendered.
        csr_eff, _ = typing.cast(
            tuple[cx509.CertificateSigningRequestBuilder, typing.Any],
            x509util.build_csr(private_key, **csr_args),
        )
    elif csr is not None:
        csr_eff = csr
        public_key = csr.public_key()
    else:  # pragma: no cover
        raise TypeError("Either csr or private_key must be set")

    # Subject Name
    try:
        csr_subject = csr_eff.subject  # ty: ignore[unresolved-attribute]
    except AttributeError:
        # CSRBuilder (created by x509util.build_csr())
        csr_subject = _getattr_safe(csr_eff, "_subject_name")

    builder = (
        cx509.CertificateBuilder(public_key=public_key)
        .subject_name(csr_subject)
        .issuer_name(issuer.subject)
    )

    # Validity
    not_before = datetime.now(tz=timezone.utc) - timedelta(
        seconds=timestring_map(not_before_duration)
    )
    not_after_dt = _strptime(not_after, "not_after") or (
        datetime.now(tz=timezone.utc) + timedelta(seconds=ttl)
    )
    builder = builder.not_valid_before(not_before).not_valid_after(not_after_dt)

    # Verbatim copy extensions from CSR
    try:
        csr_exts: cx509.Extensions = csr_eff.extensions  # ty: ignore[unresolved-attribute]
    except AttributeError:
        csr_exts = cx509.Extensions(_getattr_safe(csr_eff, "_extensions"))
    for ext in csr_exts:
        if not isinstance(ext.value, cx509.BasicConstraints):
            builder = builder.add_extension(ext.value, ext.critical)

    # basicConstraints
    builder = builder.add_extension(
        cx509.BasicConstraints(True, max_path_length if max_path_length >= 0 else None),
        critical=True,
    )

    # Default KeyUsage
    try:
        csr_exts.get_extension_for_class(cx509.KeyUsage)
    except cx509.ExtensionNotFound:
        builder = _add_key_usage_ca(builder, [])

    # SubjectAlternativeName simulation (for otherName workaround, this would actually be in the generated CSR)
    try:
        csr_exts.get_extension_for_class(cx509.SubjectAlternativeName)
    except cx509.ExtensionNotFound:
        builder = _add_sans(
            builder,
            None,
            normalized_sans,
            exclude_cn_from_sans=True,
            verbatim=True,
        )

    # AuthorityInformationAccess/CRLDistributionPoints/FreshestCRL
    builder = _add_authority_info(builder, urls)

    # Default SubjectKeyIdentifier
    try:
        csr_exts.get_extension_for_class(cx509.SubjectKeyIdentifier)
    except cx509.ExtensionNotFound:
        builder = _add_ski(builder, public_key)

    # AuthorityKeyIdentifier
    builder = _add_aki(builder, issuer=issuer)

    return builder


def _build_subject(
    *,
    country: list[str] | str | None,
    province: list[str] | str | None,
    locality: list[str] | str | None,
    street_address: list[str] | str | None,
    postal_code: list[str] | str | None,
    organization: list[str] | str | None,
    ou: list[str] | str | None,
    common_name: str | None,
    serial_number: str | None,
    user_ids: list[str] | str | None = None,
):
    rdns = []
    for oid, vals in (
        (cx509.NameOID.COUNTRY_NAME, country),
        (cx509.NameOID.STATE_OR_PROVINCE_NAME, province),
        (cx509.NameOID.LOCALITY_NAME, locality),
        (cx509.NameOID.STREET_ADDRESS, street_address),
        (cx509.NameOID.POSTAL_CODE, postal_code),
        (cx509.NameOID.ORGANIZATION_NAME, organization),
        (cx509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        (cx509.NameOID.COMMON_NAME, common_name),
        (cx509.NameOID.SERIAL_NUMBER, serial_number),
        (cx509.NameOID.USER_ID, user_ids),
    ):
        if vals is None or not vals:
            continue
        if not isinstance(vals, list):
            vals = [vals]
        if oid == cx509.NameOID.USER_ID:
            rdns.extend(
                cx509.RelativeDistinguishedName([cx509.NameAttribute(oid, str(val))])
                for val in vals
            )
        else:
            rdns.append(
                cx509.RelativeDistinguishedName(cx509.NameAttribute(oid, str(val)) for val in vals)
            )
    return cx509.Name(rdns)


def _compare_cert_signing(
    current: cx509.Certificate,
    signing_ca: cx509.Certificate | None,
    public_key: CertificatePublicKeyTypes,
    signature_bits: int | None = None,
) -> dict[str, typing.Any]:
    changes = {}

    if signing_ca is not None:
        if not x509util.verify_signature(current, signing_ca.public_key()):
            changes["signing_private_key"] = True

        # Check correctly if issuer is the same
        if _getattr_safe(signing_ca, "subject") != _getattr_safe(current, "issuer"):
            changes["issuer_name"] = {
                "old": _getattr_safe(current, "issuer").rfc4514_string(),
                "new": _getattr_safe(signing_ca, "subject").rfc4514_string(),
            }

    if current.public_key() != public_key:
        changes["private_key"] = True

    if signature_bits:
        if current.signature_hash_algorithm is not None and not isinstance(
            current.signature_hash_algorithm,
            _get_hashing_algorithm(signature_bits),
        ):
            algo = type(current.signature_hash_algorithm).__name__
            cur_bits = None
            if algo.startswith("SHA"):
                try:
                    cur_bits = int(algo[3:])
                except (TypeError, ValueError):
                    pass
            changes["signature_bits"] = {"old": cur_bits, "new": signature_bits}

    return changes


def _compare_ca_chain(
    current: list[cx509.Certificate], new: list[cx509.Certificate], unordered: bool = False
) -> bool:
    if len(current) != len(new):
        return False
    if unordered:
        return {cert.fingerprint(hashes.SHA256()) for cert in new} == {
            cert.fingerprint(hashes.SHA256()) for cert in current
        }
    for i, new_cert in enumerate(new):
        if new_cert.fingerprint(hashes.SHA256()) != current[i].fingerprint(hashes.SHA256()):
            return False
    return True


def _compare_exts(
    current: cx509.Certificate, builder: cx509.CertificateBuilder
) -> dict[ExtensionChange, dict[str, typing.Any]]:
    def getextname(ext):
        try:
            return ext.oid._name
        except AttributeError:
            return ext.oid.dotted_string

    added = {}
    changed = {}
    removed = {}
    builder_extensions = cx509.Extensions(_getattr_safe(builder, "_extensions"))

    for ext in builder_extensions:
        try:
            cur_ext = current.extensions.get_extension_for_oid(ext.value.oid)
            if ext_changes := _compare_ext(cur_ext, ext):
                changed[getextname(ext)] = ext_changes
        except cx509.ExtensionNotFound:
            added[getextname(ext)] = _render_extension(ext)

    for ext in current.extensions:
        try:
            builder_extensions.get_extension_for_oid(ext.value.oid)
        except cx509.ExtensionNotFound:
            removed[getextname(ext)] = _render_extension(ext)

    return {"added": added, "changed": changed, "removed": removed}


def norm_sans(
    sans: dict[str, list[str]] | dict[str, str | list[str]] | list[str],
    *,
    allow_other_name: bool = True,
) -> dict[str, list[str]]:
    """
    Normalize all allowed input structures for SubjectAlternativeNames (``alt_names`` parameter)
    or NameConstraints (``permitted_alt_names``, ``excluded_alt_names``) into a dict of lists with uppercase keys.

    sans
        User input.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists (``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type1>:<value1>", ...]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs
        (unless ``allow_other_name`` is false).
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

    allow_other_name
        Whether to parse unknown ``<type>`` values as otherName SAN OIDs. When false, raises an exception
        for types other than ``dns``, ``email``, ``uri`` and ``ip``. Intended to parse General Names
        for the NameConstraints extension.
    """
    parsed: dict[str, list[str]] = {}

    def _norm(typ):
        typ = typ.upper()
        if typ not in SUPPORTED_SAN_TYPES:
            if not allow_other_name:
                raise SaltInvocationError(
                    f"Invalid SAN type '{typ}', valid: DNS, EMAIL, IP, URI. Note: otherName SANs are not allowed here."
                )
            try:
                cx509.ObjectIdentifier(typ)
            except ValueError as err:
                raise SaltInvocationError(
                    f"Invalid SAN type '{typ}', valid: DNS, EMAIL, IP, URI, <OID>"
                ) from err
        return typ

    if isinstance(sans, list):
        try:
            for typ, val in (item.split(":", 1) for item in sans):
                parsed.setdefault(_norm(typ), []).append(val)
        except ValueError as err:
            raise CommandExecutionError(
                f"SAN is not in correct format. Must be in format <type>:<value>: {err}"
            ) from err
        return parsed
    if isinstance(sans, dict):
        for k, v in sans.items():
            parsed.setdefault(_norm(k), []).extend(v if isinstance(v, list) else [v])
        return parsed
    raise SaltInvocationError("Wrong format for alt_names")  # pragma: no cover


def split_sans(sans: dict[str, list[str]]) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Render a normalized dict of lists of GeneralNames for the subjectAltName
    extension into a format Vault understands and return each type separately.
    Returns a tuple of (``dns_or_email_sans``, ``ip_sans``, ``uri_sans``, ``other_sans``).

    sans
        Normalized dict of lists (``{"<type>": ["<value>", ...]}``) as output by :func:`norm_sans`.
    """
    dns_sans = []
    ip_sans = []
    uri_sans = []
    other_sans = []

    for typ, vals in sans.items():
        if typ in ("DNS", "EMAIL"):
            dns_sans.extend(vals)
        elif typ == "IP":
            ip_sans.extend(vals)
        elif typ == "URI":
            uri_sans.extend(vals)
        else:
            other_sans.extend(f"{typ};UTF8:{vv}" for vv in vals)

    return dns_sans, ip_sans, uri_sans, other_sans


def split_name_constraints(
    sans: dict[str, list[str]],
) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Render a normalized dict of lists of GeneralNames for the nameConstraints
    extension into a format Vault understands and return each type separately.
    Returns a tuple of (``dns_nc``, ``email_nc``, ``ip_nc``, ``uri_nc``).

    sans
        Normalized dict of lists (``{"<type>": ["<value>", ...]}``) as output by :func:`norm_sans`
        with ``allow_other_name`` being false.
    """
    dns_gns = []
    email_gns = []
    ip_gns = []
    uri_gns = []

    for typ, vals in sans.items():
        if typ == "DNS":
            dns_gns.extend(vals)
        elif typ == "EMAIL":
            email_gns.extend(vals)
        elif typ == "IP":
            ip_gns.extend(vals)
        elif typ == "URI":
            uri_gns.extend(vals)
        else:  # pragma: no cover
            raise RuntimeError(f"Invalid GeneralName type for nameConstraints: {typ}")

    return dns_gns, email_gns, ip_gns, uri_gns


def split_csr_kwargs(
    kwargs: dict[str, typing.Any],
    allow: Sequence[str] | None = None,
) -> tuple[dict[str, typing.Any], dict[str, typing.Any]]:
    """
    Split known parameters for :py:func:`x509.create_csr <salt.modules.x509_v2.create_csr>` from
    a dict of passed keyword arguments. Returns a tuple of (``csr_args``, ``extra_args``).

    kwargs
        Keyword arguments passed to the function.

    allow
        List of additional keyword arguments to allow for CSR kwargs.
        Most are allowed by default, but e.g. ``subject`` is not.
    """
    csr_args = {}
    extra_args = {}
    allow = allow or []
    for k, v in kwargs.items():
        if k in VALID_CSR_ARGS or k in allow:
            csr_args[k] = v
        else:
            extra_args[k] = v
    return csr_args, extra_args


def sync_verbatim_csr_subject(
    csr_args: dict[str, typing.Any], *, serial_number: str | None, user_ids: list[str] | str | None
) -> dict[str, typing.Any]:
    """
    Ensure user_ids and serial_number work when signing a leaf certificate verbatim.
    """
    subject_kwargs = {}
    for subject_attr in NAME_ATTRS_OID:
        if subject_attr in csr_args:
            subject_kwargs[subject_attr] = csr_args.pop(subject_attr)
    if user_ids is not None:
        subject_kwargs["UID"] = deserialize_csl(user_ids)
    if serial_number is not None:
        subject_kwargs["SERIALNUMBER"] = serial_number
    subject_list = []  # Need to ensure the encoding matches the regular one
    for subject_attr, oid in NAME_ATTRS_OID.items():
        if subject_attr not in subject_kwargs:
            continue
        if subject_attr == "UID":
            # In contrast to all other attrs, Vault renders one Name per UID RDN instead of one Name for all of the same type
            subject_list.extend(f"UID={uid}" for uid in subject_kwargs[subject_attr])
        else:
            # x509.create_csr only allows a single RDN per attr when passed as kwarg
            subject_list.append(f"{oid.dotted_string}={subject_kwargs[subject_attr]}")
    csr_args["subject"] = subject_list
    return csr_args


def norm_intermediate_params(
    csr_args: dict[str, typing.Any],
    *,
    csr: str | None,
    sign_verbatim: bool,
    country: list[str] | str | None,
    province: list[str] | str | None,
    locality: list[str] | str | None,
    street_address: list[str] | str | None,
    postal_code: list[str] | str | None,
    organization: list[str] | str | None,
    ou: list[str] | str | None,
    common_name: str | None,
    serial_number: str | None,
    alt_names: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
    key_usage: list[str] | str | None,
    permitted_alt_names: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
    excluded_alt_names: dict[str, list[str]] | dict[str, str | list[str]] | list[str] | None,
) -> tuple[
    dict[str, typing.Any],  # csr_args
    dict[str, list[str]],  # norm_sans
    dict[str, list[str]],  # norm_permitted_nc
    dict[str, list[str]],  # norm_excluded_nc
]:
    """
    Normalize/synchronize parameters for the sign-intermediate endpoint and warn about ignored ones.
    Returns CSR generation arguments, normalized alt_names/permitted_alt_names/excluded_alt_names.
    """
    normalized_sans = norm_permitted_nc = norm_excluded_nc = None

    if csr and csr_args:
        log.warning(
            "Got CSR generation parameters when a `csr` was already passed. Ignoring: %s",
            ", ".join(f"`{param}`" for param in csr_args),
        )
        csr_args = {}
    elif not sign_verbatim and csr_args:
        log.warning(
            "Not signing verbatim, any CSR generation parameters are ignored. Ignoring: %s",
            ", ".join(f"`{param}`" for param in csr_args),
        )
        csr_args = {}
    elif sign_verbatim:
        # Keep Vault parameters in sync with CSR keyword arguments.
        subject_present = "subject" in csr_args

        subject_rdns = []
        for oid, param, csr_param, vals in (
            (cx509.NameOID.COUNTRY_NAME, "country", "C", country),
            (cx509.NameOID.STATE_OR_PROVINCE_NAME, "province", "ST", province),
            (cx509.NameOID.LOCALITY_NAME, "locality", "L", locality),
            (cx509.NameOID.STREET_ADDRESS, "street_address", "STREET", street_address),
            (
                cx509.NameOID.POSTAL_CODE,
                "postal_code",
                None,
                postal_code,
            ),  # This is not exposed in keyword arguments at all
            (cx509.NameOID.ORGANIZATION_NAME, "organization", "O", organization),
            (cx509.NameOID.ORGANIZATIONAL_UNIT_NAME, "ou", "OU", ou),
            (cx509.NameOID.COMMON_NAME, "common_name", "CN", common_name),
            (cx509.NameOID.SERIAL_NUMBER, "serial_number", "SERIALNUMBER", serial_number),
        ):
            if csr_param is not None and csr_param in csr_args:
                if vals is not None:
                    log.warning(
                        "Received both `%s` and `%s` parameters. Ignoring `%s`.",
                        param,
                        csr_param,
                        csr_param,
                    )
                    csr_args.pop(csr_param)
                elif subject_present:
                    log.warning(
                        "Received both `subject` and `%s` parameters. Ignoring `%s`.",
                        csr_param,
                        csr_param,
                    )
                    csr_args.pop(csr_param)
                else:
                    vals = csr_args.pop(csr_param)
            if vals is None:
                continue
            # When `subject` was passed, this only needs to warn about/remove CSR subject params
            if subject_present:
                log.warning(
                    "Received both `subject` and `%s` parameters. Ignoring `%s`.",
                    param,
                    param,
                )
                continue
            if not isinstance(vals, list):
                vals = [vals]
            subject_rdns.append(
                cx509.RelativeDistinguishedName(cx509.NameAttribute(oid, str(val)) for val in vals)
            )
        if not subject_present:
            csr_args["subject"] = cx509.Name(subject_rdns).rfc4514_string()

    if alt_names is not None:
        if sign_verbatim and csr:
            log.warning(
                "Received both `alt_names` and `csr` parameters for verbatim signing. Ignoring `alt_names`."
            )
        elif sign_verbatim and "subjectAltName" in csr_args:
            log.warning(
                "Received both `alt_names` and `subjectAltName` parameters for verbatim signing. Ignoring `alt_names`."
            )
        else:
            normalized_sans = norm_sans(alt_names)

    if permitted_alt_names is not None or excluded_alt_names is not None:
        if sign_verbatim and csr:
            log.warning(
                "Received `permitted_alt_names`/`excluded_alt_names` in addition to `csr` "
                "parameter for verbatim signing. Ignoring `permitted_alt_names`/`excluded_alt_names`."
            )
        elif sign_verbatim and "nameConstraints" in csr_args:
            log.warning(
                "Received `permitted_alt_names`/`excluded_alt_names` in addition to `nameConstraints` "
                "parameter for verbatim signing. Ignoring `permitted_alt_names`/`excluded_alt_names`."
            )
        else:
            norm_permitted_nc = norm_sans(permitted_alt_names or [], allow_other_name=False)
            norm_excluded_nc = norm_sans(excluded_alt_names or [], allow_other_name=False)

    if sign_verbatim and key_usage is not None:
        if csr:
            log.warning(
                "Received both `key_usage` and `csr` parameters for verbatim signing. Ignoring `key_usage`."
            )
        elif "keyUsage" in csr_args:
            log.warning(
                "Received both `key_usage` and `keyUsage` parameters for verbatim signing. Ignoring `key_usage`."
            )
        else:
            norm_usages = [usage.lower() for usage in deserialize_csl(key_usage)]
            usages = ["critical", "cRLSign", "keyCertSign"]
            if "digitalsignature" in norm_usages:
                usages.append("digitalSignature")
            csr_args["keyUsage"] = usages

    return csr_args, normalized_sans or {}, norm_permitted_nc or {}, norm_excluded_nc or {}


def get_ski(cert: str | bytes | cx509.Certificate) -> str | None:
    """
    Get a certificate's subjectKeyIdentifier in pretty hex.
    """
    loaded_cert = x509util.load_cert(cert)
    try:
        ski = loaded_cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier)
    except cx509.ExtensionNotFound:  # pragma: no cover
        return None
    return _render_extension(ski)["value"]


def _getattr_safe(obj: object, attr: str) -> typing.Any:
    try:
        return getattr(obj, attr)
    except AttributeError as err:  # pragma: no cover
        # Since we cannot get the certificate object without signing,
        # we need to compare attributes marked as internal. At least
        # convert possible exceptions into some description.
        raise CommandExecutionError(
            f"Could not get attribute {attr} from {obj.__class__.__name__}. "
            "Did the internal API of cryptography change?"
        ) from err


def _get_hashing_algorithm(bitlength: str | int) -> type[hashes.HashAlgorithm]:
    try:
        return getattr(hashes, f"SHA{bitlength}")
    except AttributeError as err:  # pragma: no cover
        raise CommandExecutionError(
            "The selected hashing algorithm does not exist in the cryptography python library"
        ) from err


def _parse_general_names(
    val: Sequence[tuple[str, typing.Any]], *, name_constraints: bool = False
) -> list[cx509.GeneralName]:
    """
    We rely on a previously private API that got renamed to a public one.
    This helper ensures the call works on all versions.
    """
    try:
        parse_general_names = (
            x509util.parse_general_names  # ty: ignore[unresolved-attribute,unused-ignore-comment,unused-ignore-comment]
        )
    except AttributeError:
        # older releases
        return x509util._parse_general_names(  # ty: ignore[unresolved-attribute,unused-ignore-comment,unused-ignore-comment]
            val
        )
    return parse_general_names(val, name_constraints=name_constraints)


def _strptime(val: str | None, param: str) -> datetime | None:
    if val is None:
        return val
    try:
        return datetime.strptime(val, TIME_FMT).replace(tzinfo=timezone.utc)
    except ValueError as err:
        raise SaltInvocationError(f"Invalid date format in param `{param}`: {err}") from err


def _get_oid(oid: str) -> cx509.ObjectIdentifier:
    if not str(oid).startswith(("0", "1", "2")) or str(oid).strip("0123456789."):
        raise CommandExecutionError(f"Invalid oid: {oid}")
    return cx509.ObjectIdentifier(oid)


def _load_cert_and_chain(
    current: str,
) -> tuple[cx509.Certificate, Encoding, list[cx509.Certificate]]:
    cert, current_encoding, current_chain, _ = typing.cast(
        tuple[cx509.Certificate, Encoding, list[cx509.Certificate], typing.Any],
        x509util.load_cert(current, passphrase=None, get_encoding=True),
    )

    if (
        current_chain
        and "pkcs7" in current_encoding
        and not hasattr(x509util, "order_certs_naively")
    ):
        # This is an issue in salt.utils.x509.load_cert that was missed until recently.
        # PKCS#7 does not guarantee certificate order, so the leaf
        # certificate is not necessarily reported as the main one.
        # Identify it as the only certificate that did not issue
        # another one in the set.
        all_certs = [cert] + current_chain
        issuer_subjects = {
            crt.issuer.rfc4514_string() for crt in all_certs if crt.issuer != crt.subject
        }
        leaves = [crt for crt in all_certs if crt.subject.rfc4514_string() not in issuer_subjects]
        if len(leaves) != 1:  # pragma: no cover
            # Some weird bundle without or with more than one leaf cert.
            # Replace it, it can't match the state spec.
            raise CommandExecutionError("Invalid cert bundle: Contains multiple leaf certificates")
        cert = leaves[0]
        current_chain = [crt for crt in all_certs if crt is not cert]
    return cert, current_encoding, current_chain


def _render_extension(ext: cx509.Extension[cx509.ExtensionType]) -> dict[str, typing.Any]:
    """
    Backport otherName rendering and [e]mail fix from patched x509util.
    Also fix AIA rendering.
    Remove this once 3006.27/3008.2 are not fully supported anymore (if AIA fix lands before these releases).
    """
    if isinstance(
        ext.value,
        (cx509.SubjectAlternativeName, cx509.IssuerAlternativeName, cx509.CertificateIssuer),
    ):
        return {"critical": ext.critical, "value": [_render_gn(gn) for gn in ext.value]}
    if isinstance(ext.value, cx509.AuthorityInformationAccess):
        return {
            "value": [
                {
                    (
                        description.access_method._name
                        if description.access_method._name != "Unknown OID"
                        else description.access_method.dotted_string
                    ): _render_gn(description.access_location)
                }
                for description in ext.value
            ]
        }
    return x509util.render_extension(ext)


def _render_gn(gn: cx509.GeneralName) -> str:
    """
    Backport otherName rendering and [e]mail fix from patched x509util.
    Remove this once 3006.27/3008.2 are not fully supported anymore.
    """
    if isinstance(gn, cx509.DNSName):
        return f"DNS:{gn.value}"
    if isinstance(gn, cx509.DirectoryName):  # pragma: no cover
        return f"dirName:{gn.value.rfc4514_string()}"
    if isinstance(gn, cx509.IPAddress):
        return f"IP:{gn.value.exploded}"
    if isinstance(gn, cx509.RFC822Name):
        return f"email:{gn.value}"
    if isinstance(gn, cx509.RegisteredID):  # pragma: no cover
        return f"RID:{gn.value.dotted_string}"
    if isinstance(gn, cx509.UniformResourceIdentifier):
        return f"URI:{gn.value}"
    if isinstance(gn, cx509.OtherName):
        try:
            val = "UTF8:" + asn1.decode_der(str, gn.value)
        except ValueError:  # pragma: no cover
            val = f"<hex:{gn.value.hex()}>"
        return f"otherName:{gn.type_id.dotted_string};{val}"
    return str(gn)  # pragma: no cover


# The x509util comparison does not show extension values in changes, only the fact they were addded/changed/removed.
# We want richer change reports.


def _compare_ext(
    old: cx509.Extension[ExtensionTypeVar], new: cx509.Extension[ExtensionTypeVar]
) -> dict[str, bool | dict[str, typing.Any]]:
    changes = {}
    if old.critical is not new.critical:
        changes["critical"] = {"old": old.critical, "new": new.critical}
    if old.value == new.value:
        return changes
    comparer = EXTENSION_COMPARERS.get(type(new.value), _compare_general_ext_val)
    ext_changes = comparer(old, new)
    # Some extensions like SAN have an order that's irrelevant to us and that depends on backend factors
    if ext_changes:
        changes["value"] = ext_changes
    return changes


def _compare_general_ext_val(
    old: cx509.Extension[ExtensionTypeVar], new: cx509.Extension[ExtensionTypeVar]
) -> dict[str, typing.Any]:
    old_rend = _render_extension(old)
    if "value" in old_rend:
        old_rend = old_rend["value"]
    else:
        # Not all extension renderers render into a `value` key...
        old_rend.pop("critical", None)
    new_rend = _render_extension(new)
    if "value" in new_rend:
        new_rend = new_rend["value"]
    else:
        new_rend.pop("critical", None)
    if isinstance(new_rend, list):
        old_rend = typing.cast(list[typing.Any], old_rend)
        if (new_rend and isinstance(new_rend[0], dict)) or (
            old_rend and isinstance(old_rend[0], dict)
        ):
            added, changed, removed = [], [], []
            cnt = max(len(old_rend), len(new_rend))
            for i in range(cnt):
                try:
                    old_i = old_rend[i]
                except IndexError:
                    old_i = None
                try:
                    new_i = new_rend[i]
                except IndexError:
                    new_i = None
                if old_i is None:
                    added.append(new_i)
                elif new_i is None:
                    removed.append(old_i)
                else:
                    changed.append(dd.recursive_diff(old_i, new_i).diffs)
            changes = {}
            if added:
                changes["added"] = added
            if changed:
                changes["changed"] = changed
            if removed:
                changes["removed"] = removed
            return changes
    if not isinstance(new_rend, dict):
        return {"old": old_rend, "new": new_rend}
    return dd.recursive_diff(old_rend, new_rend).diffs


def _compare_gn_list(
    old: list[cx509.GeneralName], new: list[cx509.GeneralName]
) -> dict[ExtensionListChange, list[str]]:
    old_rend = [_render_gn(gn) for gn in old]
    new_rend = [_render_gn(gn) for gn in new]
    if (old_set := set(old_rend)) == (new_set := set(new_rend)):  # pragma: no cover
        return {}
    return {
        "added": list(sorted(new_set - old_set)),
        "removed": list(sorted(old_set - new_set)),
    }


def _compare_authority_info_access(
    old: cx509.Extension[cx509.AuthorityInformationAccess],
    new: cx509.Extension[cx509.AuthorityInformationAccess],
) -> dict[ExtensionListChange, dict[str, list[str]]]:
    old_rend = _render_extension(old)["value"]
    new_rend = _render_extension(new)["value"]
    old_vals, new_vals = {}, {}
    for entry in old_rend:
        access = next(iter(entry))
        old_vals.setdefault(access, set()).add(entry[access])
    for entry in new_rend:
        access = next(iter(entry))
        new_vals.setdefault(access, set()).add(entry[access])
    added, removed = {}, {}
    for access in set(old_vals).union(new_vals):
        added[access] = list(sorted(new_vals.get(access, set()) - old_vals.get(access, set())))
        removed[access] = list(sorted(old_vals.get(access, set()) - new_vals.get(access, set())))
    if added or removed:
        return {
            "added": {access: changed for access, changed in added.items() if changed},
            "removed": {access: changed for access, changed in removed.items() if changed},
        }
    return {}


def _compare_ext_key_usage(
    old: cx509.Extension[cx509.ExtendedKeyUsage],
    new: cx509.Extension[cx509.ExtendedKeyUsage],
) -> dict[ExtensionListChange, list[str]]:
    old_rend = set(_render_extension(old)["value"])
    new_rend = set(_render_extension(new)["value"])
    return {
        "added": list(sorted(new_rend - old_rend)),
        "removed": list(sorted(old_rend - new_rend)),
    }


def _compare_alt_names(
    old: cx509.Extension[cx509.IssuerAlternativeName | cx509.SubjectAlternativeName],
    new: cx509.Extension[cx509.IssuerAlternativeName | cx509.SubjectAlternativeName],
) -> dict[ExtensionListChange, list[str]]:
    return _compare_gn_list(list(old.value), list(new.value))


def _compare_name_constraints(
    old: cx509.Extension[cx509.NameConstraints], new: cx509.Extension[cx509.NameConstraints]
) -> dict[str, dict[ExtensionListChange, list[str]]]:
    changes = {}
    permitted_changes = _compare_gn_list(
        old.value.permitted_subtrees or [], new.value.permitted_subtrees or []
    )
    if permitted_changes:
        changes["permitted_subtrees"] = permitted_changes
    excluded_changes = _compare_gn_list(
        old.value.excluded_subtrees or [], new.value.excluded_subtrees or []
    )
    if excluded_changes:
        changes["excluded_subtrees"] = excluded_changes
    return changes


EXTENSION_COMPARERS = immutabletypes.freeze(
    {
        cx509.IssuerAlternativeName: _compare_alt_names,
        cx509.CertificateIssuer: _compare_gn_list,
        cx509.AuthorityInformationAccess: _compare_authority_info_access,
        cx509.SubjectAlternativeName: _compare_alt_names,
        cx509.ExtendedKeyUsage: _compare_ext_key_usage,
        # cx509.CRLDistributionPoints: _compare_distribution_points,
        # cx509.FreshestCRL: _compare_distribution_points,
        # cx509.IssuingDistributionPoint: _compare_issuing_distribution_point,
        # cx509.CertificatePolicies: _compare_certificate_policies,
        cx509.NameConstraints: _compare_name_constraints,
    }
)
