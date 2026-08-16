"""
Vault PKI helpers

.. versionadded:: 1.1.0
"""

import ipaddress
import logging
import typing
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
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault.helpers import timestring_map

try:
    _compare_cert = x509util._compare_cert
except AttributeError:
    from salt.states.x509_v2 import (  # pylint: disable=no-name-in-module  # isort:skip
        _compare_cert,  # ty: ignore[unresolved-import]
    )


log = logging.getLogger(__name__)
Privkey: typing.TypeAlias = (
    ec.EllipticCurvePrivateKey
    | ed448.Ed448PrivateKey
    | ed25519.Ed25519PrivateKey
    | rsa.RSAPrivateKey
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

SUPPORTED_SAN_TYPES = ("DNS", "EMAIL", "IP", "URI")
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


def check_cert_for_changes(
    current: str,
    issuer: str,
    private_key: str,
    common_name: str,
    encoding: Encoding = "pem",
    common_name_only: bool = False,
    append_chain: list[str] | str | None = None,
    private_key_passphrase: str | None = None,
    expire_tolerance: int | str | None = None,
    alt_names: dict[str, str | list[str]] | list[str] | None = None,
    **kwargs,
) -> dict[str, typing.Any]:
    """
    current
        Path of the certificate on disk

    issuer
        Issuer certificate

    private_key
        Path of the private key on disk

    common_name
        CN

    encoding
        Requested certificate encoding

    common_name_only
        Skip change detection on subject fields other than CN.

    append_chain
        List of certificates to append. Fails with der

    private_key_passphrase
        Passphrase for ``private_key``

    expire_tolerance
        Otherwise called ``ttl_remaining``, minimum TTL to allow
        before requesting a fresh certificate.

    alt_names
        Requested SANs

    kwargs
        All other kwargs passed to the cert signing endpoint
    """
    changes: dict[str, typing.Any] = {}
    expire_tolerance = expire_tolerance or 0
    append_chain = append_chain or []

    try:
        cert, current_encoding, current_chain, _ = typing.cast(
            tuple[cx509.Certificate, Encoding, list[cx509.Certificate], typing.Any],
            x509util.load_cert(current, passphrase=None, get_encoding=True),
        )
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

    if current_chain and "pkcs7" in encoding and not hasattr(x509util, "order_certs_naively"):
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
            changes["replaced"] = True
            return changes
        cert = leaves[0]
        current_chain = [crt for crt in all_certs if crt is not cert]

    if encoding != current_encoding:
        changes["encoding"] = {
            "old": current_encoding,
            "new": encoding,
        }

    # Check common_name. This is always checked as a major
    # and required attribute for each certificate.
    # FIXME: Unless the role has `require_cn` set to false.
    current_cn = cert.subject.get_attributes_for_oid(x509util.NAME_ATTRS_OID["CN"])[0].value
    if current_cn != common_name:
        changes.update({"subject": {"CN": {"old": current_cn, "new": common_name}}})

    # If we need to compare Common Name only we can skip this one
    if not common_name_only:
        for k, v in x509util.NAME_ATTRS_OID.items():
            # Just in case ignore CN attribute if passed by mistake
            if k == "CN":
                continue
            if k in kwargs:
                current_attr = cert.subject.get_attributes_for_oid(v)
                if current_attr:
                    attr = current_attr[0]
                    if kwargs[k] != attr.value:
                        typing.cast(
                            dict[str, dict[str, dict[str, str]]], changes.setdefault("subject", {})
                        ).update({k: {"old": attr.value, "new": kwargs[k]}})
                else:
                    typing.cast(
                        dict[str, dict[str, dict[str, str]]], changes.setdefault("subject", {})
                    ).update({k: {"old": "", "new": kwargs[k]}})

    san_changes, change_type = compare_sans(
        cert, alt_names or [], common_name, kwargs.get("exclude_cn_from_sans", False)
    )
    if san_changes:
        changes.setdefault("extensions", {}).setdefault(change_type, {})[
            "subjectAltName"
        ] = san_changes

    loaded_chain: list[cx509.Certificate] = [x509util.load_cert(x) for x in append_chain]
    # Filter self-signed CA, which shouldn't be in the chain.
    loaded_chain = [
        cert
        for cert in loaded_chain
        if cert.subject.rfc4514_string() != cert.issuer.rfc4514_string()
    ]
    if not compare_ca_chain(current_chain or [], loaded_chain, unordered="pkcs7" in encoding):
        changes["ca_chain"] = True

    ca = x509util.load_cert(issuer)
    privkey: Privkey = x509util.load_privkey(private_key, private_key_passphrase)
    changes.update(
        compare_cert_signing(
            current=cert,
            signing_ca=ca,
            private_key=privkey,
        )
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

    return changes


def check_root_issuer_for_changes(
    cert,
    *,
    common_name: str,
    alt_names: dict[str, str | list[str]] | list[str] | None,
    days_valid: int,
    max_path_length: int,
    key_usage: list[str] | str | None,
    exclude_cn_from_sans: bool,
    permitted_alt_names: dict[str, str | list[str]] | list[str] | None,
    excluded_alt_names: dict[str, str | list[str]] | list[str] | None,
    ou: list[str] | str | None,
    organization: list[str] | str | None,
    country: list[str] | str | None,
    locality: list[str] | str | None,
    province: list[str] | str | None,
    street_address: list[str] | str | None,
    postal_code: list[str] | str | None,
    subject_serial_number: str | None,
    signature_bits: int,
    not_before_duration: str | int,
    not_after: str | None,
    days_remaining: int,
    urls: dict[str, list[str]],
):
    changes = {}
    # Since we load a cert from Vault, we must assume loading it works, no error handling necessary
    current = typing.cast(cx509.Certificate, x509util.load_cert(cert, passphrase=None))

    if signature_bits:
        if current.signature_hash_algorithm is not None and not isinstance(
            current.signature_hash_algorithm,
            get_hashing_algorithm(signature_bits),
        ):
            algo = type(current.signature_hash_algorithm).__name__
            cur_bits = None
            if algo.startswith("SHA"):
                try:
                    cur_bits = int(algo[3:])
                except (TypeError, ValueError):
                    pass
            changes["signature_bits"] = {"old": cur_bits, "new": signature_bits}

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
        subject_serial_number=subject_serial_number,
        not_before_duration=not_before_duration,
        not_after=not_after,
        urls=urls,
        signing_cert=None,
        public_key=current.public_key(),  # type: ignore
    )
    try:
        curr_not_after = current.not_valid_after_utc
    except AttributeError:  # pragma: no cover
        # naive datetime object, release <42 (it's always UTC)
        curr_not_after = current.not_valid_after.replace(tzinfo=timezone.utc)
    new_not_after = _getattr_safe(builder, "_not_valid_after").replace(tzinfo=timezone.utc)
    if (not_after is not None and curr_not_after != new_not_after) or (
        not_after is None
        and curr_not_after < datetime.now(tz=timezone.utc) + timedelta(days=days_remaining)
    ):
        changes["expiration"] = {
            "old": curr_not_after.strftime(TIME_FMT),
            "new": new_not_after.strftime(TIME_FMT),
        }
    changes.update(_compare_cert(current, builder, None, None, None, None))
    return changes


def _build_root_issuer_cert(  # pylint: disable=too-many-locals
    *,
    common_name: str,
    alt_names: dict[str, str | list[str]] | list[str] | None = None,
    days_valid: int,
    max_path_length: int,
    key_usage: list[str] | str | None,
    exclude_cn_from_sans: bool,
    permitted_alt_names: dict[str, str | list[str]] | list[str] | None,
    excluded_alt_names: dict[str, str | list[str]] | list[str] | None,
    ou: list[str] | str | None,
    organization: list[str] | str | None,
    country: list[str] | str | None,
    locality: list[str] | str | None,
    province: list[str] | str | None,
    street_address: list[str] | str | None,
    postal_code: list[str] | str | None,
    subject_serial_number: str | None,
    not_before_duration: str | int,
    not_after: str | None,
    urls: dict[str, list[str]],
    signing_cert: cx509.Certificate | None,
    public_key: CertificateIssuerPublicKeyTypes,
) -> cx509.CertificateBuilder:
    builder = cx509.CertificateBuilder(public_key=public_key)

    # Subject/Issuer DN
    subject_rdns = []
    for oid, vals in (
        (cx509.NameOID.COUNTRY_NAME, country),
        (cx509.NameOID.STATE_OR_PROVINCE_NAME, province),
        (cx509.NameOID.LOCALITY_NAME, locality),
        (cx509.NameOID.STREET_ADDRESS, street_address),
        (cx509.NameOID.POSTAL_CODE, postal_code),
        (cx509.NameOID.ORGANIZATION_NAME, organization),
        (cx509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        (cx509.NameOID.COMMON_NAME, common_name),
        (cx509.NameOID.SERIAL_NUMBER, subject_serial_number),
    ):
        if vals is None:
            continue
        if not isinstance(vals, list):
            vals = [vals]
        subject_rdns.append(
            cx509.RelativeDistinguishedName(cx509.NameAttribute(oid, val) for val in vals)
        )
    subject_dn = cx509.Name(subject_rdns)
    builder = builder.subject_name(subject_dn).issuer_name(
        subject_dn if signing_cert is None else signing_cert.subject
    )

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
    if key_usage is not None:
        if not isinstance(key_usage, list):
            key_usage = [key_usage]
        key_usage = [usage.lower() for usage in key_usage]  # it's case-insensitive
        key_usages["digital_signature"] = "digitalsignature" in key_usage
    builder = builder.add_extension(cx509.KeyUsage(**key_usages), critical=True)

    # subjectAlternativeName
    if alt_names or not exclude_cn_from_sans:
        normalized_sans = norm_sans(alt_names or [])
        if not exclude_cn_from_sans:
            normalized_sans.setdefault("DNS", []).insert(0, common_name)
        # x509util needs another format still
        flattened_sans = []
        # we also need to ensure the order is the same as Vault's
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
            sans = _parse_general_names(flattened_other_sans + flattened_sans)
        except SaltInvocationError as err:  # pragma: no cover
            if "otherName is currently not implemented" not in str(err):
                raise
            log.warning(
                "Salt core x509_v2 does not support otherName. "
                "Consider updating it. "
                "The state will not be idempotent."
            )
            sans = _parse_general_names(flattened_sans)
        builder = builder.add_extension(cx509.SubjectAlternativeName(sans), critical=False)

    # nameConstraints
    if permitted_alt_names or excluded_alt_names:
        nc_subtrees = {
            "permitted_subtrees": None,
            "excluded_subtrees": None,
        }
        # we also need to ensure the order is the same as Vault's, which is different than for SANs
        ordered_nc_typs = ("DNS", "IP", "EMAIL", "URI")
        if permitted_alt_names is not None:
            normalized_permitted_nc = norm_sans(permitted_alt_names, allow_other_name=False)
            flattened_permitted_nc = []
            for nc_typ in ordered_nc_typs:
                for val in normalized_permitted_nc.get(nc_typ, []):
                    flattened_permitted_nc.append((nc_typ, val))
            nc_subtrees["permitted_subtrees"] = _parse_general_names(
                flattened_permitted_nc, name_constraints=True
            )
        if excluded_alt_names is not None:
            normalized_excluded_nc = norm_sans(excluded_alt_names, allow_other_name=False)
            flattened_excluded_nc = []
            for nc_typ in ordered_nc_typs:
                for val in normalized_excluded_nc.get(nc_typ, []):
                    flattened_excluded_nc.append((nc_typ, val))
            nc_subtrees["excluded_subtrees"] = _parse_general_names(
                flattened_excluded_nc, name_constraints=True
            )
        name_constraints = cx509.NameConstraints(**nc_subtrees)
        builder = builder.add_extension(name_constraints, critical=True)

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

    # subjectKeyIdentifier
    builder = builder.add_extension(
        cx509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )
    # authorityKeyIdentifier
    builder = builder.add_extension(
        cx509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False
    )
    return builder


def compare_cert_signing(
    current: cx509.Certificate, signing_ca: cx509.Certificate, private_key: Privkey
) -> dict[str, typing.Any]:
    changes = {}

    if signing_ca and not x509util.verify_signature(current, signing_ca.public_key()):
        changes["signing_private_key"] = True

    # Check correctly if issuer is the same
    if _getattr_safe(signing_ca, "subject") != _getattr_safe(current, "issuer"):
        changes["issuer_name"] = {
            "old": _getattr_safe(current, "issuer").rfc4514_string(),
            "new": _getattr_safe(signing_ca, "subject").rfc4514_string(),
        }

    if not x509util.is_pair(current.public_key(), private_key):
        changes["private_key"] = True

    return changes


def compare_ca_chain(
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


def compare_sans(
    cert: cx509.Certificate,
    alt_names: dict[str, str | list[str]] | list[str],
    common_name: str,
    exclude_cn_from_sans: bool = False,
) -> tuple[dict[str, list[str]], ExtensionChange] | tuple[None, None]:
    """
    Compare requested DNS, EMAIL, IP, URI and other SANs against the ones present in a certificate.
    """
    normalized_sans = norm_sans(alt_names)
    requested_sans = _collect_requested_sans(normalized_sans)
    current_sans = _collect_current_sans(cert)

    if not exclude_cn_from_sans:
        current_sans.discard(("dns", common_name))
    if requested_sans == current_sans:
        return None, None
    change_type = "added" if not current_sans else "removed" if not requested_sans else "changed"

    def render(typ, val):
        return f"{typ}:{val}" if ":" not in typ else f"{typ};{val}"

    return {
        "added": sorted(render(*san) for san in requested_sans - current_sans),
        "removed": sorted(render(*san) for san in current_sans - requested_sans),
    }, change_type


def norm_sans(
    sans: dict[str, str | list[str]] | list[str],
    *,
    allow_other_name: bool = True,
) -> dict[str, list[str]]:
    """
    Normalize all allowed inputs for SubjectAlternativeNames into a dict of lists
    with uppercase keys.
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


def _collect_requested_sans(
    alt_names: dict[str, list[str]],
) -> set[tuple[str, str]]:
    """
    Collect a set of requested SubjectAlternativeNames from a normalized dict of lists
    with uppercase keys.

    Note: Ignores types other than DNS/EMAIL/IP/URI.
    """
    requested = set()
    for typ, vals in alt_names.items():
        if typ == "DNS":
            requested.update(("dns", val) for val in vals)
        elif typ == "EMAIL":
            requested.update(("email", val) for val in vals)
        elif typ == "IP":
            for val in vals:
                try:
                    val = str(ipaddress.ip_address(val))
                except ValueError:
                    pass
                requested.add(("ip", val))
        elif typ == "URI":
            requested.update(("uri", val) for val in vals)
        else:
            requested.update((f"otherName:{typ}", f"UTF8:{val}") for val in vals)
    return requested


def _collect_current_sans(cert: cx509.Certificate) -> set[tuple[str, str]]:
    """
    Collect a set of requested SubjectAlternativeNames from a normalized dict of lists
    with uppercase keys.

    Note: Ignores types other than DNS/EMAIL/IP/URI.
    """
    try:
        ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
    except cx509.ExtensionNotFound:
        return set()
    current_sans = set()
    for name in ext:
        if isinstance(name, cx509.DNSName):
            current_sans.add(("dns", name.value))
        elif isinstance(name, cx509.RFC822Name):
            current_sans.add(("email", name.value))
        elif isinstance(name, cx509.IPAddress):
            current_sans.add(("ip", str(name.value)))
        elif isinstance(name, cx509.UniformResourceIdentifier):
            current_sans.add(("uri", name.value))
        elif isinstance(name, cx509.OtherName):
            try:
                value = "UTF8:" + asn1.decode_der(str, name.value)
            except ValueError:
                # Going to be removed since Vault does not support other ASN.1 types
                value = "<undetermined, not UTF8 ASN.1 type>"
            current_sans.add((f"otherName:{name.type_id.dotted_string}", value))
        elif isinstance(name, cx509.DirectoryName):
            current_sans.add(("dirName", name.value.rfc4514_string()))
        elif isinstance(name, cx509.RegisteredID):
            current_sans.add(("rid", name.value.dotted_string))
        else:  # pragma: no cover
            log.warning(f"Unknown GeneralName type in subjectAltName extension: {type(name)}")
    return current_sans


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


def get_hashing_algorithm(bitlength: str | int) -> type[hashes.HashAlgorithm]:
    try:
        return getattr(hashes, f"SHA{bitlength}")
    except AttributeError as err:
        raise CommandExecutionError(
            "The selected hashing algorithm does not exist in the cryptography python library"
        ) from err


def _parse_general_names(val, *, name_constraints=False) -> list[cx509.GeneralName]:
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
