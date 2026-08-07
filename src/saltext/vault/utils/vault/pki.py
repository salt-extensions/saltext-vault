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
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault.helpers import timestring_map

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

    if current_chain and "pkcs7" in encoding:
        # This is an issue in salt.utils.x509.load_cert that was missed so far.
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
    if not compare_ca_chain(current_chain or [], loaded_chain):
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


def compare_cert_signing(
    current: cx509.Certificate, signing_ca: cx509.Certificate, private_key: Privkey
):
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


def compare_ca_chain(current: list[cx509.Certificate], new: list[cx509.Certificate]):
    if len(current) != len(new):
        return False
    # Compare without regarding the order since some encodings
    # do not guarantee it (PKCS#7)
    current_fprints = {crt.fingerprint(hashes.SHA256()) for crt in current}
    new_fprints = {crt.fingerprint(hashes.SHA256()) for crt in new}
    return current_fprints == new_fprints


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
) -> dict[str, list[str]]:
    """
    Normalize all allowed inputs for SubjectAlternativeNames into a dict of lists
    with uppercase keys.
    """
    parsed: dict[str, list[str]] = {}

    def _norm(typ):
        typ = typ.upper()
        if typ not in SUPPORTED_SAN_TYPES:
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
    Render a normalized dict of lists of SubjectAlternativeNames into a format
    Vault understands and return each type separately.
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


def dec2hex(decval: int | str) -> str:
    """
    Converts decimal values to nicely formatted hex strings
    """
    try:
        decval = int(decval)
    except (TypeError, ValueError) as exc:
        raise SaltInvocationError(f"input must be integer. got {type(decval)} instead") from exc

    if decval < 0:
        raise SaltInvocationError("input must be non-negative integer")

    return _pretty_hex(f"{decval:X}")


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


def _pretty_hex(hex_str: str) -> str:
    """
    Nicely formats hex strings
    """
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return ":".join([hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]).upper()
