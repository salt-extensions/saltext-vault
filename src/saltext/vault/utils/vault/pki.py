"""
Vault PKI helpers

.. versionadded:: 1.1.0
"""

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import List

import salt.utils.x509 as x509util
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault.helpers import timestring_map


def check_cert_for_changes(
    current,
    issuer,
    private_key,
    common_name: str,
    encoding="pem",
    common_name_only=False,
    append_chain=None,
    private_key_passphrase=None,
    expire_tolerance=None,
    **kwargs,
) -> dict:

    changes = {}

    expire_tolerance = expire_tolerance or 0

    append_chain = append_chain or []
    if not isinstance(append_chain, list):
        append_chain = [append_chain]

    try:
        (
            current,
            current_encoding,
            current_chain,
            _,
        ) = x509util.load_cert(current, passphrase=None, get_encoding=True)
    except SaltInvocationError as err:
        if any(
            (
                "Could not deserialize binary data" in str(err),
                "Could not load PEM-encoded" in str(err),
            )
        ):
            changes["replaced"] = True
            return changes
        else:
            raise

    if encoding != current_encoding:
        changes["encoding"] = {
            "old": current_encoding,
            "new": encoding,
        }

    # Check common_name. This is always checked as a major
    # and required attribute for each certificate.
    current_cn = current.subject.get_attributes_for_oid(x509util.NAME_ATTRS_OID["CN"])[0].value
    if current_cn != common_name:
        changes.update({"subject": {"CN": {"old": current_cn, "new": common_name}}})

    # If we need to compare Common Name only we can skip this one
    if not common_name_only:
        for k, v in x509util.NAME_ATTRS_OID.items():
            # Just in case ignore CN attribute if passed by mistake
            if k == "CN":
                continue
            if k in kwargs:
                current_attr = current.subject.get_attributes_for_oid(v)
                if current_attr:
                    attr = current_attr[0]
                    if kwargs[k] != attr.value:
                        changes.update({"subject": {k: {"old": attr.value, "new": kwargs[k]}}})
                else:
                    changes.update({"subject": {k: {"old": "", "new": kwargs[k]}}})

    append_chain = [x509util.load_cert(x) for x in append_chain]
    for ca in append_chain:
        if ca.subject.rfc4514_string() == ca.issuer.rfc4514_string():
            # Self-signed CA. Shouldn't be in the chain.
            append_chain.remove(ca)
            continue

    if not compare_ca_chain(current_chain, append_chain):
        changes["ca_chain"] = True

    ca = x509util.load_cert(issuer)
    privkey = x509util.load_privkey(private_key, private_key_passphrase)

    changes.update(
        compare_cert_signing(
            current=current,
            signing_ca=ca,
            private_key=privkey,
        )
    )

    # Check if certificate should be renewed due to close to expiration
    try:
        curr_not_valid_after = current.not_valid_after_utc
    except AttributeError:
        curr_not_valid_after = current.not_valid_after.replace(tzinfo=timezone.utc)

    if curr_not_valid_after < datetime.now(timezone.utc) + timedelta(
        seconds=timestring_map(expire_tolerance, cast=int)
    ):
        changes["expiration"] = {
            "expire_in": (curr_not_valid_after - datetime.now(timezone.utc)).total_seconds(),
            "toleration": timestring_map(expire_tolerance, cast=int),
        }

    return changes


def compare_cert_signing(current: cx509.Certificate, signing_ca: cx509.Certificate, private_key):
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


def compare_ca_chain(current: List[cx509.Certificate], new: List[cx509.Certificate]):
    if len(current) != len(new):
        return False
    for i, new_cert in enumerate(new):
        if new_cert.fingerprint(hashes.SHA256()) != current[i].fingerprint(hashes.SHA256()):
            return False
    return True


def dec2hex(decval):
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


def _getattr_safe(obj, attr):
    try:
        return getattr(obj, attr)
    except AttributeError as err:
        # Since we cannot get the certificate object without signing,
        # we need to compare attributes marked as internal. At least
        # convert possible exceptions into some description.
        raise CommandExecutionError(
            f"Could not get attribute {attr} from {obj.__class__.__name__}. "
            "Did the internal API of cryptography change?"
        ) from err


def _pretty_hex(hex_str):
    """
    Nicely formats hex strings
    """
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return ":".join([hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]).upper()
