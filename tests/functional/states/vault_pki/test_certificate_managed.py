"""
Tests for the (ca_)certificate_managed states:
issuance lifecycle, file handling and remote issuance constraints.
"""

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from salt.utils.x509 import NAME_ATTRS_OID
from salt.utils.x509 import generate_rsa_privkey
from salt.utils.x509 import load_cert

from saltext.vault.states.vault_pki import ROLE_ATTRS_UNVERIFIED_NOTE
from tests.common.containers import genmarks
from tests.common.helpers.vault_pki import AIA_UNVERIFIED_NOTE
from tests.common.helpers.vault_pki import MOUNT_URL_CONFIG
from tests.common.helpers.vault_pki import _assert_embedded_aia
from tests.common.helpers.vault_pki import _not_valid_after
from tests.support.vault import vault_write

pytestmark = genmarks(mounts="pki")


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_create(cert_typ, testmode):
    cert_managed, cert_args = cert_typ
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "created" in ret.changes
    assert Path(cert_args["name"]).exists() is not testmode


@pytest.mark.usefixtures("issuer_setup", "existing_cert")
def test_ca_certificate_managed_ok(cert_typ, testmode):
    cert_managed, cert_args = cert_typ
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_ca_certificate_managed_ttl_exceeds_mount_max(vault_pki, ca_cert_args):
    """
    Ensure the requested validity is translated into ``not_after`` and thus
    not capped at the mount's ``max_lease_ttl``.
    """
    ca_cert_args["ttl"] = "43200h"
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    cert = load_cert(ca_cert_args["name"])
    expected_not_after = datetime.now(tz=timezone.utc) + timedelta(hours=43200)
    assert abs((_not_valid_after(cert) - expected_not_after).total_seconds()) < 86400


@pytest.mark.usefixtures("issuer_setup")
def test_ca_certificate_managed_not_after_exceeding_issuer(vault_pki, ca_cert_args):
    """
    An explicit not_after beyond the signing issuer's expiry would be truncated
    during issuance, resulting in repeated changes. Ensure the state refuses it early.
    """
    ca_cert_args["not_after"] = "2040-01-01T00:00:00Z"
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is False
    assert "exceeds the signing issuer's expiry" in ret.comment
    assert not ret.changes
    assert not Path(ca_cert_args["name"]).exists()

    # Unless the issuer explicitly permits exceeding its own validity
    # and its behavior enforcement is requested
    vault_write("pki/issuer/root", issuer_name="root", leaf_not_after_behavior="permit")
    ca_cert_args["enforce_leaf_not_after_behavior"] = True
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    cert = load_cert(ca_cert_args["name"])
    assert _not_valid_after(cert) == datetime(2040, 1, 1, tzinfo=timezone.utc)
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_ca_certificate_managed_issuer_expiry_undercuts_ttl_remaining(vault_pki, ca_cert_args):
    """
    A ttl_remaining beyond the signing issuer's remaining validity would mean
    each issued certificate is immediately due for renewal.
    Ensure the state refuses this.
    """
    ca_cert_args["ttl"] = "100000h"
    ca_cert_args["ttl_remaining"] = "87600h"
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is False
    assert "`ttl_remaining` is undercut by the signing issuer's expiry" in ret.comment
    assert not ret.changes
    assert not Path(ca_cert_args["name"]).exists()


@pytest.mark.usefixtures("issuer_setup")
def test_ca_certificate_managed_issuance_error_reported_early(
    vault_pki, ca_cert_args, container, testmode
):
    """
    When the signing issuer errors out instead of truncating during CA issuance
    (``leaf_not_after_behavior=always_enforce_err`` or enforcement of the default
    ``err`` requested), ensure the state fails early if the requested validity
    exceeds the issuer's expiry, even in test mode.
    """
    if container.matches("vault>=1.18.2"):
        vault_write(
            "pki/issuer/root", issuer_name="root", leaf_not_after_behavior="always_enforce_err"
        )
    else:
        # `always_enforce_err` requires Vault 1.18.2+ and is unsupported on OpenBao
        # (as of Sep 2026), so test the enforcement condition on the others.
        # The flag itself is Vault 1.17+ only, but this still works on 1.14.8
        # since the request is never sent.
        ca_cert_args["enforce_leaf_not_after_behavior"] = True
    ca_cert_args["ttl"] = "100000h"
    ret = vault_pki.ca_certificate_managed(**ca_cert_args, test=testmode)
    assert ret.result is False
    assert "Issuance would fail" in ret.comment
    assert "exceeds the signing issuer's expiry" in ret.comment
    assert "created" in ret.changes
    assert not Path(ca_cert_args["name"]).exists()


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_is_reissued_forcibly(vault_pki, cert_args, testmode):
    ret = vault_pki.certificate_managed(**cert_args)
    assert "created" in ret.changes
    serial = load_cert(cert_args["name"]).serial_number

    cert_args["reissue"] = True
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert (ret.result is None) is testmode
    assert "replaced" in ret.changes
    assert (load_cert(cert_args["name"]).serial_number == serial) is testmode


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("encoding", ["der", "pem", "pkcs7_der", "pkcs7_pem"])
def test_certificate_managed_encoding(cert_typ, testmode, encoding):
    cert_managed, cert_args = cert_typ
    cert_args["encoding"] = encoding
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    _, enc, _, _ = load_cert(cert_args["name"], get_encoding=True)
    assert enc == encoding
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_no_create(cert_typ, testmode):
    cert_managed, cert_args = cert_typ
    cert_args["create"] = False
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert not Path(cert_args["name"]).exists()


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("follow_symlinks", (False, True))
def test_certificate_managed_symlink(cert_typ, tmp_path, follow_symlinks, testmode):
    cert_managed, cert_args = cert_typ
    ret = cert_managed(**cert_args)
    assert ret.result is True
    link = tmp_path / "cert_link"
    link.symlink_to(cert_args["name"])
    cert_args["name"] = str(link)
    cert_args["follow_symlinks"] = follow_symlinks
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is not False
    if follow_symlinks:
        # the managed file is the symlink target, which is in the correct state
        assert ret.result is True
        assert not ret.changes
        assert link.is_symlink()
    else:
        assert (ret.result is None) is testmode
        assert "replaced" in ret.changes
        # the symlink should have been replaced by a regular file
        assert link.is_symlink() is testmode


@pytest.mark.usefixtures("issuer_setup_sub", "roles_setup")
@pytest.mark.parametrize("encoding", ["der", "pem", "pkcs7_der", "pkcs7_pem"])
def test_certificate_managed_includes_chain(cert_typ, encoding, testmode):
    cert_managed, cert_args = cert_typ
    cert_args["encoding"] = encoding
    cert_args["append_ca_chain"] = True
    cert_args["issuer_ref"] = "sub"

    is_der = encoding == "der"
    if is_der:
        ret = cert_managed(**cert_args, test=testmode)
        assert ret.result is False
        assert "Cannot append the CA chain" in ret.comment
        assert not ret.changes
        return

    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    _, enc, chain, _ = load_cert(cert_args["name"], get_encoding=True)
    assert enc == encoding
    assert len(chain) == 1

    # Ensure it's idempotent still
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_certificate_managed_missing_role(vault_pki, cert_args, testmode):
    cert_args["role_name"] = "missing-role"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "Role missing-role does not exist" in ret.comment


@pytest.mark.parametrize(
    "testrole", ({"organization": "Test Org", "ou": "Test Unit"},), indirect=True
)
@pytest.mark.usefixtures("testrole", "issuer_setup", "roles_setup", "role_read_denied")
def test_certificate_managed_role_read_denied(vault_pki, cert_args):
    """
    When role read access is denied and issuer_ref is specified explicitly,
    issuance still works and drift in role-derived subject attributes/extensions
    must not cause a reissuance, only a note.
    """
    cert_args["issuer_ref"] = "root"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    assert ROLE_ATTRS_UNVERIFIED_NOTE.format(role_name="testrole", mount="pki") not in ret.comment
    cert = load_cert(cert_args["name"])
    assert cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["O"])[0].value == "Test Org"

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes
    assert ROLE_ATTRS_UNVERIFIED_NOTE.format(role_name="testrole", mount="pki") in ret.comment
    assert load_cert(cert_args["name"]).serial_number == cert.serial_number


@pytest.mark.parametrize(
    "testrole", ({"organization": "Test Org", "ou": "Test Unit"},), indirect=True
)
@pytest.mark.usefixtures("testrole", "existing_cert", "role_read_denied")
def test_certificate_managed_role_read_denied_controlled_attrs_verified(vault_pki, cert_args):
    """
    Subject attributes under the state's direct control (like CN) must still
    be verified when role-derived attributes cannot be.
    """
    serial = load_cert(cert_args["name"]).serial_number
    cert_args["issuer_ref"] = "root"
    cert_args["common_name"] = "changed.example.com"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "subject_name" in ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != serial
    assert (
        cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])[0].value == "changed.example.com"
    )
    # Vault still applies the role-derived attributes during issuance
    assert cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["O"])[0].value == "Test Org"


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "role_read_denied")
def test_certificate_managed_role_read_denied_without_issuer_ref(vault_pki, cert_args, testmode):
    """
    Without an explicit issuer_ref, the role provides the issuer reference,
    so a denied role read cannot be masked and must fail the state.
    """
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "PermissionDenied" in ret.comment


@pytest.mark.parametrize("aia_urls", (MOUNT_URL_CONFIG,), indirect=True)
@pytest.mark.usefixtures("issuer_setup", "roles_setup", "url_config_read_denied")
def test_certificate_managed_url_config_denied(vault_pki, cert_args, aia_urls):
    """
    Ensure a denied URL read access does not cause reissuance, only a note.
    """
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    assert AIA_UNVERIFIED_NOTE not in ret.comment
    cert = load_cert(cert_args["name"])
    _assert_embedded_aia(cert, aia_urls)

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes
    assert "The certificate is in the correct state" in ret.comment
    assert AIA_UNVERIFIED_NOTE in ret.comment
    assert load_cert(cert_args["name"]).serial_number == cert.serial_number


@pytest.mark.parametrize("aia_urls", (MOUNT_URL_CONFIG,), indirect=True)
@pytest.mark.usefixtures("issuer_setup", "url_config_read_denied")
def test_ca_certificate_managed_url_config_denied(vault_pki, ca_cert_args, aia_urls):
    """
    Ensure a denied URL read access does not cause reissuance, only a note.
    """
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    assert AIA_UNVERIFIED_NOTE not in ret.comment
    cert = load_cert(ca_cert_args["name"])
    _assert_embedded_aia(cert, aia_urls)

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes
    assert "The certificate is in the correct state" in ret.comment
    assert AIA_UNVERIFIED_NOTE in ret.comment
    assert load_cert(ca_cert_args["name"]).serial_number == cert.serial_number


@pytest.mark.usefixtures("issuer_setup_sub", "roles_setup")
@pytest.mark.parametrize("change", ("ca_chain", "encoding"))
def test_certificate_managed_local_changes_are_recreated(cert_typ, change):
    """
    Changes to the encoding or the appended CA chain only should not
    cause a reissuance, but be applied locally to the existing certificate.
    """
    cert_managed, cert_args = cert_typ
    cert_args["issuer_ref"] = "sub"
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    serial = load_cert(cert_args["name"]).serial_number

    if change == "ca_chain":
        cert_args["append_ca_chain"] = True
    else:
        cert_args["encoding"] = "pkcs7_pem"
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert ret.changes
    assert not set(ret.changes) - {"ca_chain", "encoding"}
    assert "recreated" in ret.comment

    cert, enc, chain, _ = load_cert(cert_args["name"], get_encoding=True)
    # the certificate itself should not have been reissued
    assert cert.serial_number == serial
    if change == "ca_chain":
        assert len(chain) == 1
    else:
        assert enc == "pkcs7_pem"


@pytest.mark.usefixtures("issuer_setup")
def test_certificate_managed_without_role_name(vault_pki, cert_args):
    cert_args.pop("role_name")
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is False
    assert "`role_name` is required" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_certificate_managed_verbatim_without_role_name(vault_pki, cert_args):
    cert_args.pop("role_name")
    cert_args["sign_verbatim"] = True
    ret = vault_pki.certificate_managed(**cert_args)

    assert ret.result is True
    assert "created" in ret.changes
    assert load_cert(cert_args["name"]).serial_number


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("existing_cert", ({"mode": "0644"},), indirect=True)
def test_certificate_managed_file_param_changes_only(cert_typ, existing_cert, testmode):
    """
    Changes affecting only the managed file (like its mode) should be
    applied via file.managed without recreating the certificate.
    """
    cert_managed, cert_args = cert_typ
    cert_path = Path(cert_args["name"])
    assert oct(cert_path.stat().st_mode)[-4:] == "0644"
    existing_cert = load_cert(cert_args["name"]).serial_number

    cert_args["mode"] = "0600"
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    # the certificate itself should be unchanged
    assert load_cert(cert_args["name"]).serial_number == existing_cert
    assert oct(cert_path.stat().st_mode)[-4:] == ("0644" if testmode else "0600")


def test_certificate_managed_changed_private_key(cert_typ, existing_cert):
    """
    A certificate whose public key does not match the specified private
    key anymore should be reissued.
    """
    cert_managed, cert_args = cert_typ
    new_privkey = generate_rsa_privkey(2048)
    cert_args["private_key"] = new_privkey.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "private_key" in ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    assert cert.public_key().public_numbers() == new_privkey.public_key().public_numbers()


@pytest.mark.parametrize("existing_cert", ({"ttl": "10m"},), indirect=True)
def test_certificate_managed_expiry(cert_typ, existing_cert):
    """
    A certificate that expires within ``ttl_remaining`` should be reissued.
    """
    cert_managed, cert_args = cert_typ
    cert_args["ttl"] = "30m"
    cert_args["ttl_remaining"] = "15m"
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "expiration" in ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    assert cert.not_valid_after_utc - cert.not_valid_before_utc > timedelta(minutes=15)


@pytest.mark.parametrize("existing_cert", ({"ttl": "10m"},), indirect=True)
def test_certificate_managed_expiry_reports_capped_not_after(
    vault_pki, cert_args, existing_cert
):  # pylint: disable=unused-argument
    """
    The role's max_ttl caps the effective certificate validity.
    Ensure change reports account for this instead of reflecting
    the requested validity.
    """
    # testrole's max_ttl is one day, which undercuts the requested 48h
    cert_args["ttl"] = "48h"
    cert_args["ttl_remaining"] = "15m"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "expiration" in ret.changes
    reported = datetime.strptime(ret.changes["not_after"]["new"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    expected = datetime.now(tz=timezone.utc) + timedelta(hours=24)
    assert abs((reported - expected).total_seconds()) < 300
    cert = load_cert(cert_args["name"])
    assert abs((_not_valid_after(cert) - expected).total_seconds()) < 300


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_not_after_exceeding_max_ttl(vault_pki, cert_args):
    """
    An explicit not_after beyond the role's max_ttl would be truncated during
    issuance, resulting in repeated changes. Ensure the state refuses it early.
    Within the limit, it should be applied faithfully and converge.
    """
    cert_args["ttl_remaining"] = "1h"
    cert_args["not_after"] = (datetime.now(tz=timezone.utc) + timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is False
    assert "exceeds the role's `max_ttl`" in ret.comment
    assert not ret.changes
    assert not Path(cert_args["name"]).exists()

    # testrole's max_ttl is one day
    cert_args["not_after"] = (datetime.now(tz=timezone.utc) + timedelta(hours=20)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    cert = load_cert(cert_args["name"])
    assert _not_valid_after(cert).strftime("%Y-%m-%dT%H:%M:%SZ") == cert_args["not_after"]
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_max_ttl_undercuts_ttl_remaining(vault_pki, cert_args):
    """
    A ttl_remaining beyond the role's max_ttl would mean each issued certificate
    is immediately due for renewal. Ensure the state refuses this configuration.
    """
    # testrole's max_ttl is one day
    cert_args["ttl"] = "48h"
    cert_args["ttl_remaining"] = "25h"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is False
    assert "`ttl_remaining` is undercut by the role's `max_ttl`" in ret.comment
    assert not ret.changes
    assert not Path(cert_args["name"]).exists()


@pytest.mark.usefixtures("issuer_setup")
def test_certificate_managed_not_after_exceeding_issuer(vault_pki, cert_args):
    """
    An explicit not_after beyond the signing issuer's expiry would error out
    (or be truncated, depending on the issuer's ``leaf_not_after_behavior``)
    during issuance. Ensure the state refuses it early.
    """
    cert_args.pop("role_name")
    cert_args["sign_verbatim"] = True
    cert_args["not_after"] = "2040-01-01T00:00:00Z"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is False
    assert "exceeds the signing issuer's expiry" in ret.comment
    assert not ret.changes
    assert not Path(cert_args["name"]).exists()

    # Unless the issuer explicitly permits exceeding its own validity
    vault_write("pki/issuer/root", issuer_name="root", leaf_not_after_behavior="permit")
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    cert = load_cert(cert_args["name"])
    assert _not_valid_after(cert) == datetime(2040, 1, 1, tzinfo=timezone.utc)
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_certificate_managed_issuer_expiry_undercuts_ttl_remaining(vault_pki, cert_args):
    """
    A ttl_remaining beyond the signing issuer's remaining validity would mean
    each renewal attempt fails (or each issued certificate is immediately due
    for renewal, depending on the issuer's ``leaf_not_after_behavior``).
    Ensure the state refuses this configuration.
    """
    cert_args.pop("role_name")
    cert_args["sign_verbatim"] = True
    cert_args["ttl"] = "100000h"
    cert_args["ttl_remaining"] = "87600h"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is False
    assert "`ttl_remaining` is undercut by the signing issuer's expiry" in ret.comment
    assert not ret.changes
    assert not Path(cert_args["name"]).exists()


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_expiry_reports_issuer_capped_not_after(vault_pki, cert_args):
    """
    A signing issuer with ``leaf_not_after_behavior=truncate`` caps the
    effective certificate validity at its own expiry. Ensure change reports
    account for this instead of reflecting the requested validity.
    """
    res = vault_write(
        "pki/root/generate/internal", common_name="Short Root", ttl="20h", issuer_name="shortroot"
    )["data"]
    vault_write(
        f"pki/issuer/{res['issuer_id']}",
        issuer_name="shortroot",
        leaf_not_after_behavior="truncate",
    )
    issuer_expiry = _not_valid_after(load_cert(res["certificate"]))
    cert_args["issuer_ref"] = "shortroot"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    # The current certificate expires in 30m, which undercuts the new tolerance.
    # The requested 48h exceed both the role's max_ttl (one day) and the
    # truncating issuer's remaining validity (~20h), the latter binding.
    cert_args["ttl"] = "48h"
    cert_args["ttl_remaining"] = "45m"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "expiration" in ret.changes
    reported = datetime.strptime(ret.changes["not_after"]["new"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    assert abs((reported - issuer_expiry).total_seconds()) < 300
    cert = load_cert(cert_args["name"])
    assert _not_valid_after(cert) == issuer_expiry

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_issuance_error_reported_early(vault_pki, cert_args, testmode):
    """
    When a certificate needs to be reissued, but the request is predetermined
    to fail because the requested validity exceeds the signing issuer's expiry
    and the issuer errors out instead of truncating (the default behavior),
    ensure the state fails early, even in test mode.
    """
    vault_write(
        "pki/root/generate/internal", common_name="Short Root", ttl="20h", issuer_name="shortroot"
    )
    cert_args["issuer_ref"] = "shortroot"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    # The excessive validity alone should not fail the state while the
    # certificate does not need to be reissued, but a note should be included.
    # The effective validity is min(ttl, testrole's max_ttl) = 24h > ~20h.
    cert_args["ttl"] = "48h"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "Note: Issuance would fail" in ret.comment
    assert "exceeds the signing issuer's expiry" in ret.comment

    # Once a reissuance is required, the state should fail early.
    cert_args["ttl_remaining"] = "45m"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is False
    assert "Issuance would fail" in ret.comment
    assert "exceeds the signing issuer's expiry" in ret.comment
    assert "expiration" in ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_existing_file_not_a_cert(cert_typ):
    """
    When the target file exists, but does not contain a certificate,
    it should be replaced.
    """
    cert_managed, cert_args = cert_typ
    Path(cert_args["name"]).write_text("banana")
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "replaced" in ret.changes
    assert load_cert(cert_args["name"])


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_missing_issuer(cert_typ, testmode):
    cert_managed, cert_args = cert_typ
    cert_args["issuer_ref"] = "missing-issuer"
    cert_args["append_ca_chain"] = True
    ret = cert_managed(**cert_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "'missing-issuer' does not exist" in ret.comment
