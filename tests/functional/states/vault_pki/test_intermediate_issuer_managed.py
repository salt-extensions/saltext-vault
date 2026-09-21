"""
Tests for the intermediate_issuer_managed state.
"""

from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from cryptography import x509 as cx509
from salt.utils.x509 import load_cert

from saltext.vault.utils.vault import helpers as hlp
from tests.common.containers import genmarks
from tests.common.helpers.vault_pki import AIA_UNVERIFIED_NOTE
from tests.common.helpers.vault_pki import DEFAULT_CLUSTER_AIA_PATH
from tests.common.helpers.vault_pki import MOUNT_URL_CONFIG
from tests.common.helpers.vault_pki import _assert_embedded_aia
from tests.common.helpers.vault_pki import _default_issuer
from tests.common.helpers.vault_pki import _not_valid_after
from tests.common.helpers.vault_pki import _subject
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytestmark = genmarks(mounts="pki")


@pytest.mark.usefixtures("clean_pki_mount")
def test_intermediate_issuer_managed_create(vault_pki, int_ca_args, testmode):
    # the hard-coded ca_cert is valid until 2036, consider swapping it with ca2_cert
    int_ca_args["days_valid"] = 1825
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "created" in ret.changes
    assert ret.changes["created"]["CN"] == int_ca_args["name"]
    assert ret.changes["created"]["issuer_name"] == int_ca_args.get("issuer_name")
    assert (ret.changes["created"]["issuer_id"] == "<TBD>") is testmode
    assert (ret.changes["created"]["key_id"] == "<TBD>") is testmode
    assert (ret.changes["imported"] == ["<TBD>"]) is testmode
    assert "old_issuer" not in ret.changes
    assert (
        f"Intermediate CA certificate {'would have' if testmode else 'has'} been created"
        in ret.comment
    )
    if testmode:
        assert not vault_list(f"{int_ca_args['mount']}/issuers")
        return
    issuer_info = _default_issuer(int_ca_args["mount"])
    assert ret.changes["created"]["issuer_id"] == issuer_info["issuer_id"]
    assert ret.changes["created"]["key_id"] == issuer_info["key_id"]

    cert = load_cert(issuer_info["certificate"])
    assert _subject(cert) == int_ca_args["name"]
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 0
    # Ensure the requested validity is not capped at the mount's max_lease_ttl
    expected_not_after = datetime.now(tz=timezone.utc) + timedelta(days=int_ca_args["days_valid"])
    assert abs((_not_valid_after(cert) - expected_not_after).total_seconds()) < 86400


@pytest.mark.usefixtures("existing_intermediate", "aia_urls")
@pytest.mark.parametrize(
    "aia_urls",
    (
        {
            "enable_templating": True,
            "issuing_certificates": [
                "https://one.default.ca/{{issuer_id}}",
                "{{cluster_aia_path}}issuer/{{issuer_id}}/der",
            ],
            "crl_distribution_points": [
                "https://crl1.default.ca/{{issuer_id}}",
                "{{cluster_path}}/crl/pem",
            ],
            "delta_crl_distribution_points": [
                "https://deltacrl1.default.ca/{{issuer_id}}",
                "{{cluster_aia_path}}/issuer/{{issuer_id}}/crl/delta/der",
            ],
            "ocsp_servers": [
                "{{cluster_aia_path}}/ocsp",
            ],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "existing_intermediate",
    (
        {
            "max_path_length": 1,
            "alt_names": [
                "dns:test2.root.ca",
                "ip:1.2.3.4",
                "uri:https://root.ca",
                "email:test@root.ca",
            ],
            "key_usage": ["DigitalSignature"],
            "permitted_alt_names": [  # types other than dns require Vault 1.19+, filtered in existing_root
                "dns:.foo.bar",
                "email:.foo.bar",
                "ip:0.0.0.0/1",
                "ip:2001:500::/30",
                "uri:.bar.baz",
            ],
            "excluded_alt_names": [  # requires Vault 1.19+, also filtered in existing_root
                "dns:no.foo.bar",
                "email:no.foo.bar",
                "ip:0.0.0.0/24",
                "ip:2001:500::/32",
                "uri:no.bar.baz",
            ],
            "ou": ["an org unit", "Org Unit 1", "Another Org Unit 2"],
            "organization": "Test Org",
            "country": "US",
            "locality": "Springfield",
            "province": "Utah",
            "street_address": "Test Rd 123",
            "postal_code": "1337",
            "serial_number": "37",
        },
    ),
    indirect=True,
)
def test_intermediate_issuer_managed_ok(vault_pki, int_ca_args, container):
    """
    Ensure both issuance types work and are idempotent.
    There might be slight differences, e.g. CN is not included in sans with salt_ca.
    """
    cert = load_cert(_default_issuer(int_ca_args["mount"])["certificate"])
    assert (
        cert.subject.rfc4514_string()
        == "2.5.4.5=37,CN=Test Intermediate CA,OU=Org Unit 1+OU=an org unit+OU=Another Org Unit 2,O=Test Org,2.5.4.17=1337,STREET=Test Rd 123,L=Springfield,ST=Utah,C=US"
    )
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 1

    ku = cert.extensions.get_extension_for_class(cx509.KeyUsage)
    assert ku.critical is True
    assert ku.value.digital_signature is (
        "signing_cert" in int_ca_args or "vault" not in container or "latest" in container
    )
    assert ku.value.crl_sign is True
    assert ku.value.key_cert_sign is True

    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert sans.critical is False
    assert {str(san.value) for san in sans.value} == {
        val.split(":", maxsplit=1)[1] for val in int_ca_args["alt_names"]
    }

    nc = cert.extensions.get_extension_for_class(cx509.NameConstraints)
    assert nc.critical is True
    assert {str(st.value) for st in nc.value.permitted_subtrees} == {
        val.split(":", maxsplit=1)[1] for val in int_ca_args["permitted_alt_names"]
    }
    if int_ca_args.get("excluded_alt_names"):
        assert {str(st.value) for st in nc.value.excluded_subtrees} == {
            val.split(":", maxsplit=1)[1] for val in int_ca_args["excluded_alt_names"]
        }
    else:
        assert nc.value.excluded_subtrees is None

    cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier)
    cert.extensions.get_extension_for_class(cx509.AuthorityKeyIdentifier)

    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment


@pytest.mark.usefixtures("existing_intermediate")
@pytest.mark.parametrize(
    "existing_intermediate",
    (
        {
            "not_after": (datetime.now(tz=timezone.utc) + timedelta(days=85)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "days_remaining": 80,
        },
    ),
    indirect=True,
)
def test_intermediate_issuer_managed_not_after(vault_pki, int_ca_args):
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment

    int_ca_args["days_remaining"] = 90
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is False
    assert not ret.changes
    assert "expires in 12 weeks" in ret.comment
    assert "less than the tolerance of" in ret.comment

    prev, int_ca_args["not_after"] = int_ca_args["not_after"], (
        datetime.now(tz=timezone.utc) + timedelta(days=100)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert ret.changes["cert"]["not_after"] == {"old": prev, "new": int_ca_args["not_after"]}
    assert "expiration" not in ret.changes["cert"]
    assert "has been rotated" in ret.comment


@pytest.mark.usefixtures("clean_pki_mount")
@pytest.mark.parametrize("int_ca_args", ("vault_ca",), indirect=True)
def test_intermediate_issuer_managed_not_after_exceeding_issuer(vault_pki, int_ca_args):
    """
    An explicit not_after beyond the signing issuer's expiry would be truncated
    during issuance, resulting in repeated changes. Ensure the state refuses it
    early instead. This only applies to certificates signed by a Vault issuer.
    """
    int_ca_args["not_after"] = "2040-01-01T00:00:00Z"
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is False
    assert "exceeds the signing issuer's expiry" in ret.comment
    assert not ret.changes
    assert not vault_list(f"{int_ca_args['mount']}/issuers")

    # Unless the issuer explicitly permits exceeding its own validity
    # and its behavior enforcement is requested
    vault_write("pki/issuer/root", issuer_name="root", leaf_not_after_behavior="permit")
    int_ca_args["enforce_leaf_not_after_behavior"] = True
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    cert = load_cert(_default_issuer(int_ca_args["mount"])["certificate"])
    assert _not_valid_after(cert) == datetime(2040, 1, 1, tzinfo=timezone.utc)
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("clean_pki_mount")
@pytest.mark.parametrize("int_ca_args", ("vault_ca",), indirect=True)
def test_intermediate_issuer_managed_issuer_expiry_undercuts_days_remaining(vault_pki, int_ca_args):
    """
    A days_remaining beyond the signing issuer's remaining validity would mean
    each issued certificate is immediately due for rotation.
    Ensure the state refuses this. This only applies to certificates signed
    by a Vault issuer.
    """
    int_ca_args["days_valid"] = 4000
    int_ca_args["days_remaining"] = 3650
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is False
    assert "`days_remaining` is undercut by the signing issuer's expiry" in ret.comment
    assert not ret.changes
    assert not vault_list(f"{int_ca_args['mount']}/issuers")


@pytest.mark.usefixtures("clean_pki_mount")
@pytest.mark.parametrize("int_ca_args", ("vault_ca",), indirect=True)
def test_intermediate_issuer_managed_issuance_error_reported_early(
    vault_pki, int_ca_args, container, testmode
):
    """
    When the signing issuer errors out instead of truncating during CA issuance
    (``leaf_not_after_behavior=always_enforce_err`` or enforcement of the default
    ``err`` requested), ensure the state fails early if the requested validity
    exceeds the issuer's expiry, even in test mode.
    """
    if "vault" in container and "latest" in container:
        vault_write(
            "pki/issuer/root", issuer_name="root", leaf_not_after_behavior="always_enforce_err"
        )
    else:
        # `always_enforce_err` requires Vault 1.18.2+ and is unsupported on OpenBao
        # (as of Sep 2026), so test the enforcement condition on the others.
        # The flag itself is Vault 1.17+ only, but this still works on 1.14.8
        # since the request is never sent.
        int_ca_args["enforce_leaf_not_after_behavior"] = True
    int_ca_args["days_valid"] = 4000
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is False
    assert "Issuance would fail" in ret.comment
    assert "exceeds the signing issuer's expiry" in ret.comment
    assert "created" in ret.changes
    assert not vault_list(f"{int_ca_args['mount']}/issuers")

    # While no new certificate is required, the state should
    # succeed and only include a note.
    int_ca_args["days_valid"] = 90
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "created" in ret.changes

    int_ca_args["days_valid"] = 4000
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "Note: Issuance would fail" in ret.comment
    assert "exceeds the signing issuer's expiry" in ret.comment


@pytest.mark.usefixtures("existing_intermediate")
@pytest.mark.parametrize(
    "existing_intermediate",
    (
        {
            "subjectAltName": [
                "dns:test2.root.ca",
                "ip:1.2.3.4",
                "uri:https://root.ca",
                "email:test@root.ca",
            ],
            "keyUsage": "digitalSignature,keyCertSign",
            "nameConstraints": {
                "permitted": [
                    "dns:.foo.bar",
                    "email:.foo.bar",
                    "ip:0.0.0.0/1",
                    "ip:2001:500::/30",
                    "uri:.bar.baz",
                ],
                "excluded": ["dns:no.foo.bar"],
            },
            "subjectKeyIdentifier": "cafebabe",
            "OU": "Test org unit",
            "O": "Test Org",
            "C": "US",
            "L": "Springfield",
            "ST": "Utah",
            "STREET": "Test Rd 123",
            "SERIALNUMBER": "37",
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize("int_ca_args", ("salt_ca",), indirect=True)
def test_intermediate_issuer_managed_salt_ca(vault_pki, int_ca_args):
    """
    Ensure passing x509 args works as expected, is idempotent and reports changes.
    """
    cert = load_cert(_default_issuer(int_ca_args["mount"])["certificate"])
    assert (
        cert.subject.rfc4514_string()
        == "2.5.4.5=37,CN=Test Intermediate CA,OU=Test org unit,O=Test Org,STREET=Test Rd 123,L=Springfield,ST=Utah,C=US"
    )
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 0

    ku = cert.extensions.get_extension_for_class(cx509.KeyUsage)
    assert ku.critical is False
    assert ku.value.digital_signature is True
    assert ku.value.crl_sign is False
    assert ku.value.key_cert_sign is True

    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert sans.critical is False
    assert {str(san.value) for san in sans.value} == {
        val.split(":", maxsplit=1)[1] for val in int_ca_args["subjectAltName"]
    }

    nc = cert.extensions.get_extension_for_class(cx509.NameConstraints)
    assert nc.critical is False
    assert {str(st.value) for st in nc.value.permitted_subtrees} == {
        val.split(":", maxsplit=1)[1] for val in int_ca_args["nameConstraints"]["permitted"]
    }
    assert {str(st.value) for st in nc.value.excluded_subtrees} == {
        val.split(":", maxsplit=1)[1] for val in int_ca_args["nameConstraints"]["excluded"]
    }

    assert (
        cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier).value.digest
        == b"\xca\xfe\xba\xbe"
    )
    cert.extensions.get_extension_for_class(cx509.AuthorityKeyIdentifier)

    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment

    int_ca_args["max_path_length"] = 1
    int_ca_args["O"] += " Changed"
    int_ca_args["keyUsage"] += ",cRLSign"

    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert set(ret.changes["cert"]) == {"subject_name", "extensions"}
    assert ret.changes["cert"]["subject_name"] == {
        "old": "2.5.4.5=37,CN=Test Intermediate CA,OU=Test org unit,O=Test Org,STREET=Test Rd 123,L=Springfield,ST=Utah,C=US",
        "new": "2.5.4.5=37,CN=Test Intermediate CA,OU=Test org unit,O=Test Org Changed,STREET=Test Rd 123,L=Springfield,ST=Utah,C=US",
    }
    assert ret.changes["cert"]["extensions"]["changed"]["basicConstraints"]["value"]["pathlen"] == {
        "old": 0,
        "new": 1,
    }
    assert ret.changes["cert"]["extensions"]["changed"]["keyUsage"]["value"]["cRLSign"] == {
        "old": False,
        "new": True,
    }

    cert = load_cert(_default_issuer(int_ca_args["mount"])["certificate"])
    assert (
        cert.subject.rfc4514_string()
        == "2.5.4.5=37,CN=Test Intermediate CA,OU=Test org unit,O=Test Org Changed,STREET=Test Rd 123,L=Springfield,ST=Utah,C=US"
    )

    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.value.path_length == 1

    ku = cert.extensions.get_extension_for_class(cx509.KeyUsage)
    assert ku.value.crl_sign is True


@pytest.mark.usefixtures("existing_intermediate")
@pytest.mark.parametrize("int_ca_args", ("salt_ca",), indirect=True)
def test_intermediate_issuer_managed_issuer_changes(vault_pki, int_ca_args, testmode, container):
    issuer_params = {
        "issuer_name": "my_root_ca",
        "leaf_not_after_behavior": "truncate",
        "usage": ["issuing-certificates"],
        "revocation_signature_algorithm": "ECDSAWithSHA512",
        "aia_urls": "https://my.root.ca",
        "crl_endpoints": ["https://crl.my.root.ca"],
        "delta_crl_endpoints": ["https://delta.crl.my.root.ca"],
        "ocsp_servers": ["https://ocsp.my.root.ca"],
        "aia_url_templating": True,
    }
    int_ca_args.update(issuer_params)
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert (
        f"Intermediate CA issuer {'would have' if testmode else 'has'} been updated" in ret.comment
    )
    assert "created" not in ret.changes
    assert "cert" not in ret.changes
    assert "imported" not in ret.changes
    assert "old_issuer" not in ret.changes

    issuer_changes = ret.changes.get("issuer")
    assert issuer_changes
    assert issuer_changes["issuer_name"] == {"old": "", "new": "my_root_ca"}
    assert issuer_changes["leaf_not_after_behavior"] == {"old": "err", "new": "truncate"}
    assert issuer_changes["usage"] == {"added": [], "removed": ["crl-signing", "ocsp-signing"]}
    assert issuer_changes["revocation_signature_algorithm"]["new"] == "ECDSAWithSHA512"
    assert issuer_changes["aia_urls"] == {"added": [issuer_params["aia_urls"]], "removed": []}
    assert issuer_changes["crl_endpoints"] == {
        "added": issuer_params["crl_endpoints"],
        "removed": [],
    }
    if "vault" not in container or "latest" in container:
        assert issuer_changes["delta_crl_endpoints"] == {
            "added": issuer_params["delta_crl_endpoints"],
            "removed": [],
        }
    assert issuer_changes["ocsp_servers"] == {"added": issuer_params["ocsp_servers"], "removed": []}
    assert issuer_changes["aia_url_templating"] == {"old": False, "new": True}

    issuer_info = _default_issuer(int_ca_args["mount"])
    assert (issuer_info["issuer_name"] != issuer_params["issuer_name"]) is testmode
    assert (
        issuer_info["leaf_not_after_behavior"] != issuer_params["leaf_not_after_behavior"]
    ) is testmode
    assert (
        set(hlp.deserialize_csl(issuer_info["usage"]))
        != set(issuer_params["usage"] + ["read-only"])
    ) is testmode
    assert (issuer_info["issuing_certificates"] != [issuer_params["aia_urls"]]) is testmode
    assert (issuer_info["crl_distribution_points"] != issuer_params["crl_endpoints"]) is testmode
    if "vault" not in container or "latest" in container:
        assert (
            issuer_info["delta_crl_distribution_points"] != issuer_params["delta_crl_endpoints"]
        ) is testmode
    assert (issuer_info["ocsp_servers"] != issuer_params["ocsp_servers"]) is testmode
    assert (
        issuer_info.get("enable_aia_url_templating", False) != issuer_params["aia_url_templating"]
    ) is testmode


@pytest.mark.usefixtures("existing_intermediate")
@pytest.mark.parametrize(
    "existing_intermediate",
    (
        {
            "issuer_name": "my_root_ca",
            "leaf_not_after_behavior": "truncate",
            "usage": ["issuing-certificates"],
            "revocation_signature_algorithm": "",
            "aia_urls": "https://my.root.ca,https://my2.root.ca",
            "crl_endpoints": ["https://crl1.my.root.ca", "https://crl2.my.root.ca"],
            "delta_crl_endpoints": [
                "https://delta.crl.my.root.ca"
            ],  # filtered in exisiting_intermediate
            "ocsp_servers": "https://ocsp.my.root.ca",
            "aia_url_templating": True,
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize("int_ca_args", ("salt_ca",), indirect=True)
def test_intermediate_issuer_managed_issuer_ok(vault_pki, int_ca_args, testmode):
    issuer_info = _default_issuer(int_ca_args["mount"])
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert "Intermediate CA issuer is present as specified" in ret.comment
    assert not ret.changes
    new_info = _default_issuer(int_ca_args["mount"])
    assert new_info == issuer_info


@pytest.mark.parametrize("int_ca_args", ("vault_ca",), indirect=True)
@pytest.mark.parametrize("aia_urls", (MOUNT_URL_CONFIG,), indirect=True)
@pytest.mark.usefixtures("clean_pki_mount", "aia_urls", "url_config_read_denied")
def test_intermediate_issuer_managed_url_config_denied(vault_pki, int_ca_args):
    """
    Ensure a denied URL read access does not cause rotation, only a note.
    """
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "has been created" in ret.comment
    assert AIA_UNVERIFIED_NOTE not in ret.comment
    issuer_info = _default_issuer(int_ca_args["mount"])
    _assert_embedded_aia(load_cert(issuer_info["certificate"]), MOUNT_URL_CONFIG)

    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment
    assert AIA_UNVERIFIED_NOTE in ret.comment
    assert _default_issuer(int_ca_args["mount"])["issuer_id"] == issuer_info["issuer_id"]


@pytest.mark.parametrize("int_ca_args", ("vault_ca",), indirect=True)
@pytest.mark.parametrize(
    "issuer_setup",
    (
        {
            "issuing_certificates": ["{{cluster_aia_path}}ca.der"],
            "crl_distribution_points": ["{{cluster_path}}/crl"],
            "enable_aia_url_templating": True,
        },
    ),
    indirect=True,
)
@pytest.mark.usefixtures("clean_pki_mount", "url_config_read_denied")
def test_intermediate_issuer_managed_cluster_config_denied(vault_pki, int_ca_args):
    """
    Ensure a denied cluster config read access does not cause rotation when the
    (issuer-specific) URL configuration of the signing issuer is templated.
    """
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "has been created" in ret.comment
    assert AIA_UNVERIFIED_NOTE not in ret.comment
    issuer_info = _default_issuer(int_ca_args["mount"])
    _assert_embedded_aia(
        load_cert(issuer_info["certificate"]),
        {"issuing_certificates": [f"{DEFAULT_CLUSTER_AIA_PATH}ca.der"]},
    )

    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment
    assert AIA_UNVERIFIED_NOTE in ret.comment
    assert _default_issuer(int_ca_args["mount"])["issuer_id"] == issuer_info["issuer_id"]


@pytest.mark.parametrize(
    "existing_intermediate",
    (
        {
            "issuer_name": "my_int_ca",
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize("int_ca_args", ("salt_ca",), indirect=True)
def test_intermediate_issuer_managed_changes_with_issuer_name(
    vault_pki, int_ca_args, existing_intermediate, testmode
):
    """
    Ensure issuer certificate rotation keeps issuer config the same
    and accounts for issuer_name needing to be unique.
    """
    issuer_info = _default_issuer(int_ca_args["mount"])
    int_ca_args["max_path_length"] = 2
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert (
        f"Intermediate CA certificate {'would have' if testmode else 'has'} been rotated"
        in ret.comment
    )
    assert ret.changes
    assert "cert" in ret.changes
    assert "issuer" not in ret.changes
    assert "issuer_id" in ret.changes
    assert "old_issuer" in ret.changes
    assert ret.changes["old_issuer"]["issuer_id"] == issuer_info["issuer_id"]
    assert ret.changes["old_issuer"]["usage"] == {"removed": ["issuing-certificates"]}
    assert ret.changes["old_issuer"]["issuer_name"]["old"] == issuer_info["issuer_name"]
    assert ret.changes["old_issuer"]["issuer_name"]["new"].startswith(
        issuer_info["issuer_name"] + "-" + ("<TBD>" if testmode else "")
    )
    new_info = _default_issuer(int_ca_args["mount"])
    if testmode:
        assert new_info["issuer_id"] == existing_intermediate["issuer_id"]
        assert new_info["issuer_name"] == existing_intermediate["issuer_name"]
        return
    assert new_info["issuer_id"] != issuer_info["issuer_id"]
    assert new_info["issuer_name"] == int_ca_args["issuer_name"]
    upd_old_info = vault_read(f"{int_ca_args['mount']}/issuer/{issuer_info['issuer_id']}")["data"]
    assert upd_old_info["issuer_name"].startswith(int_ca_args["issuer_name"] + "-")
    assert "issuing-certificates" in issuer_info["usage"]
    assert "issuing-certificates" not in upd_old_info["usage"]


def test_intermediate_issuer_managed_changes(
    vault_pki, int_ca_args, existing_intermediate, testmode
):
    old_cert = load_cert(existing_intermediate["certificate"])

    int_ca_args["name"] = "Rotated Intermediate CA"
    int_ca_args["max_path_length"] = None
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "issuer_id" in ret.changes
    assert "imported" in ret.changes
    assert "key_id" not in ret.changes
    assert ret.changes["issuer_id"]["old"] == existing_intermediate["issuer_id"]
    assert (ret.changes["issuer_id"]["new"] == "<TBD>") is testmode
    assert (ret.changes["imported"] == ["<TBD>"]) is testmode

    assert "old_issuer" in ret.changes
    assert ret.changes["old_issuer"] == {
        "issuer_id": existing_intermediate["issuer_id"],
        "usage": {"removed": ["issuing-certificates"]},
    }

    assert ret.changes["cert"]["subject_name"] == {
        "old": "CN=Test Intermediate CA",
        "new": "CN=Rotated Intermediate CA",
    }
    assert "basicConstraints" in ret.changes["cert"]["extensions"]["changed"]
    assert ret.changes["cert"]["extensions"]["changed"]["basicConstraints"]["value"]["pathlen"] == {
        "old": 0,
        "new": 2 if "issuer_ref" in int_ca_args else None,
    }
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment

    new_info = _default_issuer(int_ca_args["mount"])
    if testmode:
        assert new_info["issuer_id"] == existing_intermediate["issuer_id"]
        return
    assert new_info["issuer_id"] != existing_intermediate["issuer_id"]
    new_cert = load_cert(new_info["certificate"])
    assert _subject(new_cert) == "Rotated Intermediate CA"
    basic_constraints = new_cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    # This will break soon. IIRC, issuing cert has a pathlen and x509_v2 not accounting for that was fixed
    assert basic_constraints.value.path_length is (2 if "issuer_ref" in int_ca_args else None)
    # The key should have been reused
    assert new_info["key_id"] == existing_intermediate["key_id"]
    assert new_cert.public_key().public_numbers() == old_cert.public_key().public_numbers()


def test_intermediate_issuer_managed_changes_rotate_key(
    vault_pki, int_ca_args, existing_intermediate, testmode
):
    old_cert = load_cert(existing_intermediate["certificate"])

    int_ca_args["name"] = "Rotated Intermediate CA"
    int_ca_args["rotate_key"] = True
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "key_id" in ret.changes
    assert ret.changes["key_id"]["old"] == existing_intermediate["key_id"]
    assert (ret.changes["key_id"]["new"] == "<TBD>") is testmode
    assert ret.changes["cert"]["private_key"] is True
    assert (
        ret.changes["cert"]["extensions"]["changed"]["subjectKeyIdentifier"]["value"]["new"]
        == "<TBD>"
    ) is testmode

    new_info = _default_issuer(int_ca_args["mount"])
    if testmode:
        assert new_info["issuer_id"] == existing_intermediate["issuer_id"]
        assert new_info["key_id"] == existing_intermediate["key_id"]
        return
    assert ret.changes["key_id"]["new"] == new_info["key_id"]
    assert new_info["issuer_id"] != existing_intermediate["issuer_id"]
    assert new_info["key_id"] != existing_intermediate["key_id"]
    new_cert = load_cert(new_info["certificate"])
    assert new_cert.public_key().public_numbers() != old_cert.public_key().public_numbers()


@pytest.mark.usefixtures("clean_pki_mount")
@pytest.mark.parametrize("int_ca_args", ("salt_ca",), indirect=True)
def test_intermediate_issuer_managed_changes_existing_key(vault_pki, int_ca_args, testmode):
    key_1 = vault_write(f"{int_ca_args['mount']}/keys/generate/internal", key_name="old_key")[
        "data"
    ]
    key_2 = vault_write(f"{int_ca_args['mount']}/keys/generate/internal", key_name="new_key")[
        "data"
    ]
    int_ca_args["key_ref"] = key_1["key_name"]
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    issuer_info = _default_issuer(int_ca_args["mount"])
    assert issuer_info["key_id"] == key_1["key_id"]

    # Ensure key_ref is idempotent when specified via name
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer(int_ca_args["mount"]) == issuer_info

    # Ensure key_ref is idempotent when specified via ID
    int_ca_args["key_ref"] = key_1["key_id"]
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer(int_ca_args["mount"]) == issuer_info

    # Ensure existing issuer key is kept, even if key_ref is removed
    int_ca_args.pop("key_ref")
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer(int_ca_args["mount"]) == issuer_info

    # Now change the explicit key_ref to a key_name of a different key
    int_ca_args["key_ref"] = key_2["key_name"]
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    assert ret.changes
    assert "key_id" in ret.changes
    assert ret.changes["key_id"]["old"] == key_1["key_id"]
    assert (ret.changes["key_id"]["new"] == "<TBD>") is testmode
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "private_key" in cert_changes
    assert "subjectKeyIdentifier" in cert_changes["extensions"]["changed"]
    new_info = _default_issuer(int_ca_args["mount"])
    assert (new_info == issuer_info) is testmode
    if testmode:
        return
    assert new_info["key_id"] == key_2["key_id"]
    assert ret.changes["key_id"]["new"] == key_2["key_id"]


@pytest.mark.parametrize(
    "existing_intermediate", ({"days_valid": 20, "days_remaining": 10},), indirect=True
)
def test_intermediate_issuer_managed_changes_expiry(vault_pki, int_ca_args, existing_intermediate):
    int_ca_args["days_valid"] = 90
    int_ca_args["days_remaining"] = 30
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "expiration" in ret.changes.get("cert", {})
    assert _default_issuer(int_ca_args["mount"])["issuer_id"] != existing_intermediate["issuer_id"]


@pytest.mark.parametrize("int_ca_args", ("salt_ca",), indirect=True)
def test_intermediate_issuer_managed_invalid_key_type(vault_pki, int_ca_args, testmode):
    int_ca_args["key_type"] = "banana"
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "Invalid value 'banana' for `key_type`" in ret.comment
    assert "Traceback" not in ret.comment
