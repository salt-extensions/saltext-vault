"""
Tests for the root_issuer_managed state.
"""

from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from salt.utils.x509 import load_cert

from saltext.vault.utils.vault import helpers as hlp
from tests.common.containers import genmarks
from tests.common.helpers.vault_pki import AIA_UNVERIFIED_NOTE
from tests.common.helpers.vault_pki import MOUNT_URL_CONFIG
from tests.common.helpers.vault_pki import _assert_embedded_aia
from tests.common.helpers.vault_pki import _default_issuer
from tests.common.helpers.vault_pki import _import_configured_issuer
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytestmark = genmarks(mounts="pki")


@pytest.mark.usefixtures("clean_pki_issuers")
@pytest.mark.parametrize(
    "testmode,pathlen,aia_urls",
    (
        pytest.param(False, -1, {}, id="defaults"),
        pytest.param(False, 3, {}, id="pathlen"),
        pytest.param(True, -1, {}, id="testmode"),
        pytest.param(
            False,
            -1,
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="aia_only",
        ),
        pytest.param(
            False,
            -1,
            {
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
            },
            id="crl_only",
        ),
        pytest.param(
            False,
            -1,
            {
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
            },
            id="deltacrl_only",
        ),
        pytest.param(
            False,
            -1,
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="all_urls",
        ),
    ),
    indirect=("testmode", "aia_urls"),
)
def test_root_issuer_managed_create(
    vault_pki, root_ca_args, testmode, aia_urls, pathlen, container
):
    if pathlen >= 0:
        root_ca_args["max_path_length"] = pathlen
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "created" in ret.changes
    assert ret.changes["created"]["CN"] == root_ca_args["name"]
    assert ret.changes["created"]["issuer_name"] == root_ca_args.get("issuer_name")
    assert (ret.changes["created"]["issuer_id"] == "<TBD>") is testmode
    assert (ret.changes["created"]["key_id"] == "<TBD>") is testmode
    assert "old_issuer" not in ret.changes
    assert f"Root CA certificate {'would have' if testmode else 'has'} been created" in ret.comment
    if testmode:
        assert not vault_list("pki/issuers")
        return
    issuer_info = _default_issuer()
    assert ret.changes["created"]["issuer_id"] == issuer_info["issuer_id"]
    assert ret.changes["created"]["key_id"] == issuer_info["key_id"]

    cert = load_cert(issuer_info["certificate"])
    if aia_urls.get("issuing_certificates") or aia_urls.get("ocsp_servers"):
        cert.extensions.get_extension_for_class(cx509.AuthorityInformationAccess)
    if aia_urls.get("crl_distribution_points"):
        cert.extensions.get_extension_for_class(cx509.CRLDistributionPoints)
    if aia_urls.get("delta_crl_distribution_points"):
        if container.matches("vault>=1.20") or (
            container.is_openbao() and aia_urls.get("crl_distribution_points")
        ):
            cert.extensions.get_extension_for_class(cx509.FreshestCRL)
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length is (pathlen if pathlen >= 0 else None)


@pytest.mark.usefixtures("existing_root")
def test_root_issuer_managed_issuer_changes(vault_pki, root_ca_args, testmode, container):
    issuer_params = {
        "issuer_name": "my_root_ca",
        "leaf_not_after_behavior": "truncate",
        "usage": ["issuing-certificates"],
        "revocation_signature_algorithm": "",
        "aia_urls": "https://my.root.ca",
        "crl_endpoints": ["https://crl.my.root.ca"],
        "delta_crl_endpoints": ["https://delta.crl.my.root.ca"],
        "ocsp_servers": ["https://ocsp.my.root.ca"],
        "aia_url_templating": True,
    }
    root_ca_args.update(issuer_params)
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"Root CA issuer {'would have' if testmode else 'has'} been updated" in ret.comment
    assert "created" not in ret.changes
    assert "cert" not in ret.changes
    assert "imported" not in ret.changes
    assert "old_issuer" not in ret.changes

    issuer_changes = ret.changes.get("issuer")
    assert issuer_changes
    assert issuer_changes["issuer_name"] == {"old": "", "new": "my_root_ca"}
    assert issuer_changes["leaf_not_after_behavior"] == {"old": "err", "new": "truncate"}
    assert issuer_changes["usage"] == {"added": [], "removed": ["crl-signing", "ocsp-signing"]}
    assert issuer_changes["revocation_signature_algorithm"]["new"] == ""
    assert issuer_changes["aia_urls"] == {"added": [issuer_params["aia_urls"]], "removed": []}
    assert issuer_changes["crl_endpoints"] == {
        "added": issuer_params["crl_endpoints"],
        "removed": [],
    }
    if container.matches("vault>=1.20", "openbao"):
        assert issuer_changes["delta_crl_endpoints"] == {
            "added": issuer_params["delta_crl_endpoints"],
            "removed": [],
        }
    assert issuer_changes["ocsp_servers"] == {"added": issuer_params["ocsp_servers"], "removed": []}
    assert issuer_changes["aia_url_templating"] == {"old": False, "new": True}

    issuer_info = _default_issuer()
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
    if container.matches("vault>=1.20", "openbao"):
        assert (
            issuer_info["delta_crl_distribution_points"] != issuer_params["delta_crl_endpoints"]
        ) is testmode
    assert (issuer_info["ocsp_servers"] != issuer_params["ocsp_servers"]) is testmode
    assert (
        issuer_info.get("enable_aia_url_templating", False) != issuer_params["aia_url_templating"]
    ) is testmode


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    (
        {
            "issuer_name": "my_root_ca",
            "leaf_not_after_behavior": "truncate",
            "usage": ["issuing-certificates"],
            "revocation_signature_algorithm": "",
            "aia_urls": "https://my.root.ca,https://my2.root.ca",
            "crl_endpoints": ["https://crl1.my.root.ca", "https://crl2.my.root.ca"],
            "delta_crl_endpoints": ["https://delta.crl.my.root.ca"],  # filtered in existing_root
            "ocsp_servers": "https://ocsp.my.root.ca",
            "aia_url_templating": True,
        },
    ),
    indirect=True,
)
def test_root_issuer_managed_issuer_ok(vault_pki, root_ca_args, testmode):
    issuer_info = _default_issuer()
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert "Root CA issuer is present as specified" in ret.comment
    assert not ret.changes
    new_info = _default_issuer()
    assert new_info == issuer_info


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    (
        {
            "issuer_name": "my_root_ca",
            "allow_premature_rotation": True,
        },
    ),
    indirect=True,
)
def test_root_issuer_managed_changes_with_issuer_name(vault_pki, root_ca_args):
    """
    Ensure issuer certificate rotation keeps issuer config the same
    and accounts for issuer_name needing to be unique.
    """
    issuer_info = _default_issuer()
    root_ca_args["max_path_length"] = 2
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert "has been rotated" in ret.comment
    assert ret.changes
    assert "cert" in ret.changes
    assert "issuer" not in ret.changes
    assert "old_issuer" in ret.changes
    assert ret.changes["old_issuer"]["issuer_id"] == issuer_info["issuer_id"]
    assert ret.changes["old_issuer"]["usage"] == {"removed": ["issuing-certificates"]}
    assert ret.changes["old_issuer"]["issuer_name"]["old"] == issuer_info["issuer_name"]
    assert ret.changes["old_issuer"]["issuer_name"]["new"].startswith(
        issuer_info["issuer_name"] + "-"
    )
    new_info = _default_issuer()
    assert new_info["issuer_id"] != issuer_info["issuer_id"]
    assert new_info["issuer_name"] == root_ca_args["issuer_name"]


ISSUER_CONFIGS = (
    ("crl_distribution_points", "crl_endpoints"),
    ("delta_crl_distribution_points", "delta_crl_endpoints"),
    ("enable_aia_url_templating", "aia_url_templating"),
    ("issuer_name", "issuer_name"),
    ("issuing_certificates", "aia_urls"),
    ("leaf_not_after_behavior", "leaf_not_after_behavior"),
    ("ocsp_servers", "ocsp_servers"),
    ("revocation_signature_algorithm", "revocation_signature_algorithm"),
    ("usage", "usage"),
)


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    (
        {
            "allow_premature_rotation": True,
            "crl_endpoints": ["https://crl.example.com/crl.pem"],
            "delta_crl_endpoints": ["https://delta.example.com/delta.pem"],
            "aia_url_templating": True,
            "aia_urls": ["https://ca.example.com/ca.der"],
            "leaf_not_after_behavior": "permit",
            "ocsp_servers": ["https://ocsp.example.com"],
            "revocation_signature_algorithm": "ECDSAWithSHA384",
            "usage": "read-only,issuing-certificates,crl-signing",
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize(
    "condition",
    ("all_default", "rotate_key", "with_issuer_name", "denied", "denied_issuer_changes"),
)
def test_root_issuer_managed_rotation_preserves_all_issuer_config_and_reports_implicit_changes(
    vault_pki, root_ca_args, existing_root, testmode, condition
):
    """
    1) Even when no issuer parameter is specified, a certificate rotation should preserve
       the most of the current non-default issuer config on the new issuer
       (which starts out with default configuration otherwise) and not report any issuer changes.
       This means we run update_issuer, even though nothing is reported as changed on the issuer.
    2) When we rotate/replace keys, we don't preserve revocation_signature_algorithm and report it.
    3) When issuer_name is unspecified, but the current one has one, it's not preserved and we report it.
    4) When we deny early rotation, 2/3 should not be reported
    5) When we deny early rotation, changes should still be applied and reported
    """
    remove = ("usage", "leaf_not_after_behavior")
    any_issuer_changes = False
    current_config = {
        conf[0]: root_ca_args[conf[1]] for conf in ISSUER_CONFIGS if conf[1] in root_ca_args
    }
    # sanity check. only delta_crl_distribution_points is conditional
    assert len(current_config) >= len(ISSUER_CONFIGS) - 2

    if condition == "all_default":
        # Ensure we're not passing any issuer config params
        remove = [conf[1] for conf in ISSUER_CONFIGS]

    if condition in ("rotate_key", "denied"):
        root_ca_args["rotate_key"] = True
        remove = ("revocation_signature_algorithm",)
        any_issuer_changes = condition == "rotate_key"

    if condition in ("with_issuer_name", "denied"):
        vault_write(
            f"pki/issuer/{existing_root['issuer_id']}", **current_config, issuer_name="foobar"
        )
        any_issuer_changes = condition == "with_issuer_name"

    if condition == "denied_issuer_changes":
        remove = ()
        root_ca_args["leaf_not_after_behavior"] = "truncate"  # ensure this change is applied still
        any_issuer_changes = True

    for rm in remove:
        root_ca_args.pop(rm, None)

    denied = condition.startswith("denied")
    root_ca_args["allow_premature_rotation"] = not denied

    # We might have changed the issuer config, so re-check from existing_root
    pre_info = _default_issuer()
    # and verify the issuer is configured as expected
    if condition in ("denied", "with_issuer_name"):
        assert pre_info["issuer_name"] == "foobar"
    for conf, _ in ISSUER_CONFIGS:
        if conf not in current_config:
            continue
        if conf == "usage":
            assert set(hlp.deserialize_csl(pre_info[conf])) == set(
                hlp.deserialize_csl(current_config[conf])
            )
        else:
            assert pre_info[conf] == current_config[conf]

    if condition != "denied_issuer_changes":
        # Ensure we're idempotent without forcing a rotation
        ret = vault_pki.root_issuer_managed(**root_ca_args)
        assert ret.result is True
        assert not ret.changes
        assert "Root CA issuer is present as specified" in ret.comment

    # Now force rotation
    root_ca_args["max_path_length"] = 2
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    if denied:
        assert ret.result is False
    else:
        assert ret.result is not False
        assert (ret.result is None) is testmode
        assert (
            f"Root CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
        )
    assert ("Root CA issuer" in ret.comment) is any_issuer_changes
    assert "Failed to recover" not in ret.comment

    assert ("issuer" in ret.changes) is any_issuer_changes
    assert ret.changes["old_issuer"]["issuer_id"] == pre_info["issuer_id"]
    assert ret.changes["old_issuer"]["usage"] == {"removed": ["issuing-certificates"]}

    if condition == "rotate_key":
        assert ret.changes["issuer"] == {
            "revocation_signature_algorithm": {"old": "ECDSAWithSHA384", "new": "<key default>"}
        }
    elif condition == "with_issuer_name":
        assert ret.changes["issuer"] == {"issuer_name": {"old": "foobar", "new": ""}}

    new_info = _default_issuer()
    if testmode:
        assert new_info == pre_info
        return
    assert (new_info["issuer_id"] == pre_info["issuer_id"]) is denied
    assert (new_info["key_id"] != pre_info["key_id"]) is (condition == "rotate_key")
    assert bool(new_info["issuer_name"]) is (condition == "denied")
    if condition == "denied_issuer_changes":
        assert new_info["leaf_not_after_behavior"] == "truncate"
    else:
        assert new_info["leaf_not_after_behavior"] == "permit"
    if condition == "rotate_key":
        # Unspecified revsigalgo is not recovered here because it could cause failure when the key algo changes
        assert new_info["revocation_signature_algorithm"] == "ECDSAWithSHA256"
    else:
        # preserved because we did not rotate the key
        assert new_info["revocation_signature_algorithm"] == "ECDSAWithSHA384"
    assert set(hlp.deserialize_csl(new_info["usage"])) == {
        "read-only",
        "issuing-certificates",
        "crl-signing",
    }
    assert new_info["enable_aia_url_templating"] is True
    assert new_info["issuing_certificates"] == ["https://ca.example.com/ca.der"]
    assert new_info["crl_distribution_points"] == ["https://crl.example.com/crl.pem"]
    assert new_info["ocsp_servers"] == ["https://ocsp.example.com"]

    old_info = vault_read(f"pki/issuer/{pre_info['issuer_id']}")["data"]
    assert ("issuing-certificates" in old_info["usage"]) is denied
    if condition in ("with_issuer_name", "denied"):
        assert old_info["issuer_name"] == "foobar"

    if root_ca_args["allow_premature_rotation"]:
        # The state should still report convergence afterwards
        ret = vault_pki.root_issuer_managed(**root_ca_args)
        assert ret.result is True
        assert not ret.changes
        assert "Root CA issuer is present as specified" in ret.comment


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    (
        {
            "allow_premature_rotation": True,
            "crl_endpoints": ["https://crl.example.com/crl.pem"],
            "delta_crl_endpoints": ["https://delta.example.com/delta.pem"],
            "aia_url_templating": True,
            "aia_urls": ["https://ca.example.com/ca.der"],
            "leaf_not_after_behavior": "permit",
            "ocsp_servers": ["https://ocsp.example.com"],
            "revocation_signature_algorithm": "ECDSAWithSHA384",
            "usage": "read-only,issuing-certificates,crl-signing",
        },
    ),
    indirect=True,
)
def test_root_issuer_managed_rotation_reports_recovery_failure_changes(
    vault_pki, root_ca_args, existing_root, container
):
    """
    When we try to recover unspecified, but customized issuer config and fail, we report
    changes that we normally wouldn't need to.
    """
    for _, conf in ISSUER_CONFIGS:
        root_ca_args.pop(conf, None)
    root_ca_args["max_path_length"] = 2
    root_ca_args["allow_premature_rotation"] = True
    root_ca_args["revocation_signature_algorithm"] = "invalid"
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is False
    assert "Failed to recover" in ret.comment
    assert "Received an exception later:" in ret.comment
    assert "Unknown signature algorithm" in ret.comment

    assert "issuer" in ret.changes
    assert "issuer_id" in ret.changes
    assert ret.changes["old_issuer"]["issuer_id"] == existing_root["issuer_id"]
    assert ret.changes["old_issuer"]["usage"] == {"removed": ["issuing-certificates"]}
    exp_changes = {
        "crl_endpoints": {"removed": ["https://crl.example.com/crl.pem"], "added": []},
        "delta_crl_endpoints": {"removed": ["https://delta.example.com/delta.pem"], "added": []},
        "aia_url_templating": {"old": True, "new": False},
        "aia_urls": {"removed": ["https://ca.example.com/ca.der"], "added": []},
        "leaf_not_after_behavior": {"old": "permit", "new": "err"},
        "ocsp_servers": {"removed": ["https://ocsp.example.com"], "added": []},
        "usage": {"added": ["ocsp-signing"], "removed": []},
    }
    if not container.matches("vault>=1.20", "openbao"):
        exp_changes.pop("delta_crl_endpoints")
    assert ret.changes["issuer"] == exp_changes


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    ({"issuer_name": "my_root_ca"},),
    indirect=True,
)
def test_root_issuer_managed_issuer_name_taken(
    vault_pki, root_ca_args, ca2_cert, ca2_key, testmode
):
    """
    When the issuer name should be changed, but the requested one is taken by another
    issuer and the current default issuer is named (i.e. the conflict cannot be an
    artifact of a previously interrupted rotation), the state should fail
    without touching either issuer.
    """
    collision_id = _import_configured_issuer(ca2_cert, ca2_key, {"issuer_name": "other_root"})
    issuer_info = _default_issuer()
    issuers_before = sorted(vault_list("pki/issuers"))
    root_ca_args["issuer_name"] = "other_root"
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is False
    assert "Another issuer with name 'other_root' exists on mount 'pki'" in ret.comment
    assert collision_id in ret.comment
    assert not ret.changes
    assert sorted(vault_list("pki/issuers")) == issuers_before
    assert _default_issuer() == issuer_info
    assert vault_read(f"pki/issuer/{collision_id}")["data"]["issuer_name"] == "other_root"


@pytest.mark.usefixtures("existing_root")
def test_root_issuer_managed_issuer_name_taken_before_rotation(
    vault_pki, root_ca_args, ca2_cert, ca2_key, testmode
):
    """
    When the requested issuer name is taken by another issuer and the certificate
    needs to be rotated, the state should fail before generating a new issuer,
    even if the current default issuer is unnamed.
    """
    collision_id = _import_configured_issuer(ca2_cert, ca2_key, {"issuer_name": "my_root_ca"})
    issuer_info = _default_issuer()
    issuers_before = sorted(vault_list("pki/issuers"))
    root_ca_args.update(
        {
            "issuer_name": "my_root_ca",
            "max_path_length": 2,
            "allow_premature_rotation": True,
        }
    )
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is False
    assert "Another issuer with name 'my_root_ca' exists on mount 'pki'" in ret.comment
    assert not ret.changes
    assert sorted(vault_list("pki/issuers")) == issuers_before
    assert _default_issuer() == issuer_info
    assert vault_read(f"pki/issuer/{collision_id}")["data"]["issuer_name"] == "my_root_ca"


@pytest.mark.usefixtures("existing_root")
def test_root_issuer_managed_issuer_name_taken_artifact(
    vault_pki, root_ca_args, ca2_cert, ca2_key, testmode
):
    """
    When the requested issuer name is taken by another issuer, but the current default
    issuer is unnamed and its certificate does not need to be changed, assume the name
    is held by a leftover of a previously interrupted rotation (which failed between
    switching the default issuer and renaming the superseded one) and rotate the holder out.
    This scenario is simulated here by importing a named foreign issuer next to an
    unnamed, converged default issuer.
    """
    collision_id = _import_configured_issuer(ca2_cert, ca2_key, {"issuer_name": "my_root_ca"})
    issuer_info = _default_issuer()
    root_ca_args["issuer_name"] = "my_root_ca"
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"Root CA issuer {'would have' if testmode else 'has'} been updated" in ret.comment
    assert "cert" not in ret.changes
    assert ret.changes["issuer"]["issuer_name"] == {"old": "", "new": "my_root_ca"}
    old_issuer = ret.changes.get("old_issuer")
    assert old_issuer
    assert old_issuer["issuer_id"] == collision_id
    assert old_issuer["issuer_name"]["old"] == "my_root_ca"
    assert old_issuer["issuer_name"]["new"].startswith(f"my_root_ca-{'<TBD>' if testmode else ''}")
    assert old_issuer["usage"] == {"removed": ["issuing-certificates"]}

    new_info = _default_issuer()
    assert new_info["issuer_id"] == issuer_info["issuer_id"]
    assert (new_info["issuer_name"] == "my_root_ca") is not testmode
    collision_info = vault_read(f"pki/issuer/{collision_id}")["data"]
    assert (collision_info["issuer_name"] == old_issuer["issuer_name"]["new"]) is not testmode
    assert ("issuing-certificates" not in collision_info["usage"]) is not testmode


@pytest.mark.usefixtures("existing_root", "aia_urls")
@pytest.mark.parametrize(
    "existing_root",
    (
        pytest.param({}, id="defaults"),
        pytest.param(
            {
                "key_algo": "rsa",  # needed for signature_bits to work
                "signature_bits": 384,
                "not_after": "2345-12-31T23:59:59Z",
                "alt_names": [
                    "dns:test2.root.ca",
                    "ip:1.2.3.4",
                    "uri:https://root.ca",
                    "email:test@root.ca",
                ],
                "max_path_length": 2,
                "key_usage": ["DigitalSignature"],
                "exclude_cn_from_sans": True,
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
            },
            id="all_attributes",
        ),
    ),
    indirect=True,
)
def test_root_issuer_managed_ok(vault_pki, root_ca_args, testmode, container):
    issuer_info = _default_issuer()
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert "Root CA issuer is present as specified" in ret.comment
    assert not ret.changes
    new_info = _default_issuer()
    assert new_info == issuer_info

    if "signature_bits" not in root_ca_args:
        return

    cert = load_cert(new_info["certificate"])
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 2
    if "key_usage" in root_ca_args:
        key_usage = cert.extensions.get_extension_for_class(cx509.KeyUsage)
        assert key_usage.value.crl_sign
        assert key_usage.value.key_cert_sign
        assert key_usage.value.digital_signature
    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert len(sans.value._general_names._general_names) == 4  # cn is excluded
    nc = cert.extensions.get_extension_for_class(cx509.NameConstraints)
    if container.matches("vault>=1.19"):
        assert len(nc.value.permitted_subtrees) == 5
        assert len(nc.value.excluded_subtrees) == 5
    else:
        assert len(nc.value.permitted_subtrees) == 1
        assert nc.value.excluded_subtrees is None

    # Demonstrate that URL changes don't cause rotation
    vault_write(
        "pki/config/urls",
        issuing_certificates="https://one.root.ca",
        ocsp_servers="https://ocsp1.root.ca",
    )
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "AIA-related URLs do not match" in ret.comment
    assert _default_issuer() == issuer_info


@pytest.mark.parametrize(
    "existing_root",
    (
        {
            "key_algo": "rsa",  # needed for signature_bits to work
            "signature_bits": 384,
            "not_after": "2345-12-31T23:59:59Z",
            "alt_names": [
                "dns:test2.root.ca",
                "ip:1.2.3.4",
                "uri:https://root.ca",
                "email:test@root.ca",
            ],
            "max_path_length": 2,
            "key_usage": ["DigitalSignature"],
            "exclude_cn_from_sans": True,
            "permitted_alt_names": [
                "dns:.foo.bar",
                "dns:foo.bar.baz",
                "email:.foo.bar",
                "ip:0.0.0.0/1",
                "ip:2001:500::/30",
                "uri:foo.bar.baz",  # there's a bug in x509_v2 when parsing uri nameconstraints (leading dot not allowed)
            ],
            "excluded_alt_names": [
                "dns:no.foo.bar",
                "email:no.foo.bar",
                "ip:0.0.0.0/24",
                "ip:2001:500::/32",
                "uri:no.bar.baz",
            ],
        },
    ),
    indirect=True,
)
@pytest.mark.parametrize("allow_premature_rotation", (False, True))
def test_root_issuer_managed_changes(
    vault_pki, root_ca_args, allow_premature_rotation, existing_root, testmode, container
):
    root_ca_args = root_ca_args.copy()  # we modify the dict, which is shared
    cert = load_cert(existing_root["certificate"])
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 2
    nc = cert.extensions.get_extension_for_class(cx509.NameConstraints)
    if container.matches("vault>=1.19"):
        assert len(nc.value.permitted_subtrees) == 6
        assert len(nc.value.excluded_subtrees) == 5
    else:
        assert len(nc.value.permitted_subtrees) == 2
        assert nc.value.excluded_subtrees is None
    expected_ext_changes = {
        "basicConstraints",
        "subjectAltName",
        "nameConstraints",
    }
    root_ca_args["signature_bits"] = 512
    root_ca_args["max_path_length"] = None
    if "key_usage" in root_ca_args:  # Vault 1.20+/OpenBao
        root_ca_args["key_usage"] = None
        expected_ext_changes.add("keyUsage")
    root_ca_args["exclude_cn_from_sans"] = False
    root_ca_args["permitted_alt_names"], permitted_removed = (
        root_ca_args["permitted_alt_names"][:-1],
        root_ca_args["permitted_alt_names"][-1],
    )
    if "excluded_alt_names" in root_ca_args:  # Vault 1.19+ only
        root_ca_args["excluded_alt_names"] = root_ca_args["excluded_alt_names"][:-1]
    root_ca_args["locality"] = "Salt Lake City"
    root_ca_args.pop("serial_number")

    if allow_premature_rotation:
        root_ca_args["allow_premature_rotation"] = True

    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert (ret.result is False) is not allow_premature_rotation
    assert (ret.result is None) is (testmode and allow_premature_rotation)
    if allow_premature_rotation:
        assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    else:
        assert (
            f"{'Would have r' if testmode else 'R'}efused to rotate root CA certificate"
            in ret.comment
        )
    assert ret.changes
    assert "issuer_id" in ret.changes
    assert "key_id" not in ret.changes
    assert ret.changes["issuer_id"]["old"] == existing_root["issuer_id"]
    assert (ret.changes["issuer_id"]["new"] == "<TBD>") is (
        testmode or not allow_premature_rotation
    )
    assert "old_issuer" in ret.changes
    assert ret.changes["old_issuer"] == {
        "issuer_id": existing_root["issuer_id"],
        "usage": {"removed": ["issuing-certificates"]},
    }

    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "subject_name" in cert_changes
    assert cert_changes["signature_bits"] == {"old": 384, "new": 512}
    assert "private_key" not in cert_changes

    assert set(cert_changes["extensions"]["changed"]) == expected_ext_changes
    changed_exts = cert_changes["extensions"]["changed"]
    assert changed_exts["basicConstraints"]["value"]["pathlen"] == {
        "old": 2,
        "new": None,
    }
    assert changed_exts["subjectAltName"]["value"]["added"] == ["DNS:test.root.ca"]
    assert changed_exts["subjectAltName"]["value"]["removed"] == []
    assert changed_exts["nameConstraints"]["value"]["permitted_subtrees"]["added"] == []
    pm_typ, pm_val = permitted_removed.split(":", maxsplit=1)
    assert changed_exts["nameConstraints"]["value"]["permitted_subtrees"]["removed"] == [
        f"{pm_typ.upper()}:{pm_val}"
    ]
    if "excluded_alt_names" in root_ca_args:
        assert changed_exts["nameConstraints"]["value"]["excluded_subtrees"]["added"] == []
        assert changed_exts["nameConstraints"]["value"]["excluded_subtrees"]["removed"] == [
            "URI:no.bar.baz"
        ]
    else:
        assert "excluded_subtrees" not in changed_exts["nameConstraints"]["value"]
    assert "subjectKeyIdentifier" not in changed_exts
    if "key_usage" in root_ca_args:
        assert changed_exts["keyUsage"]["value"]["digitalSignature"] == {
            "new": False,
            "old": True,
        }

    new_info = _default_issuer()
    assert (new_info == existing_root) is (testmode or not allow_premature_rotation)
    assert new_info["key_id"] == existing_root["key_id"]
    new_cert = load_cert(new_info["certificate"])
    if testmode or not allow_premature_rotation:
        assert new_cert == cert
        return

    basic_constraints = new_cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length is None
    if "key_usage" in root_ca_args:
        key_usage = new_cert.extensions.get_extension_for_class(cx509.KeyUsage)
        assert key_usage.value.crl_sign
        assert key_usage.value.key_cert_sign
        assert not key_usage.value.digital_signature
    nc = new_cert.extensions.get_extension_for_class(cx509.NameConstraints)
    if container.matches("vault>=1.19"):
        assert len(nc.value.permitted_subtrees) == 5
        assert len(nc.value.excluded_subtrees) == 4
    else:
        assert len(nc.value.permitted_subtrees) == 1
        assert nc.value.excluded_subtrees is None


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    ({"days_valid": 100, "days_remaining": 30},),
    indirect=True,
)
def test_root_issuer_managed_changes_expiry(vault_pki, root_ca_args, testmode):
    """
    Ensure we don't need allow_premature_rotation when the certificate expires
    and that expiry alone is enough to trigger rotation.
    """
    issuer_info = _default_issuer()
    root_ca_args["days_remaining"], root_ca_args["days_valid"] = (
        root_ca_args["days_valid"] + 1,
        root_ca_args["days_valid"] + 1000,
    )
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "expiration" in cert_changes
    old_year = int(cert_changes["not_after"]["old"].split("-", maxsplit=1)[0])
    new_year = int(cert_changes["not_after"]["new"].split("-", maxsplit=1)[0])
    assert new_year > old_year
    assert (_default_issuer() == issuer_info) is testmode


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    ({"days_valid": 100, "days_remaining": 30},),
    indirect=True,
)
@pytest.mark.parametrize("allow_premature_rotation", (False, True))
def test_root_issuer_managed_changes_not_after(vault_pki, root_ca_args, allow_premature_rotation):
    """
    Ensure an explicit not_after is always recognized, but does not count as expiry.
    """
    issuer_info = _default_issuer()
    root_ca_args["days_remaining"] = 1
    not_after = (datetime.now(tz=timezone.utc) + timedelta(days=1000)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    root_ca_args["not_after"] = not_after
    if allow_premature_rotation:
        root_ca_args["allow_premature_rotation"] = True
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert (ret.result is False) is not allow_premature_rotation
    if allow_premature_rotation:
        assert "CA certificate has been rotated" in ret.comment
    else:
        assert "Set `allow_premature_rotation=true`" in ret.comment
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "not_after" in cert_changes
    assert "expiration" not in cert_changes
    old_year = int(cert_changes["not_after"]["old"].split("-", maxsplit=1)[0])
    new_year = int(cert_changes["not_after"]["new"].split("-", maxsplit=1)[0])
    assert new_year > old_year
    assert cert_changes["not_after"]["new"] == not_after
    assert (_default_issuer() == issuer_info) is not allow_premature_rotation


@pytest.mark.usefixtures("clean_pki_issuers")
@pytest.mark.parametrize("allow_premature_rotation", (False, True))
def test_root_issuer_managed_changes_existing_key(
    vault_pki, root_ca_args, testmode, allow_premature_rotation
):
    key_1 = vault_write("pki/keys/generate/internal", key_name="old_key")["data"]
    key_2 = vault_write("pki/keys/generate/internal", key_name="new_key")["data"]
    root_ca_args["key_ref"] = key_1["key_name"]
    if allow_premature_rotation:
        root_ca_args["allow_premature_rotation"] = True

    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    issuer_info = _default_issuer()
    assert issuer_info["key_id"] == key_1["key_id"]

    # Ensure key_ref is idempotent when specified via name
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == issuer_info

    # Ensure key_ref is idempotent when specified via ID
    root_ca_args["key_ref"] = key_1["key_id"]
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == issuer_info

    # Ensure existing issuer key is kept, even if key_ref is removed
    root_ca_args.pop("key_ref")
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == issuer_info

    # Now change the explicit key_ref to a key_name of a different key
    root_ca_args["key_ref"] = key_2["key_name"]
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert (ret.result is False) is not allow_premature_rotation
    assert (ret.result is None) is (testmode and allow_premature_rotation)
    if allow_premature_rotation:
        assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    else:
        assert f"{'Would have r' if testmode else 'R'}efused to rotate" in ret.comment
    assert ret.changes
    assert "key_id" in ret.changes
    assert ret.changes["key_id"]["old"] == key_1["key_id"]
    assert (ret.changes["key_id"]["new"] == "<TBD>") is (testmode or not allow_premature_rotation)
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "private_key" in cert_changes
    assert "subjectKeyIdentifier" in cert_changes["extensions"]["changed"]
    assert (
        cert_changes["extensions"]["changed"]["subjectKeyIdentifier"]["value"]["new"] == "<TBD>"
    ) is (testmode or not allow_premature_rotation)
    new_info = _default_issuer()
    assert (new_info == issuer_info) is (testmode or not allow_premature_rotation)
    if testmode or not allow_premature_rotation:
        return
    assert new_info["key_id"] == key_2["key_id"]
    assert ret.changes["key_id"]["new"] == key_2["key_id"]


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "aia_urls",
    (
        pytest.param({}, id="no_urls"),
        pytest.param(
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="aia_only",
        ),
        pytest.param(
            {
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
            },
            id="crl_only",
        ),
        pytest.param(
            {
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
            },
            id="deltacrl_only",
        ),
        pytest.param(
            {
                "crl_distribution_points": [
                    "https://crl1.root.ca",
                    "https://crl2.root.ca",
                ],  # required on OpenBao for FreshestCRL to be included
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
            },
            id="crl_and_deltacrl",
        ),
        pytest.param(
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="all_urls",
        ),
        pytest.param(
            {
                "enable_templating": True,
                "issuing_certificates": [
                    "https://one.root.ca/{{issuer_id}}",
                    "{{cluster_aia_path}}issuer/{{issuer_id}}/der",
                ],
                "crl_distribution_points": [
                    "https://crl1.root.ca/{{issuer_id}}",
                    "{{cluster_path}}/crl/pem",
                ],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca/{{issuer_id}}",
                    "{{cluster_aia_path}}/issuer/{{issuer_id}}/crl/delta/der",
                ],
                "ocsp_servers": [
                    "{{cluster_aia_path}}/ocsp",
                ],
            },
            # Referencing issuer_id causes all URL extensions to be absent
            id="templating_skipped",
        ),
        pytest.param(
            {
                "enable_templating": True,
                "issuing_certificates": [
                    "https://one.root.ca/my_issuer",
                    "{{cluster_aia_path}}issuer/my_issuer/der",
                ],
                "crl_distribution_points": [
                    "https://crl1.root.ca/my_issuer",
                    "{{cluster_path}}/crl/pem",
                ],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca/my_issuer",
                    # cluster_aia_path includes a final /, ensure we're idempotent without normalization
                    "{{cluster_aia_path}}/issuer/my_issuer/crl/delta/der",
                ],
                "ocsp_servers": [
                    "{{cluster_aia_path}}/ocsp",
                ],
            },
            id="templating_included",
        ),
    ),
    indirect=True,
)
@pytest.mark.behavior_test
def test_root_issuer_managed_ok_aia(vault_pki, root_ca_args):  # pragma: no cover
    issuer_info = _default_issuer()
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert "Root CA issuer is present as specified" in ret.comment
    assert "AIA-related URLs do not match" not in ret.comment
    assert not ret.changes
    new_info = _default_issuer()
    assert new_info == issuer_info


@pytest.mark.parametrize("aia_urls", (MOUNT_URL_CONFIG,), indirect=True)
@pytest.mark.usefixtures("clean_pki_issuers", "aia_urls", "url_config_read_denied")
def test_root_issuer_managed_url_config_denied(vault_pki, root_ca_args):
    """
    Ensure a denied URL read access does not cause rotation, only a note.
    """
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert "has been created" in ret.comment
    assert AIA_UNVERIFIED_NOTE not in ret.comment
    issuer_info = _default_issuer()
    _assert_embedded_aia(load_cert(issuer_info["certificate"]), MOUNT_URL_CONFIG)

    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment
    assert AIA_UNVERIFIED_NOTE in ret.comment
    assert _default_issuer()["issuer_id"] == issuer_info["issuer_id"]


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "aia_urls",
    (
        pytest.param({}, id="no_urls"),
        pytest.param(
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="aia_only",
        ),
        pytest.param(
            {
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
            },
            id="crl_only",
        ),
        pytest.param(
            {
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
            },
            marks=pytest.mark.requires_backend("vault>=1.20"),
            id="deltacrl_only",
        ),
        pytest.param(
            {
                "crl_distribution_points": [  # required on OpenBao
                    "https://crl1.root.ca",
                    "https://crl2.root.ca",
                ],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
            },
            marks=pytest.mark.requires_backend("vault>=1.20", "openbao"),
            id="crl_and_deltacrl",
        ),
        pytest.param(
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            marks=pytest.mark.requires_backend("vault>=1.20", "openbao"),
            id="all_urls",
        ),
    ),
    indirect=True,
)
@pytest.mark.behavior_test
def test_root_issuer_managed_changes_aia(
    vault_pki, root_ca_args, testmode, aia_urls, container
):  # pragma: no cover
    exp = act = None
    if not aia_urls:
        aia_urls, exp, act = (
            {"issuing_certificates": ["https://one.root.ca"]},
            {"authorityInfoAccess"},
            "added",
        )
    elif len(aia_urls) >= 4:
        aia_urls, exp, act = (
            {
                "issuing_certificates": "",
                "crl_distribution_points": "",
                "delta_crl_distribution_points": "",
                "ocsp_servers": "",
            },
            {"authorityInfoAccess", "cRLDistributionPoints", "freshestCRL"},
            "removed",
        )
        if not container.matches("vault>=1.20", "openbao"):
            aia_urls.pop("delta_crl_distribution_points")
            exp.remove("freshestCRL")
    elif "issuing_certificates" in aia_urls:
        _, exp, act = (
            aia_urls["issuing_certificates"].append("https://three.root.ca"),
            {"authorityInfoAccess"},
            "changed",
        )
    elif "crl_distribution_points" in aia_urls:
        _, exp, act = (
            aia_urls["crl_distribution_points"].append("https://crl3.root.ca"),
            {"cRLDistributionPoints"},
            "changed",
        )
    elif "delta_crl_distribution_points" in aia_urls:
        _, exp, act = (
            aia_urls["delta_crl_distribution_points"].append("https://crl3.root.ca"),
            {"freshestCRL"},
            "changed",
        )
    elif "ocsp_servers" in aia_urls:  # pragma: no cover
        _, exp, act = (
            aia_urls["ocsp_servers"].append("https://ocsp3.root.ca"),
            {"authorityInfoAccess"},
            "changed",
        )
    vault_write("pki/config/urls", **aia_urls)
    issuer_info = _default_issuer()
    root_ca_args["days_remaining"] = 10000  # force re-issuance, otherwise changes are not reported
    root_ca_args["days_valid"] = 10001
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    if act:
        assert "extensions" in cert_changes
        assert set(cert_changes["extensions"][act]) == exp
    new_info = _default_issuer()
    assert (new_info == issuer_info) is testmode


@pytest.mark.usefixtures("existing_root")
def test_root_issuer_managed_alt_names(vault_pki, root_ca_args, existing_root, testmode):
    # otherName requires x509_v2 support, otherwise the state is not idempotent
    root_ca_args["alt_names"] = [
        "dns:test2.root.ca",
        "ip:1.2.3.4",
        "uri:https://root.ca",
        "email:test@root.ca",
    ]
    root_ca_args["allow_premature_rotation"] = True
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    ext_changes = cert_changes.get("extensions")
    assert ext_changes
    assert "subjectAltName" in ext_changes["changed"]
    new_info = _default_issuer()
    if testmode:
        assert new_info["issuer_id"] == existing_root["issuer_id"]
        return
    cert = load_cert(new_info["certificate"])
    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert len(sans.value._general_names._general_names) == 5  # cn is included
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes

    root_ca_args["exclude_cn_from_sans"] = True
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    ext_changes = cert_changes.get("extensions")
    assert ext_changes
    assert "subjectAltName" in ext_changes["changed"]
