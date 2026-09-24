"""
Tests for the (ca_)certificate_managed states:
certificate contents (subject, SANs, extensions, AIA URLs, sign-verbatim).
"""

import ipaddress
import logging

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat import asn1
from salt.utils.x509 import NAME_ATTRS_OID
from salt.utils.x509 import load_cert

from tests.common.containers import genmarks
from tests.common.helpers.vault_pki import pregen_csr
from tests.support.vault import vault_write

pytestmark = genmarks(mounts="pki")


@pytest.mark.usefixtures("issuer_setup", "existing_cert")
def test_ca_certificate_managed_signature_bits(vault_pki, ca_cert_args):
    ca_cert_args["signature_bits"] = 256
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes

    ca_cert_args["signature_bits"] = 384
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert "signature_bits" in ret.changes
    assert ret.changes["signature_bits"] == {"old": 256, "new": 384}

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "testrole")
@pytest.mark.parametrize(
    "csr,testrole,cn_in_csr,cn_in_args,exp",
    (
        pytest.param(False, {}, False, "a.b", "a.b", id="regular_common_name"),
        pytest.param(True, {}, False, "a.b", "a.b", id="csr_common_name_only"),
        pytest.param(True, {}, "a.b", False, "a.b", id="csr_cn_only"),
        pytest.param(True, {}, "a.b", "c.d", "a.b", id="csr_cn_mismatch"),
        pytest.param(True, {"require_cn": False}, False, False, None, id="csr_no_require_cn_empty"),
        pytest.param(
            True, {"use_csr_common_name": False}, "a.b", "c.d", "c.d", id="csr_ignore_cn_mismatch"
        ),
        pytest.param(
            True,
            {"use_csr_common_name": False, "require_cn": False},
            "a.b",
            False,
            None,
            id="csr_no_require_ignore_cn_empty",
        ),
    ),
    indirect=["testrole"],
)
def test_certificate_managed_cn_ok(vault_pki, cert_args, csr, cn_in_csr, cn_in_args, exp):
    if cn_in_args:
        cert_args["common_name"] = cn_in_args
    else:
        cert_args.pop("common_name")
    if csr:
        if cn_in_csr:
            cert_args["CN"] = cn_in_csr
        pregen_csr(cert_args)
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes

    cert = load_cert(cert_args["name"])
    assert [cn.value for cn in cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)] == (
        [exp] if exp else []
    )

    # Try again
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.parametrize(
    "csr,verbatim,cn_in_csr,cn_in_args,exp",
    (
        pytest.param(False, False, False, "a.b", "a.b", id="regular_common_name"),
        pytest.param(False, True, False, "a.b", "a.b", id="regular_common_name_verbatim"),
        pytest.param(False, False, False, False, False, id="regular_missing"),
        pytest.param(False, True, False, False, False, id="regular_missing_verbatim"),
        pytest.param(True, False, False, "a.b", "a.b", id="csr_common_name_only"),
        pytest.param(True, True, False, "a.b", False, id="csr_common_name_only_verbatim"),
        pytest.param(True, False, "a.b", False, "a.b", id="csr_cn_only"),
        pytest.param(True, True, "a.b", False, "a.b", id="csr_cn_only_verbatim"),
        pytest.param(True, False, "a.b", "c.d", "c.d", id="csr_cn_mismatch"),
        pytest.param(True, True, "a.b", "c.d", "a.b", id="csr_cn_mismatch_verbatim"),
        pytest.param(True, False, False, False, False, id="csr_missing"),
        pytest.param(True, True, False, False, False, id="csr_missing_verbatim"),
    ),
)
def test_ca_certificate_managed_cn_ok(
    vault_pki, ca_cert_args, csr, cn_in_csr, cn_in_args, verbatim, exp
):
    if cn_in_args:
        ca_cert_args["common_name"] = cn_in_args
    else:
        ca_cert_args.pop("common_name")
    if csr:
        if cn_in_csr:
            ca_cert_args["CN"] = cn_in_csr
        pregen_csr(ca_cert_args)
    ret = vault_pki.ca_certificate_managed(**ca_cert_args, sign_verbatim=verbatim)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes

    cert = load_cert(ca_cert_args["name"])
    assert [cn.value for cn in cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)] == (
        [exp] if exp else []
    )

    # Try again
    ret = vault_pki.ca_certificate_managed(**ca_cert_args, sign_verbatim=verbatim)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_ca_certificate_managed_missing_cn(vault_pki, ca_cert_args):
    ca_cert_args.pop("common_name")
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(ca_cert_args["name"])
    assert cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"]) == []

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("testrole", ({"require_cn": False},), indirect=True)
def test_certificate_managed_without_common_name(vault_pki, cert_args, testrole):
    cert_args.pop("common_name")
    cert_args["CN"] = "should.not.matter"
    ret = vault_pki.certificate_managed(**cert_args)

    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(cert_args["name"])
    assert cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME) == []
    with pytest.raises(cx509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes

    # Now try with require_cn
    testrole["require_cn"] = True
    vault_write("pki/roles/testrole", **testrole)
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is False
    assert "`common_name` is required" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_verbatim_without_common_name(vault_pki, cert_args):
    cert_args.pop("common_name")
    cert_args["CN"] = "should.not.matter"
    cert_args["sign_verbatim"] = True
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(cert_args["name"])
    assert cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME) == []
    with pytest.raises(cx509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.parametrize("existing_cert", ({"alt_names": ["dns:foo.bar.baz"]},), indirect=True)
def test_certificate_managed_exclude_cn_from_sans(cert_typ, existing_cert):
    """
    By default, the common name is included in the SANs. Ensure setting
    ``exclude_cn_from_sans`` is detected as a change, honored during
    reissuance and idempotent.
    """
    cert_managed, cert_args = cert_typ
    cert = load_cert(cert_args["name"])
    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
    assert cert_args["common_name"] in sans.get_values_for_type(cx509.DNSName)

    cert_args["exclude_cn_from_sans"] = True
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
    assert cert_args["common_name"] not in sans.get_values_for_type(cx509.DNSName)

    # Ensure it's idempotent still
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    (
        pytest.param({"common_name": "foo.bar.baz"}, id="dns_cn"),
        pytest.param({"common_name": "foo@bar.baz"}, id="email_cn"),
        pytest.param({"common_name": "Neither an email nor a domain"}, id="invalid_cn"),
    ),
    indirect=True,
)
def test_certificate_managed_not_exclude_cn_from_sans(vault_pki, cert_args):
    """
    Ensure email common names are included as emails, domain common names as DNSName and
    invalid ones are ignored.
    """
    cert = load_cert(cert_args["name"])
    cn = cert_args["common_name"]
    try:
        sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
    except cx509.ExtensionNotFound:
        sans = None

    if sans is None:
        assert " " in cn
    elif "@" in cn:
        assert cert_args["common_name"] in sans.get_values_for_type(cx509.RFC822Name)
    elif " " not in cn:
        assert cert_args["common_name"] in sans.get_values_for_type(cx509.DNSName)
    else:
        raise AssertionError("No SANs expected for invalid email/dns CN")

    # Ensure it's idempotent still
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.parametrize(
    "existing_cert", ({"sign_verbatim": True, "O": "Salt Project", "C": "US"},), indirect=True
)
def test_certificate_managed_subject_attr_comparison(vault_pki, cert_args, existing_cert):
    """
    Ensure subject attributes other than CN are compared as well.
    """
    cert_args["C"] = "UK"
    cert_args["L"] = "Boston"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert ret.changes["subject_name"] == {
        "old": "CN=saltproject.io,O=Salt Project,C=US",
        "new": "CN=saltproject.io,O=Salt Project,L=Boston,C=UK",
    }
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    assert cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["O"])[0].value == "Salt Project"
    assert cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["C"])[0].value == "UK"
    assert cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["L"])[0].value == "Boston"


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    (
        pytest.param({"user_ids": "foo", "serial_number": "foobar"}, id="single_with_serial"),
        pytest.param({"user_ids": "foo,bar"}, id="comma_separated"),
        pytest.param({"user_ids": ["bar", "foo"]}, id="list"),
    ),
    indirect=True,
)
def test_certificate_managed_user_ids_and_serial_number(vault_pki, cert_args):
    cert: cx509.Certificate = load_cert(cert_args["name"])
    user_ids = [uid.value for uid in cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["UID"])]
    assert user_ids == (
        cert_args["user_ids"].split(",")
        if isinstance(cert_args["user_ids"], str)
        else cert_args["user_ids"]
    )
    ssn = [sn.value for sn in cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["SERIALNUMBER"])]
    if cert_args.get("serial_number"):
        assert ssn == [cert_args["serial_number"]]
    else:
        assert not ssn

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("sign_verbatim", (False, True))
def test_certificate_managed_san(cert_typ, sign_verbatim):
    """
    Ensure changes to the requested SANs are detected and applied.
    This test is quite complex, when it should not be.
    TODO: Refactor into separate tests.
    """
    cert_managed, cert_args = cert_typ

    def _assert_san(ass):
        cert = load_cert(cert_args["name"])
        try:
            sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
        except cx509.ExtensionNotFound:
            if ass is False:
                return
            raise
        if ass is False:
            raise AssertionError(f"subjectAltName extension still present! Values: {list(sans)}")
        for typ, (in_vals, out_vals) in ass.items():
            typ_sans = sans.get_values_for_type(typ)
            if typ is cx509.IPAddress:
                typ_sans = [str(x) for x in typ_sans]
            elif typ is cx509.OtherName:
                typ_sans = [
                    f"{on.type_id.dotted_string}:{asn1.decode_der(str, on.value)}"
                    for on in sans.get_values_for_type(cx509.OtherName)
                ]
            for is_in in in_vals:
                assert is_in in typ_sans
            for is_out in out_vals:
                assert is_out not in typ_sans

    def render_other(in_vals):
        isl = True
        ret = []
        if isinstance(in_vals, str):
            in_vals = [in_vals]
            isl = False
        for in_val in in_vals:
            if in_val.startswith("IP"):
                ret.append("IP:" + ipaddress.ip_address(in_val.split(":", maxsplit=1)[1]).exploded)
            elif in_val.startswith(("DNS", "email", "URI")):
                ret.append(in_val.replace("überexample", "xn--berexample-8db"))
            else:
                typ, val = in_val.split(":", maxsplit=1)
                ret.append(f"otherName:{typ};UTF8:{val}")
        if not isl:
            return ret[0]
        return ret

    dns, email, uri, ip, other = (
        cx509.DNSName,
        cx509.RFC822Name,
        cx509.UniformResourceIdentifier,
        cx509.IPAddress,
        cx509.OtherName,
    )

    # Add cert with diverse SANs
    cert_args.pop("alt_names", None)
    cert_args["sign_verbatim"] = sign_verbatim
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    init_vals = [
        "1.2.3.4:Hi there!",
        "1.2.3.4:You too :)",
        "2.3.4.5:Are you guys seriously talking to yourselves?",
        "DNS:foo.example.com",
        "DNS:foo2.example.com",
        "DNS:foo2.überexample.com",
        "email:foo@b.ar",
        "IP:1.1.1.1",
        "IP:13::17",
        "URI:https://f.o.o/bar/baz",
        "URI:https://f.o.o/bar/quux",
    ]
    # expectations of <type>: present[], absent[]
    exp = {
        dns: (["foo.example.com"] + ([] if sign_verbatim else [cert_args["common_name"]]), []),
        email: (["foo@b.ar"], []),
        uri: (["https://f.o.o/bar/baz"], []),
        ip: (["1.1.1.1", "13::17"], []),
        other: (
            [
                "1.2.3.4:Hi there!",
                "1.2.3.4:You too :)",
                "2.3.4.5:Are you guys seriously talking to yourselves?",
            ],
            [],
        ),
    }
    if "role_name" in cert_args:
        # sign_intermediate handles csr kwargs the other way around from sign_certificate
        cert_args["subjectAltName"] = ["DNS:this.should.not.matter"]
    cert_args["alt_names"] = init_vals.copy()
    added_vals = init_vals.copy()

    ret = cert_managed(**cert_args)
    assert ret.result is True
    if sign_verbatim:
        assert set(ret.changes["extensions"]["added"]["subjectAltName"]["value"]) == set(
            render_other(added_vals)
        )
    else:
        assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
            "added": list(sorted(render_other(added_vals))),
            "removed": [],
        }

    _assert_san(exp)

    # Ensure we're idempotent
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes

    # Now add more SANs
    change_vals = [
        "DNS:foo3.example.com",
        "email:bar@b.az",
        "URI:https://f.o.o/bar/wut",
        "IP:2.2.2.2",
        "1.2.3.4:No! :|",
        "1.3.6.1.5.5.7.8.9::::::!@#$%^&*",
    ]
    cert_args["alt_names"].extend(change_vals)
    exp[dns][0].append("foo3.example.com")
    exp[email][0].append("bar@b.az")
    exp[uri][0].append("https://f.o.o/bar/wut")
    exp[ip][0].append("2.2.2.2")
    exp[other][0].extend(["1.2.3.4:No! :|", "1.3.6.1.5.5.7.8.9::::::!@#$%^&*"])

    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
        "added": list(sorted(render_other(change_vals))),
        "removed": [],
    }

    _assert_san(exp)

    if not sign_verbatim:
        # Exclude CN from SANs
        cert_args["exclude_cn_from_sans"] = True
        exp[dns][0].remove(cert_args["common_name"])
        exp[dns][1].append(cert_args["common_name"])
        ret = cert_managed(**cert_args)
        assert ret.result is True
        assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
            "added": [],
            "removed": [f"DNS:{cert_args['common_name']}"],
        }

        _assert_san(exp)

    # Now remove the initial SANs
    cert_args["alt_names"] = list(change_vals)
    exp[dns] = (["foo3.example.com"], ["foo.example.com"])
    exp[email] = (["bar@b.az"], ["foo@b.ar"])
    exp[uri] = (["https://f.o.o/bar/wut"], ["https://f.o.o/bar/baz"])
    exp[ip] = (["2.2.2.2"], ["1.1.1.1", "13::17"])
    exp[other] = (["1.2.3.4:No! :|"], ["1.2.3.4:Hi there!"])
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
        "added": [],
        "removed": list(sorted(render_other(init_vals))),
    }

    _assert_san(exp)

    # Now swap both sets in one swoop
    cert_args["alt_names"] = list(init_vals)
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
        "added": list(sorted(render_other(init_vals))),
        "removed": list(sorted(render_other(change_vals))),
    }
    exp = {k: (v[1], v[0]) for k, v in exp.items()}

    _assert_san(exp)

    remove_vals = cert_args.pop("alt_names")
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert set(ret.changes["extensions"]["removed"]["subjectAltName"]["value"]) == set(
        render_other(remove_vals)
    )
    _assert_san(False)


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert", "testrole")
@pytest.mark.parametrize(
    "existing_cert,testrole,additional",
    (
        pytest.param(
            {
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "test.saltproject.io",
                "common_name": None,
            },
            {},
            ("dns", "test.saltproject.io"),
            id="CN",
        ),
        pytest.param(
            {
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "Something neither DNS nor EMAIL",
                "common_name": None,
            },
            {},
            (),
            id="CN_invalid",
        ),
        pytest.param(
            {
                "exclude_cn_from_sans": True,
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "test.saltproject.io",
                "common_name": None,
            },
            {},
            (),
            id="exclude_cn",
        ),
        pytest.param(
            {
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "wrong.saltproject.io",
                "common_name": "test.saltproject.io",
            },
            {"use_csr_common_name": False},
            ("dns", "test.saltproject.io"),
            id="ignore_CN",
        ),
        pytest.param(
            {
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.san",
                    "EMAIL:test@saltproject.san",
                    "IP:1.2.3.5",
                    "URI:https://foo.bar.san",
                ],
                "alt_names": [
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "test.saltproject.io",
                "common_name": "wrong.saltproject.io",
            },
            {"use_csr_sans": False},
            ("dns", "test.saltproject.io"),
            id="ignore_sans",
        ),
        pytest.param(
            {
                "generate_csr": True,
                "CN": "test.saltproject.io",
                "common_name": None,
                # still need DNS: prefix because the execution module does not have role insight and needs to parse it a bit
                "alt_names": ["DNS:this_should_not_even_be_parsed"],
            },
            {},
            ("dns", "test.saltproject.io"),
            id="no_sans",
        ),
    ),
    indirect=["existing_cert", "testrole"],
)
def test_certificate_managed_san_from_csr(vault_pki, cert_args, additional):
    cert: cx509.Certificate = load_cert(cert_args["name"])
    san = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert san.critical is False

    exp = {"dns": set(), "mail": set(), "ip": set(), "uri": set()}
    if "DNS:this_should_not_even_be_parsed" not in cert_args.get("alt_names", []):
        exp["dns"] = {"*.saltproject.io"}
        exp["mail"] = {"test@saltproject.io"}
        exp["ip"] = {ipaddress.ip_address("1.2.3.4")}
        exp["uri"] = {"https://foo.bar.baz"}
    if additional:
        exp[additional[0]].add(additional[1])
    assert set(san.value.get_values_for_type(cx509.DNSName)) == exp["dns"]
    assert set(san.value.get_values_for_type(cx509.RFC822Name)) == exp["mail"]
    assert set(san.value.get_values_for_type(cx509.IPAddress)) == exp["ip"]
    assert set(san.value.get_values_for_type(cx509.UniformResourceIdentifier)) == exp["uri"]

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert,empty",
    (
        pytest.param(
            {
                "sign_verbatim": True,
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "test.saltproject.io",
                "common_name": None,
            },
            False,
            id="verbatim",
        ),
        pytest.param(
            {
                "generate_csr": True,
                "sign_verbatim": True,
                "CN": "test.saltproject.io",
                "common_name": None,
                "alt_names": ["this_should_not_even_be_parsed"],
            },
            True,
            id="verbatim_no_sans",
        ),
    ),
    indirect=["existing_cert"],
)
def test_ca_certificate_managed_san_from_csr(vault_pki, ca_cert_args, empty):
    """
    sign_intermediate does not merge SANs from API and CSR and only respects them at all with sign_verbatim
    """
    cert: cx509.Certificate = load_cert(ca_cert_args["name"])
    if empty:
        with pytest.raises(cx509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    else:
        san = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        assert san.critical is True
        assert set(san.value.get_values_for_type(cx509.DNSName)) == {"*.saltproject.io"}
        assert set(san.value.get_values_for_type(cx509.RFC822Name)) == {"test@saltproject.io"}
        assert set(san.value.get_values_for_type(cx509.IPAddress)) == {
            ipaddress.ip_address("1.2.3.4")
        }
        assert set(san.value.get_values_for_type(cx509.UniformResourceIdentifier)) == {
            "https://foo.bar.baz"
        }

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert", "roles_setup")
@pytest.mark.parametrize(
    "aia_urls,issuer_setup",
    (
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
            {},
            id="mount_config_only",
        ),
        pytest.param(
            {},
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="issuer_config_only",
        ),
        pytest.param(
            {
                "issuing_certificates": [
                    "https://one.root-general.ca",
                    "https://two.root-general.ca",
                ],
                "crl_distribution_points": [
                    "https://crl1.root-general.ca",
                    "https://crl2.root-general.ca",
                ],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root-general.ca",
                    "https://deltacrl2.root-general.ca",
                ],
                "ocsp_servers": ["https://ocsp1.root-general.ca", "https://ocsp2.root-general.ca"],
            },
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="issuer_overrides_mount",
        ),
        pytest.param(
            {
                "issuing_certificates": [
                    "https://one.root-general.ca",
                    "https://two.root-general.ca",
                ],
            },
            {
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
            id="partial_issuer_disables_mount",
        ),
    ),
    indirect=True,
)
def test_certificate_managed_urls(cert_typ, issuer_setup, aia_urls, container):
    """
    Ensure issuer URLs are added to the certificate as intended. If the issuer has any configured URL,
    the mount default URLs are not applied.
    """
    cert_managed, cert_args = cert_typ
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes

    # Now check that we recognize URL changes.
    # Whether issuer was not configured before (first test case)
    issuer_first_configured = not any(
        url in issuer_setup
        for url in (
            "issuing_certificates",
            "ocsp_servers",
            "crl_distribution_points",
            "delta_crl_distribution_points",
        )
    )
    had_crl_config = "crl_distribution_points" in (
        issuer_setup if not issuer_first_configured else aia_urls
    )
    issuer_id = issuer_setup.pop("issuer_id")
    issuer_setup["ocsp_servers"] = ["https://new-ocsp.root.ca"]
    issuer_setup["crl_distribution_points"] = ["https://new-crl.root.ca"]
    vault_write(f"/pki/issuer/{issuer_id}", **issuer_setup)
    ret = cert_managed(**cert_args)

    assert ret.result is True
    assert "extensions" in ret.changes
    exp_aia = {
        "added": {"OCSP": ["URI:https://new-ocsp.root.ca"]},
        "removed": {
            "OCSP": ["URI:https://ocsp1.root.ca", "URI:https://ocsp2.root.ca"],
        },
    }

    if issuer_first_configured:
        exp_aia["removed"]["caIssuers"] = ["URI:https://one.root.ca", "URI:https://two.root.ca"]
        # delta_crl_distribution_points requires Vault 1.20+/OpenBao, not present in 1.14.8
        assert ("freshestCRL" in ret.changes["extensions"]["removed"]) is (
            container.matches("vault>=1.20", "openbao")
        )
    else:
        assert "freshestCRL" not in ret.changes["extensions"]["removed"]
    assert ret.changes["extensions"]["changed"]["authorityInfoAccess"]["value"] == exp_aia
    if had_crl_config:
        exp_crl = {
            "changed": [
                {
                    "fullname": {
                        "new": ["URI:https://new-crl.root.ca"],
                        "old": ["URI:https://crl1.root.ca"],
                    }
                }
            ],
            "removed": [
                {
                    "crlissuer": [],
                    "fullname": ["URI:https://crl2.root.ca"],
                    "reasons": [],
                    "relativename": None,
                }
            ],
        }
        assert ret.changes["extensions"]["changed"]["cRLDistributionPoints"]["value"] == exp_crl
    else:
        assert "cRLDistributionPoints" in ret.changes["extensions"]["added"]

    # One final idempotency check
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "cluster_config", "aia_urls")
@pytest.mark.parametrize(
    "aia_urls",
    (
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
                # cluster_aia_path includes a final /, ensure we're idempotent without normalization
                "{{cluster_aia_path}}/issuer/{{issuer_id}}/crl/delta/der",
            ],
            "ocsp_servers": [
                "https://ocsp1.root.ca/{{issuer_id}}",
                "{{cluster_aia_path}}/ocsp",
            ],
        },
    ),
    indirect=True,
)
def test_certificate_managed_urls_templating(cert_typ):
    """
    Ensure templated issuer URLs are rendered as expected/don't cause non-idempotency.
    """
    cert_managed, cert_args = cert_typ
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert", "issuer_setup", "roles_setup")
def test_certificate_managed_basic_constraints(vault_pki, cert_args, testmode, roles_setup):
    roles_setup["testrole"]["basic_constraints_valid_for_non_ca"] = True
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    # Ensure we recognize the extension being added
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "extensions" in ret.changes
    assert "basicConstraints" in ret.changes["extensions"]["added"]

    if not testmode:
        # Ensure idempotency
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is True
        assert not ret.changes

    # Ensure we recognize the extension not being added
    roles_setup["testrole"]["basic_constraints_valid_for_non_ca"] = False
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert bool(ret.changes) is not testmode


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.parametrize(
    "call_type", ("pk", "pk_verbatim", "pk_verbatim_kwargs", "csr", "csr_verbatim")
)
def test_ca_certificate_managed_basic_constraints_issuer_constrained(
    vault_pki, ca_cert_args, call_type
):
    csr = "csr" in call_type
    verbatim = "verbatim" in call_type
    ca_cert_args["sign_verbatim"] = verbatim
    ca_cert_args.pop("max_path_length", None)
    if (csr and verbatim) or "kwargs" in call_type:
        ca_cert_args["basicConstraints"] = {"ca": True, "pathlen": 10}
        if csr:
            ca_cert_args = pregen_csr(ca_cert_args)
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(ca_cert_args["name"])
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 2

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes

    ca_cert_args["max_path_length"] = -1
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is False
    assert "unconstrained `max_path_length` is not allowed" in ret.comment
    assert "only `2` or less can be requested" in ret.comment
    assert not ret.changes

    ca_cert_args["max_path_length"] = 3
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is False
    assert "`3` exceeds the maximum" in ret.comment
    assert "only `2` or less can be requested" in ret.comment
    assert not ret.changes

    ca_cert_args["max_path_length"] = 1
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert ret.changes
    assert "basicConstraints" in ret.changes["extensions"]["changed"]
    assert ret.changes["extensions"]["changed"]["basicConstraints"]["value"]["pathlen"] == {
        "old": 2,
        "new": 1,
    }
    cert = load_cert(ca_cert_args["name"])
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 1

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes

    ca_cert_args.pop("max_path_length")
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert ret.changes
    assert "basicConstraints" in ret.changes["extensions"]["changed"]
    assert ret.changes["extensions"]["changed"]["basicConstraints"]["value"]["pathlen"] == {
        "old": 1,
        "new": 2,
    }
    cert = load_cert(ca_cert_args["name"])
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 2


@pytest.mark.usefixtures("issuer_setup_no_pathlen")
@pytest.mark.parametrize("call_type", ("pk", "pk_verbatim_kwargs", "csr_verbatim"))
def test_ca_certificate_managed_basic_constraints_issuer_unconstrained(
    vault_pki, ca_cert_args, call_type
):
    csr = "csr" in call_type
    verbatim = "verbatim" in call_type
    ca_cert_args["sign_verbatim"] = verbatim
    ca_cert_args.pop("max_path_length", None)
    if (csr and verbatim) or "kwargs" in call_type:
        ca_cert_args["basicConstraints"] = {"ca": True, "pathlen": 10}
        if csr:
            ca_cert_args = pregen_csr(ca_cert_args)
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(ca_cert_args["name"])
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length is None

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes

    ca_cert_args["max_path_length"] = -1
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes

    ca_cert_args["max_path_length"] = 2
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert ret.changes
    assert "basicConstraints" in ret.changes["extensions"]["changed"]
    assert ret.changes["extensions"]["changed"]["basicConstraints"]["value"]["pathlen"] == {
        "old": None,
        "new": 2,
    }
    cert = load_cert(ca_cert_args["name"])
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 2

    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert not ret.changes

    ca_cert_args.pop("max_path_length")
    ret = vault_pki.ca_certificate_managed(**ca_cert_args)
    assert ret.result is True
    assert ret.changes
    assert "basicConstraints" in ret.changes["extensions"]["changed"]
    assert ret.changes["extensions"]["changed"]["basicConstraints"]["value"]["pathlen"] == {
        "old": 2,
        "new": None,
    }
    cert = load_cert(ca_cert_args["name"])
    bc = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length is None


@pytest.mark.usefixtures("existing_cert", "issuer_setup", "roles_setup")
def test_certificate_managed_key_usage(vault_pki, cert_args, testmode, roles_setup):
    roles_setup["testrole"]["key_usage"] = [
        "digitalsignature",
        "keyagreement",  # needs to be set for encipheronly/decipheronly (cryptography fails, Vault succeeds)
        # "keyencipherment",  # this is removed vs the defaults
        "contentcommitment",
        "dataencipherment",
        "encipheronly",
        "decipheronly",
        "keycertsign",  # keyCertSign is not accepted by Vault,
        "crlsign",  # but cRLsign is
    ]
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    # Ensure we recognize the extension being changed
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "extensions" in ret.changes
    assert ret.changes["extensions"]["changed"]["keyUsage"]["value"] == {
        "keyEncipherment": {"new": False, "old": True},
        "nonRepudiation": {"new": True, "old": False},  # contentCommitment
        "dataEncipherment": {"new": True, "old": False},
        "encipherOnly": {"new": True, "old": False},
        "decipherOnly": {"new": True, "old": False},
        "cRLSign": {"new": True, "old": False},
    }

    if not testmode:
        # Ensure idempotency
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is True
        assert not ret.changes

    # Ensure we recognize the extension being removed
    roles_setup["testrole"]["key_usage"] = []
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "keyUsage" in ret.changes["extensions"]["removed"]

    if not testmode:
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is True
        assert not ret.changes


@pytest.mark.usefixtures("existing_cert", "issuer_setup")
@pytest.mark.parametrize(
    "call_type", ("pk", "pk_verbatim", "pk_verbatim_kwargs", "csr", "csr_verbatim")
)
@pytest.mark.requires_backend("vault>=1.20", "openbao")
def test_ca_certificate_managed_key_usage(vault_pki, ca_cert_args, call_type):
    csr = "csr" in call_type
    verbatim = "verbatim" in call_type
    # Ensure we recognize the extension being changed
    if (csr and verbatim) or "kwargs" in call_type:
        ca_cert_args["keyUsage"] = ["keyCertSign", "digitalSignature"]
        exp_critical, exp_val = False, {
            "cRLSign": {"old": True, "new": False},
            "digitalSignature": {"old": False, "new": True},
        }
        if csr:
            ca_cert_args = pregen_csr(ca_cert_args)
    else:
        ca_cert_args["key_usage"] = ["digitalsignature"]
        exp_critical, exp_val = True, {"digitalSignature": {"old": False, "new": True}}
    ret = vault_pki.ca_certificate_managed(**ca_cert_args, sign_verbatim=verbatim)
    assert ret.result is True
    assert "extensions" in ret.changes
    assert ret.changes["extensions"]["changed"]["keyUsage"]["value"] == exp_val
    if not exp_critical:
        assert ret.changes["extensions"]["changed"]["keyUsage"]["critical"] == {
            "old": True,
            "new": False,
        }

    # Ensure idempotency
    ret = vault_pki.ca_certificate_managed(**ca_cert_args, sign_verbatim=verbatim)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert", "issuer_setup", "roles_setup")
def test_certificate_managed_ext_key_usage(vault_pki, cert_args, testmode, roles_setup):
    roles_setup["testrole"]["ext_key_usage"] = ["timestamping", "serverauth"]
    roles_setup["testrole"]["client_flag"] = False
    roles_setup["testrole"]["code_signing_flag"] = True
    roles_setup["testrole"]["email_protection_flag"] = True
    roles_setup["testrole"]["ext_key_usage_oids"] = ["1.2.3.4.5.6.7.8"]
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    # Ensure we recognize the extension being changed
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "extensions" in ret.changes
    assert ret.changes["extensions"]["changed"]["extendedKeyUsage"]["value"] == {
        "added": ["1.2.3.4.5.6.7.8", "codeSigning", "emailProtection", "timeStamping"],
        "removed": ["clientAuth"],
    }

    if not testmode:
        # Ensure idempotency
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is True
        assert not ret.changes

    # Ensure we recognize the extension being removed
    roles_setup["testrole"]["client_flag"] = False
    roles_setup["testrole"]["server_flag"] = False
    roles_setup["testrole"]["code_signing_flag"] = False
    roles_setup["testrole"]["email_protection_flag"] = False
    roles_setup["testrole"]["ext_key_usage"] = []
    roles_setup["testrole"]["ext_key_usage_oids"] = []
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "extendedKeyUsage" in ret.changes["extensions"]["removed"]

    if not testmode:
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is True
        assert not ret.changes


@pytest.mark.usefixtures("existing_cert", "issuer_setup", "roles_setup")
def test_certificate_managed_certificate_policies(vault_pki, cert_args, testmode, roles_setup):
    roles_setup["testrole"]["policy_identifiers"] = [
        "2.3.4.5.6.7.8.9",
        '{"oid":"1.2.3.4.5.6","notice":"foo"}',
        '{"oid":"1.2.3.4.5.7","cps":"https://foo.bar/cps_pointer"}',
        '{"oid":"1.2.3.4.5.8","cps":"https://foo.bar/cps_pointer","notice":"bar"}',
    ]
    vault_write("pki/roles/testrole", **roles_setup["testrole"])

    # Ensure we recognize the extension being changed
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "extensions" in ret.changes
    cpo = {}
    for pol in ret.changes["extensions"]["added"]["certificatePolicies"]["value"]:
        cpo.update(pol)
    assert cpo["2.3.4.5.6.7.8.9"] == []
    assert cpo["1.2.3.4.5.6"][0]["explicit_text"] == "foo"
    assert cpo["1.2.3.4.5.7"] == [{"practice_statement": "https://foo.bar/cps_pointer"}]
    assert cpo["1.2.3.4.5.8"][0] == {"practice_statement": "https://foo.bar/cps_pointer"}
    assert cpo["1.2.3.4.5.8"][1]["explicit_text"] == "bar"

    if not testmode:
        # Ensure idempotency
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is True
        assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.parametrize(
    "call_type", ("pk", "pk_verbatim", "pk_verbatim_kwargs", "csr", "csr_verbatim")
)
def test_ca_certificate_managed_name_constraints(vault_pki, ca_cert_args, container, call_type):
    csr = "csr" in call_type
    verbatim = "verbatim" in call_type
    ca_cert_args["permitted_alt_names"] = ["dns:.foo.bar"]
    if has_all_constraints := container.matches("vault>=1.19"):
        ca_cert_args["permitted_alt_names"].extend(
            ["email:.email.foo.bar", "ip:0.0.0.0/1", "uri:.uri.foo.bar"]
        )
        ca_cert_args["excluded_alt_names"] = [
            "dns:no.foo.bar",
            "email:info@email.foo.bar",
            "ip:0.0.0.0/24",
            "uri:no.uri.foo.bar",
        ]
    if (csr and verbatim) or "kwargs" in call_type:
        nc_def = {
            "permitted": ca_cert_args.pop("permitted_alt_names"),
        }
        if "excluded_alt_names" in ca_cert_args:
            nc_def["excluded"] = ca_cert_args.pop("excluded_alt_names")
        ca_cert_args["nameConstraints"] = nc_def
        if csr:
            ca_cert_args = pregen_csr(ca_cert_args)
    ret = vault_pki.ca_certificate_managed(**ca_cert_args, sign_verbatim=verbatim)
    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(ca_cert_args["name"])
    nc = cert.extensions.get_extension_for_class(cx509.NameConstraints)
    pst = nc.value.permitted_subtrees or []
    pst_vals = [str(gn.value) for gn in pst]
    assert ".foo.bar" in pst_vals
    if has_all_constraints:
        assert len(pst) == 4
        assert ".email.foo.bar" in pst_vals
        assert ".uri.foo.bar" in pst_vals
        assert "0.0.0.0/1" in pst_vals
    else:
        assert len(pst) == 1
    est = nc.value.excluded_subtrees
    if has_all_constraints:
        assert est is not None
        assert len(est) == 4
        est_vals = [str(gn.value) for gn in est]
        assert "no.foo.bar" in est_vals
        assert "info@email.foo.bar" in est_vals
        assert "no.uri.foo.bar" in est_vals
        assert "0.0.0.0/24" in est_vals
    else:
        assert est is None

    ret = vault_pki.ca_certificate_managed(**ca_cert_args, sign_verbatim=verbatim)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.internal_logic_test
def test_certificate_managed_csr_ignored_warnings(
    vault_pki, cert_args, caplog, testrole, private_key
):
    csr_args = {
        "CN": "test.saltproject.io",
        "subjectAltName": ["DNS:test.saltproject.io"],
        "private_key": private_key,
    }
    cert_args.pop("common_name", None)
    cert_args.update(csr_args)
    cert_args = pregen_csr(cert_args)  # this removes CSR args from cert_args

    # Ensure no warnings by default
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(**cert_args)
        assert ret.result is True and "created" in ret.changes
        assert "Ignoring" not in caplog.text

    # CSR with CN + common_name warns
    caplog.clear()
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(**cert_args, common_name="this.is.warned.about")
        assert ret.result is True and not ret.changes
        assert "Ignoring passed `common_name`" in caplog.text

    # CSR without CN + common_name does not warn, even if use_csr_common_name is at its default of true
    cert_args.update(csr_args)  # need to add CN back in
    cert_args.pop("CN")
    cert_args = pregen_csr(cert_args)
    caplog.clear()
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(**cert_args, common_name="test.saltproject.io")
        assert ret.result is True and not ret.changes
        assert "Ignoring passed `common_name`" not in caplog.text

    # CSR with CN + common_name does not warn when use_csr_common_name is false
    cert_args.update(csr_args)  # need to add CN back in
    cert_args = pregen_csr(cert_args)
    testrole["use_csr_common_name"] = False
    cert_args["common_name"] = "test.saltproject.io"
    vault_write("pki/roles/testrole", **testrole)
    caplog.clear()
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(**cert_args)
        assert ret.result is True and not ret.changes
        assert "Ignoring passed `common_name`" not in caplog.text

    # CSR with or without SANs + alt_names warns
    caplog.clear()
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(**cert_args, alt_names=["DNS:this.is.warned.about"])
        assert ret.result is True and not ret.changes
        assert "Ignoring passed `alt_names`" in caplog.text

    # CSR with or without SANs + alt_names does not warn when use_csr_sans is false
    testrole["use_csr_sans"] = False
    cert_args["alt_names"] = ["DNS:test.saltproject.io"]
    vault_write("pki/roles/testrole", **testrole)
    caplog.clear()
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(**cert_args)
        assert ret.result is True and not ret.changes
        assert "Ignoring passed `alt_names`" not in caplog.text

    # CSR + CSR generation kwargs warns
    caplog.clear()
    with caplog.at_level(logging.WARN):
        ret = vault_pki.certificate_managed(
            **cert_args, CN="this.is.warned.about", keyUsage="critical,crlSign,keyCertSign"
        )
        assert ret.result is True and not ret.changes
        assert "received CSR generation arguments. Ignoring: `CN`, `keyUsage`" in caplog.text


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    (
        pytest.param({"sign_verbatim": True, "user_ids": "foo"}, id="single"),
        pytest.param(
            {"sign_verbatim": True, "user_ids": "foo,bar", "serial_number": "foobar"},
            id="comma_separated_with_serial",
        ),
        pytest.param({"sign_verbatim": True, "user_ids": ["bar", "foo"]}, id="list"),
    ),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_user_ids_and_serial_number(vault_pki, cert_args):
    cert: cx509.Certificate = load_cert(cert_args["name"])
    user_ids = [uid.value for uid in cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["UID"])]
    exp_uids = (
        cert_args["user_ids"].split(",")
        if isinstance(cert_args["user_ids"], str)
        else cert_args["user_ids"]
    )
    assert user_ids == exp_uids
    ssn = [sn.value for sn in cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["SERIALNUMBER"])]
    if cert_args.get("serial_number"):
        assert ssn == [cert_args["serial_number"]]
        # Assert ASN1 order being the same as the one Vault encodes in regular mode
        assert (
            cert.subject.rfc4514_string()
            == ",".join(f"UID={uid}" for uid in reversed(exp_uids))
            + f",2.5.4.5={cert_args['serial_number']},CN=saltproject.io"
        )
    else:
        assert not ssn
        assert (
            cert.subject.rfc4514_string()
            == ",".join(f"UID={uid}" for uid in reversed(exp_uids)) + ",CN=saltproject.io"
        )

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    (
        pytest.param(
            {
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "CN": "test.saltproject.io",
                "common_name": None,
                "sign_verbatim": True,
            },
            id="from_csr",
        ),
        pytest.param(
            {
                "generate_csr": True,
                "subjectAltName": [
                    "critical",
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                # still need DNS: prefix because the execution module does not have role insight and needs to parse it a bit
                "alt_names": ["DNS:this_should_not_even_be_parsed"],
                "CN": "test.saltproject.io",
                "common_name": None,
                "sign_verbatim": True,
            },
            id="from_csr_ignore_alt_names",
        ),
        pytest.param(
            {
                "sign_verbatim": True,
                "alt_names": [
                    "DNS:*.saltproject.io",
                    "EMAIL:test@saltproject.io",
                    "IP:1.2.3.4",
                    "URI:https://foo.bar.baz",
                ],
                "common_name": "test.saltproject.io",
            },
            id="from_alt_names",
        ),
    ),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_subject_alt_name(vault_pki, cert_args):
    cert: cx509.Certificate = load_cert(cert_args["name"])
    san = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert san.critical is ("csr" in cert_args)
    assert set(san.value.get_values_for_type(cx509.DNSName)) == {"*.saltproject.io"}
    assert set(san.value.get_values_for_type(cx509.RFC822Name)) == {"test@saltproject.io"}
    assert set(san.value.get_values_for_type(cx509.IPAddress)) == {ipaddress.ip_address("1.2.3.4")}
    assert set(san.value.get_values_for_type(cx509.UniformResourceIdentifier)) == {
        "https://foo.bar.baz"
    }

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    # intentionally leave keyUsage non-critical
    (
        pytest.param(
            {
                "generate_csr": True,
                "sign_verbatim": True,
                "keyUsage": ["digitalSignature", "keyAgreement"],
            },
            id="from_csr",
        ),
        pytest.param(
            {"sign_verbatim": True, "keyUsage": ["digitalSignature", "keyAgreement"]},
            id="from_csr_on_the_fly",
        ),
        pytest.param(
            {
                "sign_verbatim": True,
                "key_usage": ["digitalSignature", "keyAgreement"],
            },
            id="fallback",
        ),
    ),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_key_usage(vault_pki, cert_args):
    cert = load_cert(cert_args["name"])
    key_usage = cert.extensions.get_extension_for_class(cx509.KeyUsage)
    assert key_usage.critical is ("key_usage" in cert_args)
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_agreement is True
    assert key_usage.value.key_encipherment is False

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    # intentionally make extendedKeyUsage critical
    (
        pytest.param(
            {
                "sign_verbatim": True,
                "extendedKeyUsage": [
                    "critical",
                    "timeStamping",
                    "emailProtection",
                    "1.3.6.1.4.1.311.2.1.21",
                ],
            },
            id="from_csr",
        ),
        pytest.param(
            {
                "sign_verbatim": True,
                "ext_key_usage": [
                    "timeStamping",
                    "emailProtection",
                ],
                "ext_key_usage_oids": [
                    "1.3.6.1.4.1.311.2.1.21",
                ],
            },
            id="fallback",
        ),
    ),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_extended_key_usage(vault_pki, cert_args):
    cert = load_cert(cert_args["name"])
    ext_key_usage = cert.extensions.get_extension_for_class(cx509.ExtendedKeyUsage)
    assert ext_key_usage.critical is ("extendedKeyUsage" in cert_args)
    ext_key_usages = {usage.dotted_string for usage in ext_key_usage.value}
    assert ext_key_usages == {"1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.4", "1.3.6.1.4.1.311.2.1.21"}

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    ({"sign_verbatim": True, "subjectKeyIdentifier": "ca:fe:ba:be"},),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_explicit_subject_key_identifier(cert_typ):
    cert_managed, cert_args = cert_typ
    cert = load_cert(cert_args["name"])
    ski = cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier)
    assert ski.value.digest.hex() == "cafebabe"

    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    ({"sign_verbatim": True, "tlsfeature": "status_request"},),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_other_ext(cert_typ):
    cert_managed, cert_args = cert_typ
    cert: cx509.Certificate = load_cert(cert_args["name"])
    tls = cert.extensions.get_extension_for_class(cx509.TLSFeature)
    assert list(tls.value) == [cx509.TLSFeatureType.status_request]

    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_changed_cn(vault_pki, cert_args, testmode):
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes

    old_cn = cert_args["common_name"]
    cert_args["common_name"] = "brand new common name"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert (ret.result is None) is testmode
    cert = load_cert(cert_args["name"])

    assert "subject_name" in ret.changes
    assert f"CN={old_cn}" in ret.changes["subject_name"]["old"]
    assert f"CN={cert_args['common_name']}" in ret.changes["subject_name"]["new"]
    # The new CN is not a valid DNS/EMAIL SAN and no alt_names are specified
    assert "extensions" in ret.changes
    assert "subjectAltName" in ret.changes["extensions"]["removed"]

    c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])
    assert c_attrs[0].value == (old_cn if testmode else "brand new common name")


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "testrole")
@pytest.mark.parametrize(
    "testrole",
    (
        pytest.param({}, id="use_csr_cn"),
        pytest.param({"use_csr_common_name": False}, id="ignore_csr_cn"),
    ),
    indirect=True,
)
def test_certificate_managed_use_csr_common_name(vault_pki, cert_args):
    cert_args["CN"] = (
        "cn.saltproject.io"  # Ensure this parameter for create_csr is synchronized with the common_name one
    )
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes
    cert = load_cert(cert_args["name"])
    assert (
        cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)[0].value == "saltproject.io"
    )
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "attr,replace",
    [
        pytest.param({"L": "Boston"}, {"L": "Moscow"}, id="locality"),
        pytest.param({"C": "US"}, {"C": "RU"}, id="country"),
        pytest.param({"ST": "That Street"}, {"ST": "Other Street"}, id="state"),
        pytest.param({"O": "Salt Project"}, {"O": "Salt"}, id="organization"),
        pytest.param({"OU": "Salt Extensions"}, {"OU": "Extensions"}, id="org_unit"),
        pytest.param(
            {
                "L": "Boston",
                "C": "US",
                "ST": "That Street",
                "O": "Salt Project",
                "OU": "Salt Extensions",
            },
            {
                "L": "Moscow",
                "C": "RU",
                "ST": "Other Street",
                "O": "Salt",
                "OU": "Extensions",
            },
            id="all_attrs",
        ),
    ],
)
def test_certificate_managed_subject(cert_typ, attr, replace, testmode):
    cert_managed, args = cert_typ
    args["sign_verbatim"] = True
    args = {**args, **attr}
    ret = cert_managed(**args)
    assert ret.result
    assert "created" in ret.changes

    cert = load_cert(args["name"])
    for k, v in attr.items():
        c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[k])
        assert len(c_attrs) == 1
        assert c_attrs[0].value == v

    args = {**args, **replace}
    ret = cert_managed(**args, test=testmode)
    assert (ret.result is None) is testmode
    cert = load_cert(args["name"])

    assert "subject_name" in ret.changes

    for k, v in replace.items():
        assert f"{k}={attr[k]}" in ret.changes["subject_name"]["old"]
        assert f"{k}={v}" in ret.changes["subject_name"]["new"]
        c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[k])
        assert len(c_attrs) == 1
        assert c_attrs[0].value == (attr[k] if testmode else v)


@pytest.mark.usefixtures("issuer_setup", "issuer_setup_additional")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_changed_issuer(vault_pki, cert_args, testmode):
    cert_args["issuer_ref"] = "root"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes

    cert_args["issuer_ref"] = "additional"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "issuer_name" in ret.changes
