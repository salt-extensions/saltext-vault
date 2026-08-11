"""
Integration tests for the vault_pki state module, specifically
remote certificate signing via the x509_v2 modules (``ca_server``).
"""

import pytest
from cryptography import x509 as cx509
from salt.utils.x509 import NAME_ATTRS_OID
from salt.utils.x509 import load_cert
from saltfactories.utils import random_string

from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_read

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies"),
    pytest.mark.parametrize("secret_mounts", ("pki",), indirect=True),
]


CA_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIIbfpgqP0VGPgwDQYJKoZIhvcNAQELBQAwKzELMAkGA1UE
BhMCVVMxDTALBgNVBAMMBFRlc3QxDTALBgNVBAoMBFNhbHQwHhcNMjIxMTE1MTQw
NDMzWhcNMzIxMTEyMTQwNDMzWjArMQswCQYDVQQGEwJVUzENMAsGA1UEAwwEVGVz
dDENMAsGA1UECgwEU2FsdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AOGTScvrjcEt6vsJcG9RUp6fKaDNDWZnJET0omanK9ZwaoGpJPp8UDYe/8ADeI7N
10wdyB4oDM9gRDjInBtdQO/PsrmKZF6LzqVFgLMxu2up+PHMi9z6B2P4esIAzMu9
PYxc9zH4HzLImHqscVD2HCabsjp9X134Af7hVY5NN/W/4qTP7uOM20wSG2TPI6+B
tA9VyPbEPMPRzXzrqc45rVYe6kb2bT84GE93Vcu/e5JZ/k2AKD8Hoa2cxLPsTLq5
igl+D+k+dfUtiABiKPvVQiYBsD1fyHDn2m7B6pCgvrGqHjsoAKufgFnXy6PJRg7n
vQfaxSiusM5s+VS+fjlvgwsCAwEAAaNgMF4wDwYDVR0TBAgwBgEB/wIBATALBgNV
HQ8EBAMCAQYwHQYDVR0OBBYEFFzy8fRTKSOe7kBakqO0Ki71potnMB8GA1UdIwQY
MBaAFFzy8fRTKSOe7kBakqO0Ki71potnMA0GCSqGSIb3DQEBCwUAA4IBAQBZS4MP
fXYPoGZ66seM+0eikScZHirbRe8vHxHkujnTBUjQITKm86WeQgeBCD2pobgBGZtt
5YFozM4cERqY7/1BdemUxFvPmMFFznt0TM5w+DfGWVK8un6SYwHnmBbnkWgX4Srm
GsL0HHWxVXkGnFGFk6Sbo3vnN7CpkpQTWFqeQQ5rHOw91pt7KnNZwc6I3ZjrCUHJ
+UmKKrga16a4Q+8FBpYdphQU609npo/0zuaE6FyiJYlW3tG+mlbbNgzY/+eUaxt2
9Bp9mtA+Hkox551Mfpq45Oi+ehwMt0xjZCjuFCM78oiUdHCGO+EmcT7ogiYALiOF
LN1w5sybsYwIw6QN
-----END CERTIFICATE-----
"""

CA_KEY = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4ZNJy+uNwS3q+wlwb1FSnp8poM0NZmckRPSiZqcr1nBqgakk
+nxQNh7/wAN4js3XTB3IHigMz2BEOMicG11A78+yuYpkXovOpUWAszG7a6n48cyL
3PoHY/h6wgDMy709jFz3MfgfMsiYeqxxUPYcJpuyOn1fXfgB/uFVjk039b/ipM/u
44zbTBIbZM8jr4G0D1XI9sQ8w9HNfOupzjmtVh7qRvZtPzgYT3dVy797kln+TYAo
PwehrZzEs+xMurmKCX4P6T519S2IAGIo+9VCJgGwPV/IcOfabsHqkKC+saoeOygA
q5+AWdfLo8lGDue9B9rFKK6wzmz5VL5+OW+DCwIDAQABAoIBAFfImc9hu6iR1gAb
jEXFwAE6r1iEc9KGEPdEvG52X/jzhn8u89UGy7BEIAL5VtE8Caz1agtSSqnpLKNs
blO31q18hnDuCmFAxwpKIeuaTvV3EAoJL+Su6HFfIWaeKRSgcHNPOmOXy4xXw/75
XJ/FJu9fZ9ybLaHEAgLObh0Sr9RSPQbZ72ZawPP8+5WCbR+2w90RApHXQL0piSbW
lIx1NE6o5wQb3vik8z/k5FqLCY2a8++WNyfvS+WWFY5WXGI7ZiDDQk46gnslquH2
Lon5CEn3JlTGQFhxaaa2ivssscf2lA2Rvm2E8o1rdZJS2OpSE0ai4TXY9XnyjZj1
5usWIwECgYEA+3Mwu03A7PyLEBksS/u3MSo/176S9lF/uXcecQNdhAIalUZ8AgV3
7HP2yI9ZC0ekA809ZzFjGFostXm9VfUOEZ549jLOMzvBtCdaI0aBUE8icu52fX4r
fT2NY6hYgz5/fxD8sq1XH/fqNNexABwtViH6YAly/9A1/8M3BOWt72UCgYEA5ag8
sIfiBUoWd1sS6qHDuugWlpx4ZWYC/59XEJyCN2wioP8qFji/aNZxF1wLfyQe/zaa
YBFusjsBnSfBU1p4UKCRHWQ9/CnC0DzqTkyKC4Fv8GuxgywNm5W9gPKk7idHP7mw
e+7Uvf1pOQccqEPh7yltpW+Xw27gfsC2DMAIGa8CgYByv/q5P56PiCCeVB6W/mR3
l2RTPLEsn7y+EtJdmL+QgrVG8kedVImJ6tHwbRqhvyvmYD9pXGxwrJZCqy/wjkjB
WaSyFjVrxBV99Yd5Ga/hyntaH+ELHA0UtoZTuHvMSTU9866ei+R6vlSvkM9B0ZoO
+KqeMTG99HLwKVJudbKO0QKBgQCd33U49XBOqoufKSBr4yAmUH2Ws6GgMuxExUiY
xr5NUyzK+B36gLA0ZZYAtOnCURZt4x9kgxdRtnZ5jma74ilrY7XeOpbRzfN6KyX3
BW6wUh6da6rvvUztc5Z+Gk9+18mG6SOFTr04jgfTiCwPD/s06YnSfFAbrRDukZOU
WD45SQKBgBvjSwl3AbPoJnRjZjGuCUMKQKrLm30xCeorxasu+di/4YV5Yd8VUjaO
mYyqXW6bQndKLuXT+AXtCd/Xt2sI96z8mc0G5fImDUxQjMUuS3RyQK357cEOu8Zy
HdI7Pfaf/l0HozAw/Al+LXbpmSBdfmz0U/EGAKRqXMW5+vQ7XHXD
-----END RSA PRIVATE KEY-----"""


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        # Allow minions to request certificate signing by the CA minion
        "peer": {
            ".*": [
                "x509.sign_remote_certificate",
            ],
        },
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "pki_admin",
                ],
            },
        },
    }


@pytest.fixture(scope="module")
def minion_config_overrides(salt_version):
    if salt_version[0] < 3008:
        # Need to enable x509_v2 explicitly on Salt <3008
        return {"features": {"x509_v2": True}}
    return {}


@pytest.fixture(scope="module")
def ca_minion(master, salt_version):
    defaults = {
        "x509_signing_policies": {
            "vault_intermediate": {
                "signing_cert": CA_CERT,
                "signing_private_key": CA_KEY,
                "basicConstraints": "critical, CA:true, pathlen:0",
                "keyUsage": "critical, cRLSign, keyCertSign",
                "authorityKeyIdentifier": "keyid:always",
                "subjectKeyIdentifier": "hash",
            },
        },
    }
    overrides = {}
    if salt_version[0] < 3008:
        # Need to enable x509_v2 explicitly on Salt <3008
        overrides["features"] = {"x509_v2": True}
    factory = master.salt_minion_daemon(
        random_string("ca-minion-", uppercase=False),
        defaults=defaults,
        overrides=overrides,
    )
    with factory.started():
        yield factory


@pytest.fixture
def clean_pki_mount():
    try:
        yield
    finally:
        for issuer in vault_list("pki/issuers"):
            vault_delete(f"pki/issuer/{issuer}")
        for key in vault_list("pki/keys"):
            vault_delete(f"pki/key/{key}")


def _subject_cn(cert):
    return cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])[0].value


@pytest.mark.usefixtures("clean_pki_mount")
def test_intermediate_ca_present_with_remote_signing(salt_call_cli, ca_minion):
    """
    Ensure an intermediate CA can be provisioned and rotated when its
    certificate is signed by a CA minion via peer communication,
    without local access to the signing private key.
    """

    def _apply(**kwargs):
        ret = salt_call_cli.run("state.single", "vault_pki.intermediate_ca_present", **kwargs)
        assert ret.returncode == 0, ret.stderr
        assert isinstance(ret.data, dict)
        return ret.data[next(iter(ret.data))]

    state_args = {
        "name": "Test Remote Intermediate CA",
        "mount": "pki",
        "ca_server": ca_minion.id,
        "signing_policy": "vault_intermediate",
        "days_valid": 90,
        "append_certs": [CA_CERT],
    }

    res = _apply(**state_args)
    assert res["result"] is True
    assert "created" in res["changes"]
    issuer_info = vault_read("pki/issuer/default")["data"]
    cert = load_cert(issuer_info["certificate"])
    assert _subject_cn(cert) == "Test Remote Intermediate CA"
    assert cert.issuer.get_attributes_for_oid(NAME_ATTRS_OID["CN"])[0].value == "Test"
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 0
    # The appended root CA certificate should have been imported as well,
    # completing the intermediate issuer's chain
    chain = issuer_info["ca_chain"]
    assert len(chain) == 2
    assert _subject_cn(load_cert(chain[1])) == "Test"

    # The state should be idempotent
    res = _apply(**state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "present as specified" in res["comment"]

    # Rotation should replace the default issuer, but reuse its key
    state_args["name"] = "Rotated Remote Intermediate CA"
    res = _apply(**state_args)
    assert res["result"] is True
    assert res["changes"]["cert"]["subject_name"] == "CN=Rotated Remote Intermediate CA"
    new_info = vault_read("pki/issuer/default")["data"]
    assert new_info["issuer_id"] != issuer_info["issuer_id"]
    assert new_info["key_id"] == issuer_info["key_id"]
    assert _subject_cn(load_cert(new_info["certificate"])) == "Rotated Remote Intermediate CA"
