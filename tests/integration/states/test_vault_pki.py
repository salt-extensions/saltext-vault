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
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_policies"),
    pytest.mark.parametrize("secret_mounts", ("pki",), indirect=True),
]


# This hardcoded cert expires Nov 12 14:04:33 2032 GMT
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


PRIVKEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9rv+XRGjI4P8I
CkRQJnR2lLOjg21h7zRGDpAYxxjkW5MIeHWWB4O4V92mMlbYGu4vE5NdXnShZB0o
Xd1rlP3jIlpWW5xUTjXQFTQA1WMRcXf3dkscW0R/HDnb71imtnWWct+3Hpk1+p+L
+CzTOthVG92Eggxy327wG6k3JIOm51iL4oxrJ/Y6tqZslFGVkjIaAi8yReS7BZCC
P93qGFMoydjMmGUZrAWHIrFGWLH0dphR5fZPiLdHCwxZ0tl45wJ91yPzqy6ke8UN
kyi9BgOCcFg/nXI1TL6S0T7QlVrPRFJ45EpMEYkgaqDmVnwKVRTX8jkuBipR8OdL
YWhj4yFPAgMBAAECggEAHojrUDiM/blqlKrCcHygRu6NNIdVtmxBZ/20KKj0Ut6C
/twVYb937tcGMVjtLgC30xA9qswnzktFflgN6uGjNUs0a653rgKhGwwuwOuY9Rfl
DgsW8Euo7SVoEwWmqb+5kiyP4vSkCVJ9GJUs8hwI8zp3IHum8V8ShsiNJvlT0Cwq
N1nhmRCdT6W1oVlllcWJEk7QfW43bU69gAMMg4R5cUVLFPb2y3aKx4lPLAjjnGkF
nIG7wjjLSR1Zp5jsoVEesRWKHWDI9vj2H7HNQ2HmRKlcE5+Vzv/IviE0xiqomsyr
rlKqPrvQ9Y/OZ2wxzbrPIH8FqPN9o8Qn/IJa8cBVEQKBgQD8IgFzq6/xZDWkCpDy
EcqOqzIxyTpvKsclvbQUT0pJvCG4k2UiOVwPdKeqAXyfdClyESCNsQZ6K7s4Eit8
llXWRFEXb93Jw0WYi+sikxO6skkQIzu4SZOl0ZGUCpva4GDRy/uFFcQrJB6xDY4z
h0ucDSYt8xCY9pjsSU47uRBxuwKBgQDAl8l82BGcGiGRFhYI6E74agK71tpTQ4M2
0lDC5MpTPvitrzneBNLXyXzz0vTU4lF32EBthZlZ76rOSaElNt8EFbPIysfzRmZv
dotqi5xYR+NSFZh7l9K6K6EkvxjU+OdTLY5X+96glbuCkvsER4X7KavQzMQymBv0
MpjwSti7fQKBgF8o+oFMuFAUMUajkkc6vceRB5XQzBQvAhDVg4Ty1Cf2MIf4YYBE
Q+G1dp5shzurXQUnP7EaskYkATpNaUpRdz4ydKSy3POMltTXYjyfZB/fsEG9+ok4
g9heu2IzitVWQFSOd3SoXWym6kqKwjPiiX/xWoqXJZmF4Pu1Qyi5VWKHAoGAEzsU
03J/z6aMU4BxEtKfkA6F11vM0SOcpoy5o7xUt5tCGZW1oYW5x/JGl9IowFkY6W6e
gFEmzuQvmgmgHacs/attGE+nR5NwBxE/OpRWODp1aGzfnPe8Avr4TEMIp7ty3cte
u0pbII3S+2bRycuahUnT7jWEIckugWPMAbJ3kcECgYASe1rXPbiUTZpGVFALgCj/
8Y3ExHhMXLHNslf6fp0oDjW4fg+6iGeUxkMdyB8EVRFFJuUktU5wh2Nsx3xMMQ9g
cH4XpX9nGyPNjPazuKzovnRcW2NGx3CAW7aJE2BQ/MsohU8H+MhKGgu9lqQpDajU
8dbwN+rCJaQ9xzaih50KIA==
-----END PRIVATE KEY-----
"""


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
                    # Denies read access to `pki/config/urls` and `pki/config/cluster`
                    # for all tests in this module to verify graceful degradation.
                    "pki_deny_urls",
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
                "subject": {
                    "O": "Test Org",
                },
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
        vault_delete("pki/root")


@pytest.fixture(scope="module", autouse=True)
def cluster_config(secret_mounts):  # pylint: disable=unused-argument
    cluster = {
        "path": "https://vault.example.com/v1/pki",
        "aia_path": "https://aia.example.com/v1/pki",
    }
    vault_write(  # pylint: disable=kwarg-superseded-by-positional-arg
        "pki/config/cluster", **cluster
    )
    return cluster


def _subject(cert, typ):
    return cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[typ])[0].value


def _apply(salt_call_cli, state_func, **kwargs):
    ret = salt_call_cli.run("state.single", f"vault_pki.{state_func}", **kwargs)
    assert ret.returncode == 0, ret.stderr
    assert isinstance(ret.data, dict)
    return ret.data[next(iter(ret.data))]


@pytest.mark.usefixtures("clean_pki_mount")
def test_intermediate_issuer_managed_with_remote_signing(salt_call_cli, ca_minion):
    """
    Ensure an intermediate CA can be provisioned and rotated when its
    certificate is signed by a CA minion via peer communication,
    without local access to the signing private key/cert.
    """

    state_args = {
        "name": "Test Remote Intermediate CA",
        "mount": "pki",
        "ca_server": ca_minion.id,
        "signing_policy": "vault_intermediate",
        "days_valid": 90,
        "append_certs": [CA_CERT],
    }

    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert "created" in res["changes"]
    issuer_info = vault_read("pki/issuer/default")["data"]
    cert = load_cert(issuer_info["certificate"])
    assert _subject(cert, "CN") == "Test Remote Intermediate CA"
    assert _subject(cert, "O") == "Test Org"
    assert cert.issuer.get_attributes_for_oid(NAME_ATTRS_OID["CN"])[0].value == "Test"
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 0
    # The appended root CA certificate should have been imported as well,
    # completing the intermediate issuer's chain
    chain = issuer_info["ca_chain"]
    assert len(chain) == 2
    assert _subject(load_cert(chain[1]), "CN") == "Test"

    # The state should be idempotent
    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "present as specified" in res["comment"]

    # ... also when the signing policy overrides args (x509.certificate_managed works the same)
    state_args["max_path_length"] = 1
    state_args["subjectKeyIdentifier"] = "cafebabe"
    state_args["O"] = "Other org"
    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "present as specified" in res["comment"]
    cert = load_cert(vault_read("pki/issuer/default")["data"]["certificate"])
    assert cert.extensions.get_extension_for_class(cx509.BasicConstraints).value.path_length == 0
    assert (
        cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier).value.digest
        != b"\xca\xfe\xba\xbe"
    )

    # Rotation should replace the default issuer, but reuse its key
    state_args["name"] = "Rotated Remote Intermediate CA"
    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert res["changes"]["cert"]["subject_name"] == {
        "old": "CN=Test Remote Intermediate CA,O=Test Org",
        "new": "CN=Rotated Remote Intermediate CA,O=Test Org",
    }
    new_info = vault_read("pki/issuer/default")["data"]
    assert new_info["issuer_id"] != issuer_info["issuer_id"]
    assert new_info["key_id"] == issuer_info["key_id"]
    assert _subject(load_cert(new_info["certificate"]), "CN") == "Rotated Remote Intermediate CA"


@pytest.fixture
def pki_url_config(clean_pki_mount):  # pylint: disable=unused-argument
    """
    Configure mount default AIA URLs, which are embedded
    into certificates during issuance.
    """
    urls = {
        "issuing_certificates": ["https://ca.example.com/ca.der"],
        "crl_distribution_points": ["https://crl.example.com/crl.pem"],
        "ocsp_servers": ["https://ocsp.example.com"],
    }
    vault_write("pki/config/urls", **urls)
    try:
        yield urls
    finally:
        vault_write(
            "pki/config/urls",
            issuing_certificates="",
            crl_distribution_points="",
            ocsp_servers="",
        )


@pytest.fixture
def vault_ca_setup(pki_url_config, request):
    """
    Import a root CA issuer named `root` on a mount
    with configured default AIA URLs.
    """
    ret = vault_write("pki/config/ca", pem_bundle="\n".join([CA_CERT, CA_KEY]))["data"]
    issuer_id = ret["imported_issuers"][0]
    issuer_config = {"issuer_name": "root"}
    issuer_config.update(getattr(request, "param", {}))
    vault_write(f"pki/issuer/{issuer_id}", **issuer_config)
    if "issuing_certificates" in issuer_config:
        return issuer_config
    return pki_url_config


@pytest.fixture
def pki_role(vault_ca_setup):  # pylint: disable=unused-argument
    role_name = "url-config-denied"
    vault_write(
        f"pki/roles/{role_name}",
        ttl=3600,
        max_ttl=86400,
        allow_any_name=True,
        enforce_hostnames=False,
    )
    try:
        yield role_name
    finally:
        vault_delete(f"pki/roles/{role_name}")


AIA_UNVERIFIED_NOTE = (
    "URL-derived certificate extensions (AIA) were not verified since "
    "the URL configuration of mount `pki` could not be read/rendered"
)


@pytest.fixture
def private_key(tmp_path):
    privkey_path = tmp_path / "priv.key"
    privkey_path.write_text(PRIVKEY)
    return str(privkey_path)


def _assert_embedded_aia(cert, urls):
    aia = cert.extensions.get_extension_for_class(cx509.AuthorityInformationAccess)
    assert urls["issuing_certificates"][0] in {
        str(access.access_location.value) for access in aia.value
    }


def test_intermediate_issuer_managed_url_config_denied(salt_call_cli, vault_ca_setup):
    """
    Ensure a denied URL read access does not cause rotation.
    """
    state_args = {
        "name": "Test URL-blind Intermediate CA",
        "mount": "pki",
        "issuer_ref": "root",
        "key_algo": "ec",
        # Don't reuse the imported root's key for the intermediate.
        "rotate_key": True,
    }

    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert "has been rotated" in res["comment"]
    assert AIA_UNVERIFIED_NOTE not in res["comment"]
    issuer_info = vault_read("pki/issuer/default")["data"]
    cert = load_cert(issuer_info["certificate"])
    assert _subject(cert, "CN") == "Test URL-blind Intermediate CA"
    _assert_embedded_aia(cert, vault_ca_setup)

    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "present as specified" in res["comment"]
    assert AIA_UNVERIFIED_NOTE in res["comment"]
    new_info = vault_read("pki/issuer/default")["data"]
    assert new_info["issuer_id"] == issuer_info["issuer_id"]


def test_root_issuer_managed_url_config_denied(salt_call_cli, pki_url_config):
    """
    Ensure a denied URL read access does not cause rotation.
    """
    state_args = {
        "name": "Test URL-blind Root CA",
        "mount": "pki",
        "key_algo": "ec",
    }

    res = _apply(salt_call_cli, "root_issuer_managed", **state_args)
    assert res["result"] is True
    assert "has been created" in res["comment"]
    assert AIA_UNVERIFIED_NOTE not in res["comment"]
    issuer_info = vault_read("pki/issuer/default")["data"]
    cert = load_cert(issuer_info["certificate"])
    assert _subject(cert, "CN") == "Test URL-blind Root CA"
    _assert_embedded_aia(cert, pki_url_config)

    res = _apply(salt_call_cli, "root_issuer_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "present as specified" in res["comment"]
    assert AIA_UNVERIFIED_NOTE in res["comment"]
    assert vault_read("pki/issuer/default")["data"]["issuer_id"] == issuer_info["issuer_id"]


def test_certificate_managed_url_config_denied(
    salt_call_cli, vault_ca_setup, pki_role, tmp_path, private_key
):
    """
    Ensure a denied URL read access does not cause rotation.
    """
    cert_path = tmp_path / "cert"
    state_args = {
        "name": str(cert_path),
        "common_name": "test.example.com",
        "role_name": pki_role,
        "private_key": private_key,
        "ttl": "30m",
        "ttl_remaining": 0,
    }

    res = _apply(salt_call_cli, "certificate_managed", **state_args)
    assert res["result"] is True
    assert "The certificate has been created" in res["comment"]
    assert AIA_UNVERIFIED_NOTE not in res["comment"]
    cert = load_cert(str(cert_path))
    assert _subject(cert, "CN") == "test.example.com"
    _assert_embedded_aia(cert, vault_ca_setup)

    res = _apply(salt_call_cli, "certificate_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "The certificate is in the correct state" in res["comment"]
    assert AIA_UNVERIFIED_NOTE in res["comment"]
    assert load_cert(str(cert_path)).serial_number == cert.serial_number


def test_ca_certificate_managed_url_config_denied(
    salt_call_cli, vault_ca_setup, tmp_path, private_key
):
    """
    Ensure a denied URL read access does not cause rotation.
    """
    cert_path = tmp_path / "cert"
    state_args = {
        "name": str(cert_path),
        "common_name": "Test URL-blind File CA",
        "private_key": private_key,
        "ttl": "30m",
        "ttl_remaining": 0,
    }

    res = _apply(salt_call_cli, "ca_certificate_managed", **state_args)
    assert res["result"] is True
    assert "The certificate has been created" in res["comment"]
    assert AIA_UNVERIFIED_NOTE not in res["comment"]
    cert = load_cert(str(cert_path))
    assert _subject(cert, "CN") == "Test URL-blind File CA"
    _assert_embedded_aia(cert, vault_ca_setup)

    res = _apply(salt_call_cli, "ca_certificate_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "The certificate is in the correct state" in res["comment"]
    assert AIA_UNVERIFIED_NOTE in res["comment"]
    assert load_cert(str(cert_path)).serial_number == cert.serial_number


@pytest.mark.usefixtures("vault_ca_setup")
@pytest.mark.parametrize(
    "vault_ca_setup",
    (
        {
            "issuing_certificates": ["{{cluster_aia_path}}/ca.der"],
            "crl_distribution_points": ["{{cluster_path}}/crl"],
            "enable_aia_url_templating": True,
        },
    ),
    indirect=True,
)
def test_intermediate_issuer_managed_cluster_config_denied(salt_call_cli, cluster_config):
    """
    Ensure a denied cluster config read access does not cause rotation when the
    (issuer-specific) URL configuration is templated.
    """
    state_args = {
        "name": "Test cluster-blind Intermediate CA",
        "mount": "pki",
        "issuer_ref": "root",
        "key_algo": "ec",
        # Don't reuse the imported root's key for the intermediate.
        "rotate_key": True,
    }

    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert "has been rotated" in res["comment"]
    assert AIA_UNVERIFIED_NOTE not in res["comment"]
    issuer_info = vault_read("pki/issuer/default")["data"]
    cert = load_cert(issuer_info["certificate"])
    assert _subject(cert, "CN") == "Test cluster-blind Intermediate CA"
    _assert_embedded_aia(
        cert,
        {"issuing_certificates": [f"{cluster_config['aia_path']}/ca.der"]},
    )

    res = _apply(salt_call_cli, "intermediate_issuer_managed", **state_args)
    assert res["result"] is True
    assert not res["changes"]
    assert "present as specified" in res["comment"]
    assert AIA_UNVERIFIED_NOTE in res["comment"]
    assert vault_read("pki/issuer/default")["data"]["issuer_id"] == issuer_info["issuer_id"]
