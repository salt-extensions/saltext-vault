import pytest
from cryptography.hazmat.primitives import serialization
from salt.utils.x509 import NAME_ATTRS_OID
from salt.utils.x509 import generate_rsa_privkey
from salt.utils.x509 import load_cert

from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.slow_test,
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.usefixtures("vault_container_version"),
]


@pytest.fixture(scope="module")
def minion_config_overrides(vault_port):
    return {
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "cache": {
                "backend": "disk",
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
        "features": {"x509_v2": True},
    }


@pytest.fixture
def vault_pki(states):
    yield states.vault_pki


@pytest.fixture
def testrole():
    return {"ttl": 3600, "max_ttl": 86400, "allow_any_name": True, "enforce_hostnames": False}


@pytest.fixture
def ca2_cert():
    return """\
-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUGPU16um4LNbOXqUIEI5UjNOmgiUwDQYJKoZIhvcNAQEL
BQAwWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxl
MRIwEAYDVQQKDAlTYWx0U3RhY2sxFjAUBgNVBAMMDVRlc3QgUmVpc3N1ZXIwIBcN
MjQwNzIzMDgwMzM5WhgPMjA1NDA3MjQwODAzMzlaMFgxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTESMBAGA1UECgwJU2FsdFN0YWNr
MRYwFAYDVQQDDA1UZXN0IFJlaXNzdWVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAueJiKvUtqz429f+7AZ9X092L/siLlSukAUxCI+E/Zz37pXvRcQi9
50rsgxdUKG/5epJX46oxxWlW2CyWwXOCWvWr7CNe8wMOrNqi2Et33PNAnyUe9+iX
tfdQ33RCdrrAUVI7IUiM+WXkSqgaFCke7IdFA0FXa6+v1bkgfhwETsxelLrWpM9d
oBOh5mZLIjYjbAlTnKHemNqXYlJvgqtFq6s+KZ4tlX9f1WZkOghORPkAvti7VBFO
0uz0UMETBszlYlPVODw3DYdJrOlq4cjl7wxNnzNilAaRx2p7PiHDlFAROMAgrufq
7RDw/l5pL6vJbPC6+wu/UzWthPZx9mBGRQIDAQABo2MwYTAdBgNVHQ4EFgQUALDS
25ITRPYLJ6itcwFQ1gKprtYwHwYDVR0jBBgwFoAUALDS25ITRPYLJ6itcwFQ1gKp
rtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQEL
BQADggEBAH7TMlojvSQOO04RyayzGddiugElad30226G2RYEE6hUGA/wuRmf3UlV
0FddU+7vaEwaTXJKtjchI/MZ6yFZpNhXRWDnSo1jGIXZSxSXYkAjRI0tIE3Vt/Qs
ySmkDvfb/BtXCCinBr1833DuKF8GAbnLhoR6yHx6HFhYjMjiwgIuldw21D4skpjQ
h9bkSYnj8lsoz8m2JEbXYag+vHaVGHJ6mPFPKQWG1CWko+ONwSdXZO7nVOpk2JJm
vfAVwCW9ly5eg8M+nIBjxoDGxgiVweuxe7kfMhOKvBZJ9UmGTnOkHZR328cBliMd
wUKPgGL2SQ47Iyzegf2FmSv+wgvGUpI=
-----END CERTIFICATE-----
"""


@pytest.fixture
def ca2_key():
    return """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC54mIq9S2rPjb1
/7sBn1fT3Yv+yIuVK6QBTEIj4T9nPfule9FxCL3nSuyDF1Qob/l6klfjqjHFaVbY
LJbBc4Ja9avsI17zAw6s2qLYS3fc80CfJR736Je191DfdEJ2usBRUjshSIz5ZeRK
qBoUKR7sh0UDQVdrr6/VuSB+HAROzF6Uutakz12gE6HmZksiNiNsCVOcod6Y2pdi
Um+Cq0Wrqz4pni2Vf1/VZmQ6CE5E+QC+2LtUEU7S7PRQwRMGzOViU9U4PDcNh0ms
6WrhyOXvDE2fM2KUBpHHans+IcOUUBE4wCCu5+rtEPD+Xmkvq8ls8Lr7C79TNa2E
9nH2YEZFAgMBAAECggEAL720+NN/pzuTYhsMLJ6AMCn2irl3IBjVRoAPfKedYSbK
OvZSFHXqUD0uAX08YCZiLNjpOc+8eLdVVrAdCBJiqHnwbfWnrUJbwolkyaiYYGcZ
ccZW7dUPIe0jGEED0Pql6jz0ctfvXR6OQ55pFER7bMRRNUTS7xVwU7P4ZGtNr+7c
21Tu5X6THIUDy2PjRianENQJZ2GEsPQe4Sh0sieZvrIf1+yN9rpJJRjRj2oTWyBk
RXw37us828XqG3obe9jkDDlSr4+IWCKAIebzRcd++WnuIRIAdE51HBrYEiZYWU+Y
LjmpchAMZdiOLfa1ARehnn8ElyxXPH7iR2AjdO3dAQKBgQDuisAcK7oOeUHJiHoB
c9vYJmavPBjCC1A0gIlFixRu+78GIhkTCwsoLA6hKH4nqNzeztcJixaHdRmuKXPt
HJz13yJw/nQ1pqd0MBZnPwMMaibTbAUbjLwxVGi00zfdzNQfCDDkIMIHQ9GxuXcz
w/977Jb6dC4EEx0e6ZAfZk+LhwKBgQDHfQ4KYA6bowvBusOrWn2fHNPivk0Ql2I8
mKuhSeWAcmtEh9Fsver44zqz2xi1nj41zXGsQxdQgcxe9CJ06WQDY5kS0CKnP0mQ
T3RGHnjhStg40N3zOLTRsBZlXkikkVctmWnjT/NL94d1rfRN4UKmOr5zSr7Zxw9U
G9mA9vsK0wKBgQDg7dqqdZzyaupaw6Lv3bTOg59N22gpCQvvBcjq13NEF4QPn3Vv
XHl/vtNoqUsT0Im8WuOv7wQmZIf7jsDuM43Z1jaev4EK2gOKbpGhd2xDd5D2ySOj
z7fg+AvnfkdukObwAARCCJWMzilb4VuCZ21wCC5xKb3+P5u0+13YDdwx3wKBgF8r
uCEXBqEVviwkj+kV+MyKEkQgid+aeVFzfJ4sBQOskqRVL4JzcMBgl8bqhfVPk1pT
syF9uIe+BORgEHg6SG6de4/QIFguB0iDv3McYosJC/K/IsRAj3NiUKz3uCxa8n5c
rHm30NizNLrdzKnDB+sKJ4YVaMu4/gUgbDnsmoPlAoGAIcb4wu38jH6Ynz31s2l4
bGvNummvXmwlX8EllmuyOh6/0W209o2vAQ+fz3vvhtnyBE9rfZLaQDWN4eb4cDEV
xeM1Z86IbwIf8HQVmxwZMzR/qFPACXxR9uq79Gp4817ZFXRBPBmqp6X1Pa7VbNg0
tClJiP0NZQ8YBJ+vi2VB1iQ=
-----END PRIVATE KEY-----
"""


@pytest.fixture
def ca_cert():
    return """\
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


@pytest.fixture
def ca_key():
    return """\
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


@pytest.fixture
def cert_args(tmp_path, private_key):
    return {
        "name": f"{tmp_path}/cert",
        "common_name": "saltproject.io",
        "role_name": "testrole",
        "private_key": private_key,
        "ttl": "30m",
        "ttl_remaining": 0,
    }


@pytest.fixture(scope="module", autouse=True)
def pki_engine(vault_container_version):  # pylint: disable=unused-argument
    assert vault_enable_secret_engine("pki")
    yield
    assert vault_disable_secret_engine("pki")


@pytest.fixture(scope="module")
def private_key():
    pk = generate_rsa_privkey(2048)
    pk_bytes = pk.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pk_bytes.decode()


@pytest.fixture(params=[["testrole"]])
def roles_setup(request):  # pylint: disable=unused-argument
    try:
        for role_name in request.param:
            role_args = request.getfixturevalue(role_name)
            vault_write(f"pki/roles/{role_name}", **role_args)
            assert role_name in vault_list("pki/roles")
        yield
    finally:
        for role_name in request.param:
            if role_name in vault_list("pki/roles"):
                vault_delete(f"pki/roles/{role_name}")
                assert role_name not in vault_list("pki/roles")


@pytest.fixture
def issuer_setup(ca_cert, ca_key):
    ret_data = vault_write("/pki/config/ca", pem_bundle="\n".join([ca_cert, ca_key]))["data"]
    issuer_id = ret_data["imported_issuers"][0]
    vault_write(f"/pki/issuer/{issuer_id}", issuer_name="root")
    yield issuer_id
    vault_delete(f"/pki/issuer/{issuer_id}")


@pytest.fixture
def issuer_setup_additional(ca2_cert, ca2_key):
    ret_data = vault_write("/pki/config/ca", pem_bundle="\n".join([ca2_cert, ca2_key]))["data"]
    issuer_id = ret_data["imported_issuers"][0]
    vault_write(f"/pki/issuer/{issuer_id}", issuer_name="additional")
    yield issuer_id
    vault_delete(f"/pki/issuer/{issuer_id}")


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_create(vault_pki, cert_args):
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_state_no_changes(vault_pki, cert_args):
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes

    # Try again
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_is_reissued_forcibly(vault_pki, cert_args):
    ret = vault_pki.certificate_managed(**cert_args)
    assert "created" in ret.changes

    cert_args["reissue"] = True
    ret = vault_pki.certificate_managed(**cert_args)
    assert "replaced" in ret.changes


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize("encoding", ["der", "pem"])
def test_certificate_managed_encoding(vault_pki, cert_args, encoding):
    cert_args["encoding"] = encoding
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result

    _, enc, _, _ = load_cert(cert_args["name"], get_encoding=True)

    assert enc == encoding


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_includes_chain(vault_pki, cert_args):
    cert_args["append_ca_chain"] = True
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result

    _, chain = load_cert(cert_args["name"], load_chain=True)

    assert len(chain) == 1


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "attr",
    [
        ({"L": "Boston"}),
        ({"C": "US"}),
        ({"ST": "That Street"}),
        ({"O": "Salt Project"}),
        ({"OU": "Salt Extensions"}),
    ],
)
def test_certificate_managed_sign_verbatim(vault_pki, cert_args, attr):
    cert_args = {**cert_args, **attr}
    cert_args["sign_verbatim"] = True
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result

    cert = load_cert(cert_args["name"])

    for k, v in attr.items():
        c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[k])
        assert len(c_attrs) == 1
        assert c_attrs[0].value == v


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_changed_cn(vault_pki, cert_args):
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes

    cert_args["common_name"] = "brand new common name"
    ret = vault_pki.certificate_managed(**cert_args)
    cert = load_cert(cert_args["name"])

    assert "subject" in ret.changes
    assert "CN" in ret.changes["subject"]

    c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])
    assert c_attrs[0].value == "brand new common name"


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "attr,replace",
    [
        ({"L": "Boston"}, {"L": "Moscow"}),
        ({"C": "US"}, {"C": "RU"}),
        ({"ST": "That Street"}, {"ST": "Other Street"}),
        ({"O": "Salt Project"}, {"O": "Salt"}),
        ({"OU": "Salt Extensions"}, {"OU": "Extensions"}),
    ],
)
def test_certificate_managed_changed_subject(vault_pki, cert_args, attr, replace):
    cert_args["sign_verbatim"] = True
    cert_args = {**cert_args, **attr}
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes

    cert_args = {**cert_args, **replace}
    ret = vault_pki.certificate_managed(**cert_args)
    cert = load_cert(cert_args["name"])

    assert "subject" in ret.changes

    for k, v in replace.items():
        assert k in ret.changes["subject"]
        c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[k])
        assert len(c_attrs) == 1
        assert c_attrs[0].value == v


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("issuer_setup_additional")
@pytest.mark.usefixtures("roles_setup")
def test_certificate_managed_changed_issuer(vault_pki, cert_args):
    cert_args["issuer_ref"] = "root"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes

    cert_args["issuer_ref"] = "additional"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "issuer_name" in ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_role_managed(vault_pki):
    ret = vault_pki.role_managed("dummy")
    assert ret.result
    assert "created" in ret.changes

    ret = vault_pki.role_managed("dummy")
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("issuer_setup_additional")
@pytest.mark.parametrize("issuer_ref", ["additional", "root"])
def test_role_managed_correct_issuer(vault_pki, issuer_ref):
    ret = vault_pki.role_managed("dummy", issuer_ref=issuer_ref)
    assert ret.result

    role_info = vault_read("pki/roles/dummy")["data"]
    assert role_info["issuer_ref"] == issuer_ref


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "params",
    [
        {
            "allow_localhost": False,
            "allow_bare_domains": True,
            "allowed_domains": ["www.example.com", "www.acme.com"],
            "allow_subdomains": True,
            "allow_glob_domains": True,
        },
        {"server_flag": False, "client_flag": False, "no_store": True},
        {"organization": ["Salt"], "country": ["US"], "locality": ["Seattle"], "require_cn": False},
    ],
)
def test_role_managed_payload(vault_pki, params):
    ret = vault_pki.role_managed("testrole", **params)

    role_info = vault_read("pki/roles/testrole")["data"]

    for k, v in params.items():
        assert ret.changes[k]["new"] == v
        assert role_info[k] == v


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "ttl,expected", [(60, 60), ("10m", 600), ("1h", 3600), ("1d", 86400), ("30d", 2592000)]
)
def test_role_managed_ttl(vault_pki, ttl, expected):
    vault_pki.role_managed("testrole", ttl=ttl, max_ttl="365d")

    role_info = vault_read("pki/roles/testrole")["data"]
    assert role_info["ttl"] == expected


@pytest.mark.usefixtures("issuer_setup")
@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "max_ttl,expected", [(60, 60), ("10m", 600), ("1h", 3600), ("1d", 86400), ("30d", 2592000)]
)
def test_role_managed_max_ttl(vault_pki, max_ttl, expected):
    vault_pki.role_managed("testrole", ttl=1, max_ttl=max_ttl)

    role_info = vault_read("pki/roles/testrole")["data"]
    assert role_info["max_ttl"] == expected


@pytest.mark.usefixtures("roles_setup")
def test_role_absent(vault_pki):
    assert "testrole" in vault_list("pki/roles")
    ret = vault_pki.role_absent("testrole")
    assert "deleted" in ret.changes
    assert "testrole" not in vault_list("pki/roles")
