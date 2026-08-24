# pylint: disable=too-many-lines

import ipaddress
from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from salt.utils.x509 import NAME_ATTRS_OID
from salt.utils.x509 import generate_rsa_privkey
from salt.utils.x509 import load_cert

from saltext.vault.utils.vault import helpers as hlp
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts"),
    pytest.mark.parametrize("secret_mounts", ("pki",), indirect=True),
]


@pytest.fixture(scope="module")
def minion_config_overrides(salt_version):
    if salt_version[0] < 3008:
        # Need to enable x509_v2 explicitly on Salt <3008
        return {"features": {"x509_v2": True}}
    return {}


@pytest.fixture
def vault_pki(states):
    try:
        yield states.vault_pki
    finally:
        vault_delete("pki/roles/dummy")


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


@pytest.fixture
def testrole(request):
    defaults = {
        "ttl": 3600,
        "max_ttl": 86400,
        "allow_any_name": True,
        "enforce_hostnames": False,
        "allowed_other_sans": ["*"],
        "allowed_uri_sans": ["*"],
        "allowed_user_ids": ["*"],
        "allowed_serial_numbers": ["*"],
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


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
def ca_sub_key():
    return """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqbHMHARaW7ncu
bcgLhHEyo9wEOh4a82D5B1Y1VH/XJvwBD4Bt59HS46zqYNtXXRbWnWkISL8wvWmC
JEXZ7GmoTL+e8s/h8C1A0vqeThBv0TJyZK93CRD80vG/v+NiLd2SjlPknXibDwFz
wrkZnGLryRqmswvG12ahOYQYWlPCv+BIUxDUL/Pz0z4ZEgoZgArVXMiqXlCfvsPy
Uenx5VLNQZB95K88TMhr/fCbrncddlvDzUPlW4IpLbyfKE9MCCiWnXYqgMr/WzJx
6u6Pf9B4G+2GVCYNEeNFcsbYOgRuZAz5tSrIvIaiWqz0Uy8/+7xRHV/80EO4eUGA
aNJUWRoxAgMBAAECggEAIVNetPZuA+qyzJX0IehuuE/ZlMwGmg+QnXHlVj1lWF3L
tqtg2l0UJ1CVPindinpuHl6erNuI44+Og7/zFtfHm30SlZL2usBcIQqArpcmWK9I
VZ1BwJ25wC7BzlTIMqk0ZFXHqvNuI6guCQSBbLQrld74ArQNb/8sFwfnwFlder33
cEEkxzkz1+tjDVPllJqhDHC4pWHfGiU/NzfLnMKTnlViOYHywYLPKi4T5H4PA/Nd
Lwqnv4AURmBXxi0pYc/7640pZiBuyNfAW6zik4m4hZMPdznpRyLC2VAZMZWLdxry
38a1HHK4ZgQtq7hgS10GtJLqoB/hfFQPVTLdKKg2DwKBgQDqmrFaL7UodukHoTQT
Ob7WmizCCRRjYfljREJMHa7DgLODjVfrBcHWgKV6sB8OFESx+FJA9IW8yOaGwmKJ
m2PlNTeAXt6wfLdX2pq+8Wb4PFmYeqxrAubItYdiQEnVYZOWCpTx+aByHz76F5if
DHXvaeYztyjE7b88e+gIWv1fjwKBgQC591SvojZ57J1yQGUutNese/QqqhFbBJz9
RWCm217ksoqVZYZWxsG+wGH6R0pDjRYxn0wXrrqCLag4TI73qPawUV22C/+m7L2o
mmJ4BXxklmrtYBXd/xdMTOvzvxskClbK1oYmloWGh4LmZFBKq7DTsWXzyidZJz5i
1rwM0A0KPwKBgQCKEs8sgAWDsjBF8EdAxWyeyxBqhoN8Vk47cRH/0DxqDZYZZ5eF
19aUUxSRV5R/achgYgCu//qx+B9M0pzB1jV90cs/fxZbEpupVhxbIqJymLo2doSB
WqzPFZ9/YMzTi+EbnlC49SzL3b3n3PlTKjdC17XHXBXfiPlTNK2ENWEH2wKBgFHE
fmf7WxihAVmLFvJCcdJVbjaUMK1kieKS7rxvGHpWRrkJutfM7MOCs5HoZq7tCiUn
db20Bi3XBXA7uWEL2ewM2reA7xfmYD4SI9nCD7/qo3lcFkFWOFhEOjsifDyMjz0A
tluhM3TDgLrswKEUfNuX1MwsxsBckQHEiUrY7+LhAoGABk3BBSVayHrTCT4xJipk
PIlGdKHjzdnI4adfJEWlGQA5EUv+fiorfeFW0u1yKyiftbCrkwG8z4S5JB3PkBZc
kbVyt+nUh7+gOoNE0ebGJzirkLiFzeulFmQFE3VzwxXuuBm/Zl8ruOiRjftooJx0
A1vWs/C545K2v/LLxc55Cug=
-----END PRIVATE KEY-----
"""


@pytest.fixture
def ca_sub_cert():
    return """\
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUJ8/bURqv1pOka8sHUVqp+C4+FWIwDQYJKoZIhvcNAQEL
BQAwKzELMAkGA1UEBhMCVVMxDTALBgNVBAMMBFRlc3QxDTALBgNVBAoMBFNhbHQw
HhcNMjUwNTA0MTQyMjUxWhcNMzUwNTAyMTQyMjUxWjAuMQswCQYDVQQGEwJVUzEN
MAsGA1UECgwEU2FsdDEQMA4GA1UEAwwHVGVzdFN1YjCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKpscwcBFpbudy5tyAuEcTKj3AQ6HhrzYPkHVjVUf9cm
/AEPgG3n0dLjrOpg21ddFtadaQhIvzC9aYIkRdnsaahMv57yz+HwLUDS+p5OEG/R
MnJkr3cJEPzS8b+/42It3ZKOU+SdeJsPAXPCuRmcYuvJGqazC8bXZqE5hBhaU8K/
4EhTENQv8/PTPhkSChmACtVcyKpeUJ++w/JR6fHlUs1BkH3krzxMyGv98Juudx12
W8PNQ+VbgiktvJ8oT0wIKJaddiqAyv9bMnHq7o9/0Hgb7YZUJg0R40Vyxtg6BG5k
DPm1Ksi8hqJarPRTLz/7vFEdX/zQQ7h5QYBo0lRZGjECAwEAAaNmMGQwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDru5IneLp7q
OrwVwHw6i3deyooOMB8GA1UdIwQYMBaAFFzy8fRTKSOe7kBakqO0Ki71potnMA0G
CSqGSIb3DQEBCwUAA4IBAQBJQJcAMsbKJObyn9uX5JTy/pFptden0c9XXmwdNq53
fY85pWWSN4E5880yWzhVtB60z4hR4V0hI07928rx+zqgYSRvFJD4Sv50ju7QzjtK
cMm0oySqBACJBoQvQjffpnFxsMiPVpbVuEDmDYGrlAkAaXy9O/AMD5D3476QuMsV
4IPOZ65ISOE7yTlYsIXMcEvAej8Rv1uRSScWwoxU7F0XsULMXMfVdW6b0/x/Js2N
UfxmAJVK8gpR1J2uT0LZgZ5QHgGagYtDwiWYyW/w5fSzxCA43KrOg6g4x+y/PBFj
cYpgWHc7NNeYGs6uKgA+IJJalICKGMSJpStncc6SGeKi
-----END CERTIFICATE-----
"""


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
        roles = {}
        for role_name in request.param:
            role_args = request.getfixturevalue(role_name)
            roles[role_name] = role_args
            vault_write(f"pki/roles/{role_name}", **role_args)
            assert role_name in vault_list("pki/roles")
        yield roles
    finally:
        for role_name in request.param:
            if role_name in vault_list("pki/roles"):
                vault_delete(f"pki/roles/{role_name}")
                assert role_name not in vault_list("pki/roles")


def _wipe_issuers():
    vault_delete("pki/root")


@pytest.fixture
def issuer_setup(ca_cert, ca_key, request):
    try:
        ret_data = vault_write("/pki/config/ca", pem_bundle="\n".join([ca_cert, ca_key]))["data"]
        issuer_id = ret_data["imported_issuers"][0]
        issuer_config = {"issuer_name": "root"}
        issuer_config.update(deepcopy(getattr(request, "param", {})))
        vault_write(f"/pki/issuer/{issuer_id}", **issuer_config)
        issuer_config["issuer_id"] = issuer_id
        yield issuer_config
    finally:
        _wipe_issuers()


@pytest.fixture
def issuer_setup_additional(ca2_cert, ca2_key, request):
    ret_data = vault_write("/pki/config/ca", pem_bundle="\n".join([ca2_cert, ca2_key]))["data"]
    issuer_id = ret_data["imported_issuers"][0]
    issuer_config = {"issuer_name": "additional"}
    issuer_config.update(deepcopy(getattr(request, "param", {})))
    vault_write(f"/pki/issuer/{issuer_id}", **issuer_config)
    issuer_config["issuer_id"] = issuer_id
    # No teardown here: This fixture is only used together with issuer_setup,
    # which wipes all issuers and keys on the mount.
    yield issuer_config


@pytest.fixture
def issuer_setup_sub(ca_cert, ca_sub_cert, ca_sub_key, request):
    try:
        ret_data = vault_write(
            "/pki/config/ca", pem_bundle="\n".join([ca_sub_cert, ca_sub_key, ca_cert])
        )["data"]
        issuers = ret_data["mapping"]
        imported_key = ret_data["imported_keys"][0]
        try:
            sub_id = next(x for x in issuers if issuers[x] if issuers[x] == imported_key)
        except StopIteration as err:
            raise AssertionError("Unable to find issuer IDs") from err
        issuer_config = {"issuer_name": "sub"}
        issuer_config.update(deepcopy(getattr(request, "param", {})))
        vault_write(f"/pki/issuer/{sub_id}", **issuer_config)
        issuer_config["issuer_id"] = sub_id
        yield issuer_config
    finally:
        _wipe_issuers()


@pytest.fixture
def aia_urls(request):
    urls = deepcopy(getattr(request, "param", {}))
    vault_write("pki/config/urls", **urls)
    try:
        yield urls
    finally:
        vault_write(
            "pki/config/urls",
            issuing_certificates="",
            ocsp_servers="",
            crl_distribution_points="",
            delta_crl_distribution_points="",
            enable_templating=False,
        )


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_create(vault_pki, cert_args, testmode):
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert ret.changes
    assert "created" in ret.changes
    assert Path(cert_args["name"]).exists() is not testmode


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_state_no_changes(vault_pki, cert_args, testmode):
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert ret.changes
    assert "created" in ret.changes

    # Try again
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes


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
def test_certificate_managed_encoding(vault_pki, cert_args, encoding, testmode):
    cert_args["encoding"] = encoding
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    _, enc, _, _ = load_cert(cert_args["name"], get_encoding=True)
    assert enc == encoding
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_no_create(vault_pki, cert_args, testmode):
    cert_args["create"] = False
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert not Path(cert_args["name"]).exists()


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("follow_symlinks", (False, True))
def test_certificate_managed_symlink(vault_pki, cert_args, tmp_path, follow_symlinks, testmode):
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    link = tmp_path / "cert_link"
    link.symlink_to(cert_args["name"])
    cert_args["name"] = str(link)
    cert_args["follow_symlinks"] = follow_symlinks
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
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
def test_certificate_managed_includes_chain(vault_pki, cert_args, encoding, testmode):
    cert_args["encoding"] = encoding
    cert_args["append_ca_chain"] = True
    cert_args["issuer_ref"] = "sub"

    is_der = encoding == "der"
    if is_der:
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
        assert ret.result is False
        assert "Cannot append the CA chain" in ret.comment
        assert not ret.changes
        return

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    _, enc, chain, _ = load_cert(cert_args["name"], get_encoding=True)
    assert enc == encoding
    assert len(chain) == 1

    # Ensure it's idempotent still
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup")
def test_certificate_managed_missing_role(vault_pki, cert_args, testmode):
    cert_args["role_name"] = "missing-role"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "Role missing-role does not exist" in ret.comment


@pytest.mark.usefixtures("issuer_setup_sub", "roles_setup")
@pytest.mark.parametrize("change", ("ca_chain", "encoding"))
def test_certificate_managed_local_changes_are_recreated(vault_pki, cert_args, change):
    """
    Changes to the encoding or the appended CA chain only should not
    cause a reissuance, but be applied locally to the existing certificate.
    """
    cert_args["issuer_ref"] = "sub"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    serial = load_cert(cert_args["name"]).serial_number

    if change == "ca_chain":
        cert_args["append_ca_chain"] = True
    else:
        cert_args["encoding"] = "pkcs7_pem"
    ret = vault_pki.certificate_managed(**cert_args)
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


@pytest.fixture
def existing_cert(
    vault_pki, cert_args, issuer_setup, roles_setup, aia_urls, request
):  # pylint: disable=unused-argument
    cert_args.update(getattr(request, "param", {}))
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    return load_cert(cert_args["name"]).serial_number


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("existing_cert", ({"mode": "0644"},), indirect=True)
def test_certificate_managed_file_param_changes_only(vault_pki, cert_args, existing_cert, testmode):
    """
    Changes affecting only the managed file (like its mode) should be
    applied via file.managed without recreating the certificate.
    """
    cert_path = Path(cert_args["name"])
    assert oct(cert_path.stat().st_mode)[-4:] == "0644"
    existing_cert = load_cert(cert_args["name"]).serial_number

    cert_args["mode"] = "0600"
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    # the certificate itself should be unchanged
    assert load_cert(cert_args["name"]).serial_number == existing_cert
    assert oct(cert_path.stat().st_mode)[-4:] == ("0644" if testmode else "0600")


def test_certificate_managed_changed_private_key(vault_pki, cert_args, existing_cert):
    """
    A certificate whose public key does not match the specified private
    key anymore should be reissued.
    """
    new_privkey = generate_rsa_privkey(2048)
    cert_args["private_key"] = new_privkey.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "private_key" in ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    assert cert.public_key().public_numbers() == new_privkey.public_key().public_numbers()


@pytest.mark.parametrize("existing_cert", ({"ttl": "10m"},), indirect=True)
def test_certificate_managed_expiry(vault_pki, cert_args, existing_cert):
    """
    A certificate that expires within ``ttl_remaining`` should be reissued.
    """
    cert_args["ttl"] = "30m"
    cert_args["ttl_remaining"] = "15m"
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "expiration" in ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    assert cert.not_valid_after_utc - cert.not_valid_before_utc > timedelta(minutes=15)


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_certificate_managed_existing_file_not_a_cert(vault_pki, cert_args):
    """
    When the target file exists, but does not contain a certificate,
    it should be replaced.
    """
    Path(cert_args["name"]).write_text("banana")
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "replaced" in ret.changes
    assert load_cert(cert_args["name"])


@pytest.mark.parametrize("existing_cert", ({"alt_names": ["dns:foo.bar.baz"]},), indirect=True)
def test_certificate_managed_exclude_cn_from_sans(vault_pki, cert_args, existing_cert):
    """
    By default, the common name is included in the SANs. Ensure setting
    ``exclude_cn_from_sans`` is detected as a change, honored during
    reissuance and idempotent.
    """
    cert = load_cert(cert_args["name"])
    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
    assert cert_args["common_name"] in sans.get_values_for_type(cx509.DNSName)

    cert_args["exclude_cn_from_sans"] = True
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert ret.changes
    cert = load_cert(cert_args["name"])
    assert cert.serial_number != existing_cert
    sans = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName).value
    assert cert_args["common_name"] not in sans.get_values_for_type(cx509.DNSName)

    # Ensure it's idempotent still
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    (
        {"common_name": "foo.bar.baz"},
        {"common_name": "foo@bar.baz"},
        {"common_name": "Neither an email nor a domain"},
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
        {"user_ids": "foo", "serial_number": "foobar"},
        {"user_ids": "foo,bar"},
        {"user_ids": ["bar", "foo"]},
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
def test_certificate_managed_missing_issuer(vault_pki, cert_args, testmode):
    cert_args["issuer_ref"] = "missing-issuer"
    cert_args["append_ca_chain"] = True
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "'missing-issuer' does not exist" in ret.comment


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize("sign_verbatim", (False, True))
def test_certificate_managed_san(vault_pki, cert_args, sign_verbatim):
    """
    Ensure changes to the requested SANs are detected and applied.
    This test is quite complex, when it should not be.
    TODO: Refactor into separate tests.
    """

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
    ret = vault_pki.certificate_managed(**cert_args)
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
    cert_args["subjectAltName"] = ["DNS:this.should.not.matter"]
    cert_args["alt_names"] = init_vals.copy()
    added_vals = init_vals.copy()

    ret = vault_pki.certificate_managed(**cert_args)
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
    ret = vault_pki.certificate_managed(**cert_args)
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

    ret = vault_pki.certificate_managed(**cert_args)
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
        ret = vault_pki.certificate_managed(**cert_args)
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
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
        "added": [],
        "removed": list(sorted(render_other(init_vals))),
    }

    _assert_san(exp)

    # Now swap both sets in one swoop
    cert_args["alt_names"] = list(init_vals)
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert ret.changes["extensions"]["changed"]["subjectAltName"]["value"] == {
        "added": list(sorted(render_other(init_vals))),
        "removed": list(sorted(render_other(change_vals))),
    }
    exp = {k: (v[1], v[0]) for k, v in exp.items()}

    _assert_san(exp)

    remove_vals = cert_args.pop("alt_names")
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert set(ret.changes["extensions"]["removed"]["subjectAltName"]["value"]) == set(
        render_other(remove_vals)
    )
    _assert_san(False)


@pytest.mark.usefixtures("existing_cert", "issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "aia_urls,issuer_setup",
    (
        (
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
        ),
        (
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
        ),
        (
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
        ),
        (
            {
                "issuing_certificates": [
                    "https://one.root-general.ca",
                    "https://two.root-general.ca",
                ],
            },
            {
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
        ),
    ),
    indirect=True,
)
def test_certificate_managed_urls(
    vault_pki, cert_args, testmode, issuer_setup, aia_urls, container
):
    """
    Ensure issuer URLs are added to the certificate as intended. If the issuer has any configured URL,
    the mount default URLs are not applied.
    """
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
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
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)

    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "extensions" in ret.changes
    exp_aia = {
        "added": {"OCSP": ["URI:https://new-ocsp.root.ca"]},
        "removed": {
            "OCSP": ["URI:https://ocsp1.root.ca", "URI:https://ocsp2.root.ca"],
        },
    }

    if issuer_first_configured:
        exp_aia["removed"]["caIssuers"] = ["URI:https://one.root.ca", "URI:https://two.root.ca"]
        # delta_crl_distribution_points requires recent releases, not present in 1.14.8
        assert ("freshestCRL" in ret.changes["extensions"]["removed"]) is ("latest" in container)
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

    if not testmode:
        # One final idempotency check
        ret = vault_pki.certificate_managed(**cert_args, test=testmode)
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


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
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
def test_certificate_managed_sign_verbatim_subject(vault_pki, cert_args, attr):
    cert_args = {**cert_args, **attr}
    cert_args["sign_verbatim"] = True
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes

    cert = load_cert(cert_args["name"])
    for k, v in attr.items():
        c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[k])
        assert len(c_attrs) == 1
        assert c_attrs[0].value == v

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    (
        {"sign_verbatim": True, "user_ids": "foo"},
        {"sign_verbatim": True, "user_ids": "foo,bar", "serial_number": "foobar"},
        {"sign_verbatim": True, "user_ids": ["bar", "foo"]},
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
    ),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_subject_alt_name(vault_pki, cert_args):
    cert: cx509.Certificate = load_cert(cert_args["name"])
    san = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    assert san.critical is False
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
            {"sign_verbatim": True, "keyUsage": ["digitalSignature", "keyAgreement"]}, id="from_csr"
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
def test_certificate_managed_sign_verbatim_explicit_subject_key_identifier(vault_pki, cert_args):
    cert = load_cert(cert_args["name"])
    ski = cert.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier)
    assert ski.value.digest.hex() == "cafebabe"

    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "existing_cert")
@pytest.mark.parametrize(
    "existing_cert",
    ({"sign_verbatim": True, "tlsfeature": "status_request"},),
    indirect=True,
)
def test_certificate_managed_sign_verbatim_other_ext(vault_pki, cert_args):
    cert: cx509.Certificate = load_cert(cert_args["name"])
    tls = cert.extensions.get_extension_for_class(cx509.TLSFeature)
    assert list(tls.value) == [cx509.TLSFeatureType.status_request]

    ret = vault_pki.certificate_managed(**cert_args)
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

    c_attrs = cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])
    assert c_attrs[0].value == (old_cn if testmode else "brand new common name")


@pytest.mark.usefixtures("issuer_setup", "roles_setup", "testrole")
@pytest.mark.parametrize("testrole", ({}, {"use_csr_common_name": False}), indirect=True)
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
        ({"L": "Boston"}, {"L": "Moscow"}),
        ({"C": "US"}, {"C": "RU"}),
        ({"ST": "That Street"}, {"ST": "Other Street"}),
        ({"O": "Salt Project"}, {"O": "Salt"}),
        ({"OU": "Salt Extensions"}, {"OU": "Extensions"}),
        (
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
        ),
    ],
)
def test_certificate_managed_changed_subject(vault_pki, cert_args, attr, replace, testmode):
    cert_args["sign_verbatim"] = True
    cert_args = {**cert_args, **attr}
    ret = vault_pki.certificate_managed(**cert_args)
    assert ret.result
    assert "created" in ret.changes

    cert_args = {**cert_args, **replace}
    ret = vault_pki.certificate_managed(**cert_args, test=testmode)
    assert (ret.result is None) is testmode
    cert = load_cert(cert_args["name"])

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


@pytest.mark.usefixtures("issuer_setup")
def test_role_managed(vault_pki, testmode):
    ret = vault_pki.role_managed("dummy", test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "created" in ret.changes
    assert ("dummy" in vault_list("pki/roles")) is not testmode

    if not testmode:
        ret = vault_pki.role_managed("dummy", test=testmode)
        assert ret.result
        assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "issuer_setup_additional")
@pytest.mark.parametrize("issuer_ref", ["additional", "root"])
def test_role_managed_correct_issuer(vault_pki, issuer_ref, testmode):
    ret = vault_pki.role_managed("dummy", issuer_ref=issuer_ref, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    if testmode:
        assert "dummy" not in vault_list("pki/roles")
        return

    role_info = vault_read("pki/roles/dummy")["data"]
    assert role_info["issuer_ref"] == issuer_ref


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
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
def test_role_managed_payload(vault_pki, params, testmode):
    ret = vault_pki.role_managed("testrole", **params, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode

    role_info = vault_read("pki/roles/testrole")["data"]

    for k, v in params.items():
        assert ret.changes[k]["new"] == v
        assert (role_info[k] == v) is not testmode


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_role_managed_normalized_params_no_changes(vault_pki, testmode):
    """
    Ensure scalar values for list-type parameters and duration strings
    are compared correctly against the normalized values reported by
    Vault instead of causing a rewrite on every run.
    """
    params = {
        "allowed_domains": "www.example.com",
        "ttl": "1h",
        "max_ttl": "30d",
        "not_before_duration": "2m",
    }
    ret = vault_pki.role_managed("testrole", **params)
    assert ret.result is True
    assert ret.changes

    ret = vault_pki.role_managed("testrole", **params, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "ttl,expected", [(60, 60), ("10m", 600), ("1h", 3600), ("1d", 86400), ("30d", 2592000)]
)
def test_role_managed_ttl(vault_pki, ttl, expected, testmode):
    ret = vault_pki.role_managed("testrole", ttl=ttl, max_ttl="365d", test=testmode)
    assert ret.result is not False

    role_info = vault_read("pki/roles/testrole")["data"]
    if testmode:
        # the role's initial ttl as set up by the testrole fixture
        assert role_info["ttl"] == 3600
    else:
        assert role_info["ttl"] == expected


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "max_ttl,expected", [(60, 60), ("10m", 600), ("1h", 3600), ("1d", 86400), ("30d", 2592000)]
)
def test_role_managed_max_ttl(vault_pki, max_ttl, expected, testmode):
    ret = vault_pki.role_managed("testrole", ttl=1, max_ttl=max_ttl, test=testmode)
    assert ret.result is not False

    role_info = vault_read("pki/roles/testrole")["data"]
    if testmode:
        # the role's initial max_ttl as set up by the testrole fixture
        assert role_info["max_ttl"] == 86400
    else:
        assert role_info["max_ttl"] == expected


@pytest.mark.usefixtures("roles_setup")
def test_role_absent(vault_pki, testmode):
    assert "testrole" in vault_list("pki/roles")
    ret = vault_pki.role_absent("testrole", test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "deleted" in ret.changes
    assert ("testrole" in vault_list("pki/roles")) is testmode


def test_role_absent_already_absent(vault_pki, testmode):
    ret = vault_pki.role_absent("missing", test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "already absent" in ret.comment


@pytest.fixture
def clean_pki_mount():
    try:
        yield
    finally:
        _wipe_issuers()


@pytest.fixture
def int_ca_args(ca_cert, ca_key):
    return {
        "name": "Test Intermediate CA",
        "signing_private_key": ca_key,
        "signing_cert": ca_cert,
        "days_valid": 90,
    }


@pytest.fixture
def existing_intermediate(
    vault_pki, int_ca_args, clean_pki_mount, request, container
):  # pylint: disable=unused-argument
    int_ca_args.update(getattr(request, "param", {}))
    if "delta_crl_endpoints" in int_ca_args and (
        "vault" in container and "latest" not in container
    ):
        int_ca_args.pop("delta_crl_endpoints", None)
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    return _default_issuer()


def _default_issuer():
    return vault_read("pki/issuer/default")["data"]


def _subject_cn(cert):
    return cert.subject.get_attributes_for_oid(NAME_ATTRS_OID["CN"])[0].value


@pytest.mark.usefixtures("clean_pki_mount")
def test_intermediate_issuer_managed_create(vault_pki, int_ca_args, testmode):
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "created" in ret.changes
    assert (
        f"Intermediate CA certificate {'would have' if testmode else 'has'} been created"
        in ret.comment
    )
    if testmode:
        assert not vault_list("pki/issuers")
        return
    issuer_info = _default_issuer()
    cert = load_cert(issuer_info["certificate"])
    assert _subject_cn(cert) == int_ca_args["name"]
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 0


@pytest.mark.usefixtures("existing_intermediate")
def test_intermediate_issuer_managed_ok(vault_pki, int_ca_args, testmode):
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "present as specified" in ret.comment


@pytest.mark.usefixtures("existing_intermediate")
def test_intermediate_issuer_managed_issuer_changes(vault_pki, int_ca_args, testmode, container):
    issuer_params = {
        "issuer_name": "my_root_ca",
        "leaf_not_after_behavior": "truncate",
        "usage": ["issuing-certificates"],
        "revocation_signature_algorithm": "SHA384WithRSA",
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
    assert "cert" not in ret.changes

    issuer_changes = ret.changes.get("issuer")
    assert issuer_changes
    assert issuer_changes["issuer_name"] == {"old": "", "new": "my_root_ca"}
    assert issuer_changes["leaf_not_after_behavior"] == {"old": "err", "new": "truncate"}
    assert issuer_changes["usage"] == {"added": [], "removed": ["crl-signing", "ocsp-signing"]}
    assert issuer_changes["revocation_signature_algorithm"]["new"] == "SHA384WithRSA"
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
def test_intermediate_issuer_managed_issuer_ok(vault_pki, int_ca_args, testmode):
    issuer_info = _default_issuer()
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert "Intermediate CA issuer is present as specified" in ret.comment
    assert not ret.changes
    new_info = _default_issuer()
    assert new_info == issuer_info


def test_intermediate_issuer_managed_changes(
    vault_pki, int_ca_args, existing_intermediate, testmode
):
    old_cert = load_cert(existing_intermediate["certificate"])

    int_ca_args["name"] = "Rotated Intermediate CA"
    int_ca_args["max_path_length"] = None
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert ret.changes["cert"]["subject_name"] == "CN=Rotated Intermediate CA"
    assert "basicConstraints" in ret.changes["cert"]["extensions"]["changed"]
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment

    new_info = _default_issuer()
    if testmode:
        assert new_info["issuer_id"] == existing_intermediate["issuer_id"]
        return
    assert new_info["issuer_id"] != existing_intermediate["issuer_id"]
    new_cert = load_cert(new_info["certificate"])
    assert _subject_cn(new_cert) == "Rotated Intermediate CA"
    basic_constraints = new_cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    # This will break soon. IIRC, issuing cert has a pathlen and x509_v2 not accounting for that was fixed
    assert basic_constraints.value.path_length is None
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
    assert ret.changes.get("cert", {}).get("private_key") is True

    new_info = _default_issuer()
    if testmode:
        assert new_info["issuer_id"] == existing_intermediate["issuer_id"]
        assert new_info["key_id"] == existing_intermediate["key_id"]
        return
    assert new_info["issuer_id"] != existing_intermediate["issuer_id"]
    assert new_info["key_id"] != existing_intermediate["key_id"]
    new_cert = load_cert(new_info["certificate"])
    assert new_cert.public_key().public_numbers() != old_cert.public_key().public_numbers()


@pytest.mark.usefixtures("clean_pki_mount")
def test_intermediate_issuer_managed_changes_existing_key(vault_pki, int_ca_args, testmode):
    key_1 = vault_write("pki/keys/generate/internal", key_name="old_key")["data"]
    key_2 = vault_write("pki/keys/generate/internal")["data"]
    int_ca_args["key_ref"] = key_1["key_name"]
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    issuer_info = _default_issuer()
    assert issuer_info["key_id"] == key_1["key_id"]

    # Ensure key_ref is idempotent when specified via name
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == issuer_info

    # Ensure existing issuer key is kept, even if key_ref is removed
    int_ca_args.pop("key_ref")
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == issuer_info

    # Now change the explicit key_ref to a key_id
    int_ca_args["key_ref"] = key_2["key_id"]
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "private_key" in cert_changes
    assert "subjectKeyIdentifier" in cert_changes["extensions"]["changed"]
    new_info = _default_issuer()
    assert (new_info == issuer_info) is testmode
    if testmode:
        return
    assert new_info["key_id"] == key_2["key_id"]

    # And ensure key_ref via key_id is idempotent as well
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == new_info


@pytest.mark.parametrize("existing_intermediate", ({"days_valid": 20},), indirect=True)
def test_intermediate_issuer_managed_changes_expiry(vault_pki, int_ca_args, existing_intermediate):
    int_ca_args["days_valid"] = 90
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "expiration" in ret.changes.get("cert", {})
    assert _default_issuer()["issuer_id"] != existing_intermediate["issuer_id"]


def test_intermediate_issuer_managed_invalid_key_type(vault_pki, int_ca_args, testmode):
    int_ca_args["key_type"] = "banana"
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args, test=testmode)
    assert ret.result is False
    assert not ret.changes
    assert "Invalid value 'banana' for `key_type`" in ret.comment
    assert "Traceback" not in ret.comment


@pytest.fixture
def root_ca_args():
    return {
        "name": "test.root.ca",
        "ou": ["an org unit", "Org Unit 1", "Another Org Unit 2"],
        "organization": "Test Org",
        "country": "US",
        "locality": "Springfield",
        "province": "Utah",
        "street_address": "Test Rd 123",
        "postal_code": "1337",
        "serial_number": "42",
    }


@pytest.fixture
def existing_root(
    vault_pki, root_ca_args, clean_pki_mount, request, aia_urls, container
):  # pylint: disable=unused-argument
    root_ca_args.update(getattr(request, "param", {}))
    if "excluded_alt_names" in root_ca_args or any(
        not val.lower().startswith("dns") for val in root_ca_args.get("permitted_alt_names", [])
    ):
        if "vault" not in container or "latest" not in container:
            root_ca_args.pop("excluded_alt_names", None)
            if "permitted_alt_names" in root_ca_args:
                root_ca_args["permitted_alt_names"] = [
                    val
                    for val in root_ca_args["permitted_alt_names"]
                    if val.lower().startswith("dns")
                ]
    if (
        "delta_crl_endpoints" in root_ca_args
        or "key_usage" in root_ca_args
        and ("vault" in container and "latest" not in container)
    ):
        root_ca_args.pop("delta_crl_endpoints", None)
        root_ca_args.pop("key_usage", None)
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    return _default_issuer()


@pytest.mark.usefixtures("clean_pki_mount")
@pytest.mark.parametrize(
    "testmode,pathlen,aia_urls",
    (
        (False, -1, {}),
        (False, 3, {}),
        (True, -1, {}),
        (
            False,
            -1,
            {
                "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
                "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
            },
        ),
        (
            False,
            -1,
            {
                "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
            },
        ),
        (
            False,
            -1,
            {
                "delta_crl_distribution_points": [
                    "https://deltacrl1.root.ca",
                    "https://deltacrl2.root.ca",
                ],
            },
        ),
        (
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
    assert f"Root CA certificate {'would have' if testmode else 'has'} been created" in ret.comment
    if testmode:
        assert not vault_list("pki/issuers")
        return
    issuer_info = _default_issuer()
    cert = load_cert(issuer_info["certificate"])
    if aia_urls.get("issuing_certificates") or aia_urls.get("ocsp_servers"):
        cert.extensions.get_extension_for_class(cx509.AuthorityInformationAccess)
    if aia_urls.get("crl_distribution_points"):
        cert.extensions.get_extension_for_class(cx509.CRLDistributionPoints)
    if aia_urls.get("delta_crl_distribution_points"):
        if ("vault" in container and "latest" in container) or (
            "openbao" in container and aia_urls.get("crl_distribution_points")
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
    assert "cert" not in ret.changes

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
    if "vault" not in container or "latest" in container:
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
    if "vault" not in container or "latest" in container:
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
        {},
        {
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
    if "vault" not in container or "latest" not in container:
        assert len(nc.value.permitted_subtrees) == 1
        assert nc.value.excluded_subtrees is None
    else:
        assert len(nc.value.permitted_subtrees) == 5
        assert len(nc.value.excluded_subtrees) == 5


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    (
        {
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
def test_root_issuer_managed_changes(vault_pki, root_ca_args, testmode, container):
    root_ca_args = root_ca_args.copy()  # we modify the dict, which is shared
    issuer_info = _default_issuer()
    cert = load_cert(issuer_info["certificate"])
    basic_constraints = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 2
    nc = cert.extensions.get_extension_for_class(cx509.NameConstraints)
    if "vault" not in container or "latest" not in container:
        assert len(nc.value.permitted_subtrees) == 2
        assert nc.value.excluded_subtrees is None
    else:
        assert len(nc.value.permitted_subtrees) == 6
        assert len(nc.value.excluded_subtrees) == 5
    expected_ext_changes = {
        "basicConstraints",
        "subjectAltName",
        "nameConstraints",
        "subjectKeyIdentifier",
    }
    root_ca_args["rotate_key"] = True
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

    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "subject_name" in cert_changes
    assert cert_changes["signature_bits"] == {"old": 384, "new": 512}
    assert cert_changes["private_key"]

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
    assert (changed_exts["subjectKeyIdentifier"]["value"]["new"] == "<TBD>") is testmode
    if "key_usage" in root_ca_args:
        assert changed_exts["keyUsage"]["value"]["digitalSignature"] == {
            "new": False,
            "old": True,
        }

    new_info = _default_issuer()
    assert (new_info == issuer_info) is testmode
    assert (new_info["key_id"] == issuer_info["key_id"]) is testmode
    new_cert = load_cert(new_info["certificate"])
    if testmode:
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
    if "vault" not in container or "latest" not in container:
        assert len(nc.value.permitted_subtrees) == 1
        assert nc.value.excluded_subtrees is None
    else:
        assert len(nc.value.permitted_subtrees) == 5
        assert len(nc.value.excluded_subtrees) == 4


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    ({"days_valid": 100},),
    indirect=True,
)
def test_root_issuer_managed_changes_expiry(vault_pki, root_ca_args, testmode):
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
    old_year = int(cert_changes["expiration"]["old"].split("-", maxsplit=1)[0])
    new_year = int(cert_changes["expiration"]["new"].split("-", maxsplit=1)[0])
    assert new_year > old_year
    assert (_default_issuer() == issuer_info) is testmode


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "existing_root",
    ({"days_valid": 100},),
    indirect=True,
)
def test_root_issuer_managed_changes_not_after(vault_pki, root_ca_args, testmode):
    """
    Ensure an explicit not_after is always respected.
    """
    issuer_info = _default_issuer()
    root_ca_args["days_remaining"] = 1
    not_after = (datetime.now(tz=timezone.utc) + timedelta(days=1000)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    root_ca_args["not_after"] = not_after
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "expiration" in cert_changes
    old_year = int(cert_changes["expiration"]["old"].split("-", maxsplit=1)[0])
    new_year = int(cert_changes["expiration"]["new"].split("-", maxsplit=1)[0])
    assert new_year > old_year
    assert cert_changes["expiration"]["new"] == not_after
    assert (_default_issuer() == issuer_info) is testmode


@pytest.mark.usefixtures("clean_pki_mount")
def test_root_issuer_managed_changes_existing_key(vault_pki, root_ca_args, testmode):
    key_1 = vault_write("pki/keys/generate/internal", key_name="old_key")["data"]
    key_2 = vault_write("pki/keys/generate/internal")["data"]
    root_ca_args["key_ref"] = key_1["key_name"]
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

    # Ensure existing issuer key is kept, even if key_ref is removed
    root_ca_args.pop("key_ref")
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == issuer_info

    # Now change the explicit key_ref to a key_id
    root_ca_args["key_ref"] = key_2["key_id"]
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert f"CA certificate {'would have' if testmode else 'has'} been rotated" in ret.comment
    assert ret.changes
    cert_changes = ret.changes.get("cert")
    assert cert_changes
    assert "private_key" in cert_changes
    assert "subjectKeyIdentifier" in cert_changes["extensions"]["changed"]
    assert (
        cert_changes["extensions"]["changed"]["subjectKeyIdentifier"]["value"]["new"] == "<TBD>"
    ) is testmode
    new_info = _default_issuer()
    assert (new_info == issuer_info) is testmode
    if testmode:
        return
    assert new_info["key_id"] == key_2["key_id"]

    # And ensure key_ref via key_id is idempotent as well
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert _default_issuer() == new_info


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "aia_urls",
    (
        {},
        {
            "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
            "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
        },
        {
            "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
        },
        {
            "delta_crl_distribution_points": [
                "https://deltacrl1.root.ca",
                "https://deltacrl2.root.ca",
            ],
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
    ),
    indirect=True,
)
def test_root_issuer_managed_ok_aia(vault_pki, root_ca_args, testmode):
    issuer_info = _default_issuer()
    ret = vault_pki.root_issuer_managed(**root_ca_args, test=testmode)
    assert ret.result is True
    assert "Root CA issuer is present as specified" in ret.comment
    assert not ret.changes
    new_info = _default_issuer()
    assert new_info == issuer_info


@pytest.mark.usefixtures("existing_root")
@pytest.mark.parametrize(
    "aia_urls",
    (
        {},
        {
            "issuing_certificates": ["https://one.root.ca", "https://two.root.ca"],
            "ocsp_servers": ["https://ocsp1.root.ca", "https://ocsp2.root.ca"],
        },
        {
            "crl_distribution_points": ["https://crl1.root.ca", "https://crl2.root.ca"],
        },
        {
            "crl_distribution_points": [
                "https://crl1.root.ca",
                "https://crl2.root.ca",
            ],  # required on OpenBao
            "delta_crl_distribution_points": [
                "https://deltacrl1.root.ca",
                "https://deltacrl2.root.ca",
            ],
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
    ),
    indirect=True,
)
def test_root_issuer_managed_changes_aia(vault_pki, root_ca_args, testmode, aia_urls, container):
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
        if "vault" in container and "latest" not in container:
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
        if "vault" in container and "latest" not in container:
            pytest.skip("delta_crl_distribution_points requires Vault 2.0+ or OpenBao")
        elif "openbao" in container and "crl_distribution_points" not in aia_urls:
            pytest.skip("delta_crl_distribution_points requires crl_distribution_points on OpenBao")
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
