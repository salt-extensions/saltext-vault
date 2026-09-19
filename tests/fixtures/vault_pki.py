"""
Shared fixtures for the vault_pki test suites.

Import the required fixtures - including their fixture dependencies,
which are resolved by name in the importing scope - into the suite's
conftest.py or test module.
"""

from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from salt.utils.x509 import generate_rsa_privkey
from saltfactories.utils import random_string

from tests.helpers.vault_pki import DEFAULT_CLUSTER_AIA_PATH
from tests.helpers.vault_pki import DEFAULT_CLUSTER_PATH
from tests.helpers.vault_pki import _import_configured_issuer
from tests.helpers.vault_pki import _read_denied
from tests.helpers.vault_pki import _wipe_issuers
from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_list
from tests.support.vault import vault_write


@pytest.fixture
def ca2_cert():
    """
    This hardcoded certificate expires Jul 24 08:03:39 2054 GMT.
    I'm not certain whether this project will see the day where
    it needs to be rotated. oO
    """
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
    """
    This hardcoded certificate expires 2036-08-23 15:46:53 GMT.
    Please regenerate in time and remember we need leeway. :)
    """
    return """\
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIUQJgxgogKKjEPk+XPj9QLMvDSAUAwDQYJKoZIhvcNAQEL
BQAwKzELMAkGA1UEBhMCVVMxDTALBgNVBAoMBFNhbHQxDTALBgNVBAMMBFRlc3Qw
HhcNMjYwODI2MTU0NjUzWhcNMzYwODIzMTU0NjUzWjArMQswCQYDVQQGEwJVUzEN
MAsGA1UECgwEU2FsdDENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAI4J6LlZiujOIyg7k3cGTkXHULH8gsOmIRvtpMpecgLF87mm
Bh8O44W8mbYJ68zos/IK+Ztaz9ltiB8jFeJ7jy1uCKEiW4avMSVlxN7airHsNK/y
fFdTCb2G+j3k8USrbltAmXCmndkWE8pdM9hLzL0Ti+az7TC5Ls61mJPbSWvfMqlV
jXT8krjEEw3F2RRPj7Mg0gSrBN9b08u/w6GQEwXaK5MKGbyjiitWpjbtrrKU5baG
In9CLH5hSRFwYDOEI1qClSmAwZcsHj6g5W7o9+cG55u8RjtkRF7Ee1AIRiEcH9ZI
1WLEIh3MdP0HZcHEulwsQzuG+27hiG5nbXDyCYsCAwEAAaNmMGQwEgYDVR0TAQH/
BAgwBgEB/wIBAzAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFVAaieIyOMr672d
ynDMNOZT80PWMB8GA1UdIwQYMBaAFFVAaieIyOMr672dynDMNOZT80PWMA0GCSqG
SIb3DQEBCwUAA4IBAQBYc0yJaffxH56HrEITQeojsM5eDsngp4gU9bCxdghoKCsu
KrZoDy6k+XrDDeqwFn5i3LrptcwO6raU1r2fAaWC4CGF3AD2V8eD3IM8bxULyULJ
lSIffDVnus86U1WhCKTOb+nbBz/ykcvYycQfkBGxgh3a/yHylqHpCxHoPs/KbhUm
UeMxPnobR/Yukd5/R1KW6hN80hc0+MRsc//M//8OQ4Ws8grTSI/wK3UbH39Kr9W6
kLkpn/PbZsWP4IRN2HjR+EWnC+4ZeuQF0YvbceDHdUYsDBqZH8QfviUwKU779Mrx
6jgz75V8jaGr6B9h5zcSh+aSW3KQ0f0L+GJih/mh
-----END CERTIFICATE-----
"""


@pytest.fixture
def ca_key():
    return """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCOCei5WYroziMo
O5N3Bk5Fx1Cx/ILDpiEb7aTKXnICxfO5pgYfDuOFvJm2CevM6LPyCvmbWs/ZbYgf
IxXie48tbgihIluGrzElZcTe2oqx7DSv8nxXUwm9hvo95PFEq25bQJlwpp3ZFhPK
XTPYS8y9E4vms+0wuS7OtZiT20lr3zKpVY10/JK4xBMNxdkUT4+zINIEqwTfW9PL
v8OhkBMF2iuTChm8o4orVqY27a6ylOW2hiJ/Qix+YUkRcGAzhCNagpUpgMGXLB4+
oOVu6PfnBuebvEY7ZERexHtQCEYhHB/WSNVixCIdzHT9B2XBxLpcLEM7hvtu4Yhu
Z21w8gmLAgMBAAECggEALoGME3QACW3FER1AkU4dPred8kjtP8YbPRu4QxJdXg8W
WAjGJFEpqdYwtevVqwfeMzfotjcrqtM0KI3CUp+GJ6fJZ4jqUtT10Hrb1OPVWaAv
OBS7JZRosgeJ084sOQGwZmxmUP4c3MFfxXhyyzU2WgoWWnk7BiL78m5/AJpiFdFH
qnizBtoBdLkfUMMDxMTvNSHQlAdPgC93l5MFdAoNRTIyCYk5srhBOVOQ4xrJL56C
g7dJ317A26RMGEV0fSBqMjmyz7eOiE9fUfMyrKymzxFD1sNzGr8+t3X6prFHgzhu
SxIcvAn5F3Nsw7BxHGqQE7CsRAC0IxhUSDjLoTK3wQKBgQDIrJpwtHgGz/ZuBvfj
1gzCbXp+FZ20FkB/q1yGw9Gt4nkWDkxfg8N6Q9gWT3kbUCmM8dsm4M9HO6b8Mv//
OFTwH8LjErEKnudr7dm+hjdJd2/zudsOTdSPQJXq5d0m2kUDPW508/CKLdBI1P1k
XKthM3vjw+VmJf548KKRdD7JMQKBgQC1Mt29bzZmRcfxBhvPBWqsUeDEDnQvH9QP
TNs+f/pE+65/Mz4CzoFiUtuFNOMF1rgm/g4Ojm5PxP4deZwO9yo+xTaCR43bSYPD
sbGAxPV/0NIRfjLlDtGd5KVRGskBTUiG2qfXo3RaPas8ITNYpIxTkpK9Fo4KJ/pI
xiAOYXWPewKBgF4TrQORV4O6EwlZ8vS48JplwLtDXv+CPxKbP3Fec/pU5fdVFLDi
kM3M6IztDRWk6xXMfLUpR4NZj9tD/Yek3Q0FltPle2JDRLLwetg7C8hBWhak1vFJ
w5C08pOA18DTKu9t6U6i3e2ptK+wSmq2lxGmlToeKHlO7pG8HjqaiKTBAoGAB0CM
7WsJE1jRoszqygNefJ0eUNp/Pe+ZLi+WSs8WdjJYjpC/d59KQGQukwtF1tL8NdtP
NrfupFSvEwDuBQ9Raoe8IcS5YcB0fJ2dDBlV9hKmhbq2UMKiEx62myNmTh4IvBT+
SLwrCP2U3+g4ROD5GNMx+k1vy+pDsyvy1oCCEwcCgYEAmV7Pofi1LX2FGEl4XVh3
mRSBkQWVAhy+64mHIVYtlmPGdoX9g/jpLqFOSmTJU4ay8aDSoVm1OYQ7E4s4q+75
qBLJJ/qz3r23VjMoEP3vgFwVR5sn3HScacnKL06zwfEjhpfk/4aCIEV3qxYvVW+7
pUE+01oL9IcXo04uEPvJekc=
-----END PRIVATE KEY-----
"""


@pytest.fixture
def ca_sub_cert():
    """
    This hardcoded certificate expires Aug 23 15:53:27 2036 GMT.
    Please regenerate in time. :)
    """
    return """\
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUAyLX8kCZwSl74iK/rbMwUeLo+MMwDQYJKoZIhvcNAQEL
BQAwKzELMAkGA1UEBhMCVVMxDTALBgNVBAoMBFNhbHQxDTALBgNVBAMMBFRlc3Qw
HhcNMjYwODI2MTU1MzI3WhcNMzYwODIzMTU1MzI3WjAuMQswCQYDVQQGEwJVUzEN
MAsGA1UECgwEU2FsdDEQMA4GA1UEAwwHVGVzdFN1YjCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKh5GjzqPb8gzC1Xx7zj/TDWBZzYjQreovzwuYdSXSPo
E4cn6AMZGoyZBrhKeMZimxOrS8Y5l3OiG158WC+8CHAzVkd4dU4cGFdIhyjpkbGz
YGMJ7ylYqq0g7GlLEsxdLNamtDMb+axtedlmPNTmmzATeJNNkYJcseCOUE1yOWgH
krSTIsl87XL+cAfZxBtAhsL29vIqFv0UFGXBFHmNt0fHbfAEoidJ+R4yFdsg9rig
q7gDjSYbuJ9SLfHjoMTF5cZeGDliYMOXy9GaJyu3WDpJZU5Dt/UKzQtmrNsfINYl
FzAWED99EDo4PsCC82cg0c1eFkw/tMy7hUX4AM212f0CAwEAAaNmMGQwEgYDVR0T
AQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMj6WOA8feXl
gS2/ux8UEjSwxL2HMB8GA1UdIwQYMBaAFFVAaieIyOMr672dynDMNOZT80PWMA0G
CSqGSIb3DQEBCwUAA4IBAQBGN10GoJuA60VwIsOQrrd5Y/TmZMj0Lr/cBORYMqT2
WllXuB207ckLALvnY3wteNawCH1cYH/uwmb+HO6CYfUY9uqkts/ljrfoUvulkNfJ
JpH2w0HvmdeuPmmi4gjBzBMWIq36v7QueGNc+c+7oFkiyM4aFW1zb9kbeVRiGu9/
JmyF9aG+94bwmn/OWgQOu5u44R+se+ZmICwKhXMTgLPf8IkRfnWZfaYlLeTaqtPl
5prqXLjPKtBrVf+Jyj+5jppQ0bncyhHtiZJ8J8irsL/P0BZ3Bqb+yMCht1LE8U8E
wZitSD0qHEKg8bHsGGLdvGFjXOs4XN5ssKQaJTAk2fKi
-----END CERTIFICATE-----
"""


@pytest.fixture
def ca_sub_key():
    return """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoeRo86j2/IMwt
V8e84/0w1gWc2I0K3qL88LmHUl0j6BOHJ+gDGRqMmQa4SnjGYpsTq0vGOZdzohte
fFgvvAhwM1ZHeHVOHBhXSIco6ZGxs2BjCe8pWKqtIOxpSxLMXSzWprQzG/msbXnZ
ZjzU5pswE3iTTZGCXLHgjlBNcjloB5K0kyLJfO1y/nAH2cQbQIbC9vbyKhb9FBRl
wRR5jbdHx23wBKInSfkeMhXbIPa4oKu4A40mG7ifUi3x46DExeXGXhg5YmDDl8vR
micrt1g6SWVOQ7f1Cs0LZqzbHyDWJRcwFhA/fRA6OD7AgvNnINHNXhZMP7TMu4VF
+ADNtdn9AgMBAAECggEAAxn7pCxxx498gscva6hM1HXUM59+9TjFCmAKIlYfVdZj
aaUP7eKr7POyPnlMgOZ20WVhZzxPL/dHhrVGUFanVx1y1K0Ah9gXkJ/KsTOflYRm
XVxk9T9nIPnOsF+L8Iw0k50NCzXUIlr/l8N8kjTOnZN2MEwIxjwboDUugEZ+jQ4y
9L+vEuTVdIN4mPvYKhs7BosOd2gUccLc2/CtgprgenE1CQ8qXDERbgrO/KvQvqk5
6Tdl0/Tmlj6euS1P1pT5WAm4sOpTmm9tQo0/Tnkjp2uA/bvIMCdPcSx7lowZQL/s
leM+NakIyZAD3mfk0R++YfVlH17ktu6fdCSzEAJcZwKBgQDj5Tol0SI41AxxlixT
+ynBYF8Ww2qnDK9O0DqUHxqVl7fxZcTYIMS3cb/HCryReUL+FIpendmcuovllzwA
g4xIVtSFD+dqRROMgPtVCYBPu4BpqqpUikZQyUah7/FjNLcdW/fotAIZ1eJFsy4z
qtxZV5l5NA84KmFzrjE8nMqH3wKBgQC9P+GsHI0hnBixpJ0sqUnF9q4nKn6KY8Gu
0O3YdK2tPLL6oHxigo6sRc4SPWP9LR/PtM6TkA9+bBqh8FfXcfYM1GrCczXknX00
LghplhQ1QOZjqjmamTx0hFevdgNz0p5jiUDTbzVFaPCQP/zAXkHRHCrefzOLoVNN
lZ9Bp1WJowKBgCWX+8afQDD1sfPO3RMhfJrcxfLgW6ig7A5pRTCIDP+eXoagzh8F
EM5eIk+4UrEAuu9k/gprqak0EL3X+9rt2Gdag4ZLwFYEfRwRbuRxQ8xjVuSXda+q
e7z55v/xr/U4jfh24mdtwmb2pHPxAe8eAWlvjO60isouG5NUqeSgzLwrAoGAPly6
pNiTuSuTB5bTJFB0uwNayBU8taXBwTWf6uAoCxohcG1KD7wt/57RFTmdpWQlQ3C1
UfL66BH/hLWKfLhU+E1XENSeQcOT6onww7ps1k+Ym+cQLF2qikrCClO9N4GEKBCm
iAXxa/n0q9QqGcn1rk614bPQ7IYwyTQw0pWtnjkCgYEAgZbGQStSxR1MwHG8Y8A9
rNcQTv2PTvd19O1iEAxJHzQNZOciqgbNvAXxuChNSnOikrtjqbl9v99WnjqOE1TQ
oYMtPj6yNSeTRJgROi2kF4kjgnCeiLe2FhFFQqP6o5oAjrFRCDEgVTDkSzWOQgX/
/xuWR2NlXTxYrdB56Lgi4xM=
-----END PRIVATE KEY-----
"""


@pytest.fixture
def ca_cert_no_pathlen():
    """
    This hardcoded certificate expires Aug 24 21:46:46 2036 GMT.
    Please regenerate in time. :)
    """
    return """\
-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIUKm99KrqdfPb1J4sQe+SorjMC+LYwDQYJKoZIhvcNAQEL
BQAwJzElMCMGA1UEAwwcU2FsdCBUZXN0IFJvb3QgVW5jb25zdHJhaW5lZDAeFw0y
NjA4MjYyMTQ2NDZaFw0zNjA4MjQyMTQ2NDZaMCcxJTAjBgNVBAMMHFNhbHQgVGVz
dCBSb290IFVuY29uc3RyYWluZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDkK41XGREvMVzKkkZAW+fpVmfSyg7UntvKzXecfu++8fwCEVKAJG4icfhc
9AVdaZIKvHPRxdUWJY1tHe13tJYerqn/Vbf/vh1XwmxvcYut0nKE1sLN+1x42ihN
9Fl36tudmrTAGAn4sX4Qnqivu8r14Lz4g4XyEXK35zCeX6tBnzI444JNq2CDYyqB
5peAAVFO7YWdpQYqnJ9YJL6VlUQ0FYBNNqaAn95RHZ2H1+nkBwE/zSyNXcg0q4S+
O1LQh+S1s5FAUcjCwsW0Q7wS6zhApM+yRYa2MNl72MXd+3ViPpOXL5Xw9k4qNO+G
sqveQFSZ6dydcMMM0ggBKQNeBtE9AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8w
DgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTnoHneVRD2W/AFwtadSawyQGElDzAN
BgkqhkiG9w0BAQsFAAOCAQEAfsiwbppfrFjev4JH8P/Jy68+ZWSfQ/JNaqTxhzIm
43vF/MzHXt9IDJLsXfi3D/ZTYq1u7+vGDKXaoh8KG8oVL4/Lc4iihu2EAei8uUwF
Bna+MHet/PwXTAt5k21LlQvoyU9/kZyY5e5NdNJ9ULDhCoKxvNhXYZbH9mO6VYuA
uOKd0pAvlAfA+EpOYkDYw3AhWch9QFXvByGfxgONj1zY4qQCPV3BxqonOQAU957p
qU04BK9da2gtGyUzlABXK1jrO2csYRl4FK6xZS0+NszPh+8y2gy6jat8OofbGjmb
nd+qcrHZSuAiKK/WR5uZurNC25yHwvP0othH96QFVYw01w==
-----END CERTIFICATE-----
"""


@pytest.fixture
def ca_key_no_pathlen():
    return """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkK41XGREvMVzK
kkZAW+fpVmfSyg7UntvKzXecfu++8fwCEVKAJG4icfhc9AVdaZIKvHPRxdUWJY1t
He13tJYerqn/Vbf/vh1XwmxvcYut0nKE1sLN+1x42ihN9Fl36tudmrTAGAn4sX4Q
nqivu8r14Lz4g4XyEXK35zCeX6tBnzI444JNq2CDYyqB5peAAVFO7YWdpQYqnJ9Y
JL6VlUQ0FYBNNqaAn95RHZ2H1+nkBwE/zSyNXcg0q4S+O1LQh+S1s5FAUcjCwsW0
Q7wS6zhApM+yRYa2MNl72MXd+3ViPpOXL5Xw9k4qNO+GsqveQFSZ6dydcMMM0ggB
KQNeBtE9AgMBAAECggEAARAP3jg8a4EaGspwH9Qdwik4HhP5WjWsNedbl4PC15uW
bicJAJZK2ge4Xax4Su1XNAwZKQC4I5yEql2xkbVqXpW3LnyGeR84UUSTTziS6zoX
9PTwHtf9IAX6GpTZBtU19Se3kE58W2duPCMVC45/HUKQ9sJcERrSMzeVMyOkb0+N
grJTNeBIm2YiUF21sfkUSW01p0OIvsD4aMoiOAZRLkuRYdyVyj9KBNEne0J8gCwg
9DWuhJoPrtlDMp4GuQjlts9EcDyaqputWY6jWh8MsfO8yzdUPN2gC815CG1WV/cl
i7CAP4+ZGe/INnvWdSkr7yDJUmIsEzk2ag291xsuSQKBgQDz288CxSC0XIIMSCDW
/ETWjwHcqqm653fQIaaRFAF4ewD0c7dj639bo6YFMfsDReHHxbJXU3ueXAihzVme
xWMhGtPn5FN7vd/V74shZYgtL/ZpgftitbtP8Z4oP+PW9EXoK6f/gFQ2q9z4xezy
bpuBLIZGex0Gl6EC+HH3xyNRiQKBgQDvh8ehHuA6x7MF55ByKBes2sK1V3aRrXj1
J1xqLQ1wNxbp1pbTLojo55vTiGtBD0FsWemUnxW2L+b9CkXY5KygoIzYh8cH3I1t
yi64psKYKvIfx8YXQjLwIFUr2pWcFD5E0m+HStAU8s4W0YDLQj96fO3MFcCWLT69
8bseKuTZFQKBgQCqQUEasf7PbfbuFD25W4/ELTwjkJPIBmtESPo+ODV+pIJaKaBU
hsr4dB0pa2fRNS0ZiRGmnoakXaU5MmHr0+wN5Okl8efHcR2iBAijXHvi8KWdrD6T
AEay3gKKH3E3VnyoSDKW1EX3la5FkgqIiGjRmwB0nOf6/kpQBJ2tXL9v4QKBgBlH
5mz9+kKZ8y4rW5aA3sbSq/xBx/TmLz8IsXtPV/zBA70YdgDCB5c1Yr/3xQIv3wLV
lo6mH7+D3MhWPjr/H60wZM0xv3L390FgNoAssZsn5TgveJvZ09B+SR8AyguYI15W
K4lG/yFG4zOLVyGc02BVMS/6F8KB8f5QNiSf+FllAoGAafyS/xgOhqkSA4at1p4L
DtqgCaeQgnUVYPV07RA+NgL91cnylJAFbnvDgHJJIZc4PuViLMZocC8JsatKRxeI
U7Ur/g1Y3WmlWo15fojD2b8cdZ2nz+pTVdh5KzKQPgmMEGZsakHadQTNfdKueojL
ooRkBy+9MR64RNyZ+gri1OA=
-----END PRIVATE KEY-----
"""


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


@pytest.fixture
def issuer_setup(ca_cert, ca_key, request):
    try:
        issuer_config = {"issuer_name": "root"}
        issuer_config.update(deepcopy(getattr(request, "param", {})))
        issuer_config["issuer_id"] = _import_configured_issuer(ca_cert, ca_key, issuer_config)
        yield issuer_config
    finally:
        _wipe_issuers()


@pytest.fixture
def issuer_setup_additional(ca2_cert, ca2_key, request):
    issuer_config = {"issuer_name": "additional"}
    issuer_config.update(deepcopy(getattr(request, "param", {})))
    issuer_config["issuer_id"] = _import_configured_issuer(ca2_cert, ca2_key, issuer_config)
    # No teardown here: This fixture is only used together with issuer_setup,
    # which wipes all issuers and keys on the mount.
    yield issuer_config


@pytest.fixture
def issuer_setup_sub(ca_cert, ca_sub_cert, ca_sub_key, request):
    try:
        issuer_config = {"issuer_name": "sub"}
        issuer_config.update(deepcopy(getattr(request, "param", {})))
        issuer_config["issuer_id"] = _import_configured_issuer(
            [ca_sub_cert, ca_cert], ca_sub_key, issuer_config
        )
        yield issuer_config
    finally:
        _wipe_issuers()


@pytest.fixture
def issuer_setup_no_pathlen(ca_cert_no_pathlen, ca_key_no_pathlen, request):
    try:
        issuer_config = {"issuer_name": "root"}
        issuer_config.update(deepcopy(getattr(request, "param", {})))
        issuer_config["issuer_id"] = _import_configured_issuer(
            ca_cert_no_pathlen, ca_key_no_pathlen, issuer_config
        )
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


@pytest.fixture(scope="module", autouse=True)
def cluster_config(secret_mounts):  # pylint: disable=unused-argument
    # Can't reset these once they have been set on a mount,
    # so just set them once.
    vault_write(  # pylint: disable=kwarg-superseded-by-positional-arg
        "pki/config/cluster",
        path=DEFAULT_CLUSTER_PATH,
        aia_path=DEFAULT_CLUSTER_AIA_PATH,
    )


@pytest.fixture
def role_read_denied():
    with _read_denied("pki/roles/"):
        yield


@pytest.fixture
def url_config_read_denied():
    with _read_denied("pki/config/urls", "pki/config/cluster"):
        yield


@pytest.fixture
def clean_pki_mount():
    try:
        yield
    finally:
        _wipe_issuers()


@pytest.fixture
def fresh_pki_mount():
    name = random_string("fresh-mount", uppercase=False)
    vault_enable_secret_engine("pki", name)
    try:
        yield name
    finally:
        vault_disable_secret_engine(name)
