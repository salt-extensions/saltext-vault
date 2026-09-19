"""
Shared fixtures for the vault_gpg test suites.
"""

import pytest


@pytest.fixture(scope="class")
def key_a_fp():
    return "EF03765F59EE904930C8A781553A82A058C0C795"


@pytest.fixture(scope="class")
def key_a_pub():
    return """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EY4fxHQEEAJvXEaaw+o/yZCwMOJbt5FQHbVMMDX/0YI8UdzsE5YCC4iKnoC3x
FwFdkevKj3qp+45iBGLLnalfXIcVGXJGACB+tPHgsfHaXSDQPSfmX6jbZ6pHosSm
v1tTixY+NTJzGL7hDLz2sAXTbYmTbXeE9ifWWk6NcIwZivUbhNRBM+KxABEBAAG0
LUtleSBBIChHZW5lcmF0ZWQgYnkgU2FsdFN0YWNrKSA8a2V5YUBleGFtcGxlPojR
BBMBCAA7FiEE7wN2X1nukEkwyKeBVTqCoFjAx5UFAmOH8R0CGy8FCwkIBwICIgIG
FQoJCAsCBBYCAwECHgcCF4AACgkQVTqCoFjAx5XURAQAguOwI+49lG0Kby+Bsyv3
of3GgxvhS1Qa7+ysj088az5GVt0pqVe3SbRVvn/jyC6yZvWuv94KdL3R7hCeEz2/
JakCRJ4wxEsdeASE8t9H/oTqD0I5asMa9EMvn5ICEGeLsTeQb7OYYihTQj7HJLG6
pDEmK8EhJDvV/9o0lnhm/9w=
=Wc0O
-----END PGP PUBLIC KEY BLOCK-----"""


@pytest.fixture(scope="class")
def key_a_priv():
    return """\
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHYBGOH8R0BBACb1xGmsPqP8mQsDDiW7eRUB21TDA1/9GCPFHc7BOWAguIip6At
8RcBXZHryo96qfuOYgRiy52pX1yHFRlyRgAgfrTx4LHx2l0g0D0n5l+o22eqR6LE
pr9bU4sWPjUycxi+4Qy89rAF022Jk213hPYn1lpOjXCMGYr1G4TUQTPisQARAQAB
AAP7BlQ9nKcZI/24hQPxi+qpMGL1VQ87IKBWiBURExHrtrSKFdV4N0lwcV8hGSIK
wfTzmRigvDjwBCQR9E/+brJKWLdGmmHjYHIU3m4fz26E4UlxEu2XfxZOSPKPTnzh
GqVSjmZ9TDdr5Ykpz5SyQ1YOUS9iRI6O5Dp0c4+6n2gyTYECAMQPCa8UnoHw1jgw
JHnK+XM3jinqgIOMS66i5nCGe3PItaAOvPIwA0lyl2Io06lGuiSVIqbJIUTsf2Mv
y14eJnECAMt8O6gMsjJdZ/dU9srqz4ZatPUHtQm2KBnvk311PmeErJ1FiiAqXTVq
Q9y3GvkEnENeuC/ac0XztiHsEC2eIEEB/iu1i5sP3zUZZnBNDbsmDZEy+HKHm8lL
Vg1+hHUdznMMmJ/PKq+WlB3KvdNzhEFd+0R+ylfRTMWnhNMWxL1atNyYC7QtS2V5
IEEgKEdlbmVyYXRlZCBieSBTYWx0U3RhY2spIDxrZXlhQGV4YW1wbGU+iNEEEwEI
ADsWIQTvA3ZfWe6QSTDIp4FVOoKgWMDHlQUCY4fxHQIbLwULCQgHAgIiAgYVCgkI
CwIEFgIDAQIeBwIXgAAKCRBVOoKgWMDHldREBACC47Aj7j2UbQpvL4GzK/eh/caD
G+FLVBrv7KyPTzxrPkZW3SmpV7dJtFW+f+PILrJm9a6/3gp0vdHuEJ4TPb8lqQJE
njDESx14BITy30f+hOoPQjlqwxr0Qy+fkgIQZ4uxN5Bvs5hiKFNCPscksbqkMSYr
wSEkO9X/2jSWeGb/3A==
=lVXx
-----END PGP PRIVATE KEY BLOCK-----"""


@pytest.fixture(scope="class")
def key_a_pub_file(key_a_pub, tmp_path_):
    dst = tmp_path_ / "key_a.pub"
    dst.write_text(key_a_pub)
    return dst


@pytest.fixture(scope="class")
def key_a_priv_file(key_a_priv, tmp_path_):
    dst = tmp_path_ / "key_a.key"
    dst.write_text(key_a_priv)
    return dst


@pytest.fixture(scope="class")
def key_b_pub():
    return """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EY4fxNQEEAOgAzbpheJrOq4il5BrMVtP1G1kU94QX2+xLXEgW/wPdE4HD6Zbg
vliIg18v7Na4x8ubWy/7CkXC83EJ8SoSqcCccvuKjIWsm6tfeCidNstNCjewFMUR
7ZOQmAe/I2JAlz2SgNxS3ZDiCZpGkxqE0GZ+1N7Mz2WHImnExG149RVHABEBAAG0
LUtleSBCIChHZW5lcmF0ZWQgYnkgU2FsdFN0YWNrKSA8a2V5YkBleGFtcGxlPojR
BBMBCAA7FiEEEYtPq3gDjLLfe2niD2xCJkdGXJMFAmOH8TUCGy8FCwkIBwICIgIG
FQoJCAsCBBYCAwECHgcCF4AACgkQD2xCJkdGXJNR3AQAk5ZoN+/ViIX3vA/LbXPn
2VE1E7ETTeIGqsb5f98UfjIbYfkNE8+OtnPxnDbSOPWBEOT+XPPjmxnE0a2UNTfn
ECO71/ZUiyC3ZN50IZ0vgzwBH+DeIV6PDAAun5FGx4RI7v6n0CPlrUcWKYe8wY1F
COflOxnEyLVHXnX8wUIzZwo=
=Hq0X
-----END PGP PUBLIC KEY BLOCK-----"""
