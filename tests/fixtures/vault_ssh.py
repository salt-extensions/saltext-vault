"""
Shared fixtures for the vault_ssh test suites.
"""

import pytest

from tests.support.vault import vault_delete


@pytest.fixture
def iprole():
    return {
        "key_type": "otp",
        "default_user": "foobar",
        "cidr_list": "0.0.0.0/1",
        "exclude_cidr_list": "128.0.0.0/1",
        "port": 9876,
    }


@pytest.fixture
def ec_priv():
    return """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSO2hM3nJP6fxgzyXIEEKhHeqOqXccIvV8EZLfqCrcX
NGR7Be7yYdPNx+bcNFx5fyLrxKin+f/4pV4/q+mMoqVxAAAAoHwE+2V8BPtlAAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI7aEzeck/p/GDPJcgQQqEd6o6pdxwi9XwRkt+oK
txc0ZHsF7vJh083H5tw0XHl/IuvEqKf5//ilXj+r6YyipXEAAAAgc5sbtq4PEIHmkqJzEbNaO1sB
2PSfCjWqlGSC7ODBqy4AAAAAAQIDBAUGBwg=
-----END OPENSSH PRIVATE KEY-----
    """.strip()


@pytest.fixture
def ec_priv_file(ec_priv, tmp_path):
    path = tmp_path / "ec"
    path.write_text(ec_priv)
    return str(path)


@pytest.fixture
def ec_pub():
    return "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI7aEzeck/p/GDPJcgQQqEd6o6pdxwi9XwRkt+oKtxc0ZHsF7vJh083H5tw0XHl/IuvEqKf5//ilXj+r6YyipXE="


@pytest.fixture
def ec_pub_file(ec_pub, tmp_path):
    path = tmp_path / "ec.pub"
    path.write_text(ec_pub)
    return str(path)


@pytest.fixture
def _temp_ca():
    try:
        yield
    finally:
        vault_delete("ssh/config/ca")


@pytest.fixture
def _temp_role():
    name = "testrole"
    try:
        yield name
    finally:
        vault_delete(f"ssh/roles/{name}")
