import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_read

try:
    from cryptography.hazmat.primitives.serialization import SSHCertificateType
    from cryptography.hazmat.primitives.serialization import load_ssh_public_identity

    CERT_CHECK = True
except ImportError:
    CERT_CHECK = False

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts"),
    pytest.mark.parametrize("secret_mounts", ("ssh",), indirect=True),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.mark.usefixtures("roles_setup")
def test_read_role(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.read_role", "userrole")
    assert res.returncode == 0
    expected = {
        "algorithm_signer": "default",
        "allow_bare_domains": False,
        "allow_host_certificates": False,
        "allow_subdomains": False,
        "allow_user_certificates": True,
        "allow_user_key_ids": False,
        "allowed_critical_options": "",
        "allowed_domains": "",
        "allowed_domains_template": False,
        "allowed_extensions": "*",
        "allowed_user_key_lengths": {},
        "allowed_users": "*",
        "allowed_users_template": False,
        "default_critical_options": {},
        "default_extensions": {},
        "default_extensions_template": False,
        "default_user": "",
        "default_user_template": False,
        "key_id_format": "",
        "key_type": "ca",
        "max_ttl": 86400,
        "ttl": 3600,
    }
    for var, val in expected.items():
        assert var in res.data
        assert res.data[var] == val


@pytest.fixture
def _temp_role():
    name = "testrole"
    try:
        yield name
    finally:
        vault_delete(f"ssh/roles/{name}")


def test_write_role_ca(salt_ssh_cli, userrole, _temp_role):
    key_type = userrole.pop("key_type")
    res = salt_ssh_cli.run("vault_ssh.write_role_ca", _temp_role, **userrole)
    assert res.returncode == 0
    assert res.data is True
    data = vault_read(f"ssh/roles/{_temp_role}")["data"]
    assert data["key_type"] == key_type
    for var, val in userrole.items():
        assert var in data
        assert data[var] == val


def test_write_role_otp(salt_ssh_cli, iprole, _temp_role):
    key_type = iprole.pop("key_type")
    res = salt_ssh_cli.run("vault_ssh.write_role_otp", _temp_role, **iprole)
    assert res.returncode == 0
    assert res.data is True
    data = vault_read(f"ssh/roles/{_temp_role}")["data"]
    assert data["key_type"] == key_type
    for var, val in iprole.items():
        assert var in data
        assert data[var] == val


@pytest.mark.usefixtures("roles_setup")
def test_delete_role(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.delete_role", "userrole")
    assert res.returncode == 0
    assert res.data is True
    assert "userrole" not in vault_list("ssh/roles")


@pytest.mark.usefixtures("roles_setup")
def test_list_roles(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.list_roles")
    assert res.returncode == 0
    for role in ("userrole", "hostrole", "iprole"):
        assert role in res.data


@pytest.mark.usefixtures("roles_setup")
def test_list_roles_ip(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.list_roles_ip", "10.1.0.1")
    assert res.returncode == 0
    assert res.data == ["iprole"]


@pytest.mark.usefixtures("roles_setup")
def test_zeroaddress_roles(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.list_roles_zeroaddr")
    assert res.returncode == 0
    assert res.data == []
    res = salt_ssh_cli.run("vault_ssh.write_zeroaddr_roles", ["iprole"])
    assert res.returncode == 0
    assert res.data is True
    res = salt_ssh_cli.run("vault_ssh.list_roles_zeroaddr")
    assert res.returncode == 0
    assert res.data == ["iprole"]
    res = salt_ssh_cli.run("vault_ssh.delete_zeroaddr_roles")
    assert res.returncode == 0
    assert res.data is True
    res = salt_ssh_cli.run("vault_ssh.list_roles_zeroaddr")
    assert res.returncode == 0
    assert res.data == []


@pytest.fixture
def _temp_ca():
    try:
        yield
    finally:
        vault_delete("ssh/config/ca")


@pytest.mark.usefixtures("_temp_ca")
def test_create_ca(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.create_ca")
    assert res.returncode == 0
    assert res.data.startswith("ssh-rsa ")
    assert "public_key" in vault_read("ssh/config/ca")["data"]


@pytest.mark.usefixtures("_temp_ca")
def test_create_ca_key_spec(salt_ssh_cli):
    res = salt_ssh_cli.run("vault_ssh.create_ca", key_type="ec", key_bits=384)
    assert res.returncode == 0
    assert res.data.startswith("ecdsa-")
    assert "p384" in res.data
    assert "public_key" in vault_read("ssh/config/ca")["data"]


@pytest.mark.usefixtures("_temp_ca")
def test_create_ca_with_keys(salt_ssh_cli, ca_pub, ca_priv_file):
    res = salt_ssh_cli.run("vault_ssh.create_ca", public_key=ca_pub, private_key=ca_priv_file)
    assert res.returncode == 0
    assert res.data == ca_pub
    assert "public_key" in vault_read("ssh/config/ca")["data"]


@pytest.mark.usefixtures("ca_setup")
def test_read_ca(salt_ssh_cli, ca_pub):
    res = salt_ssh_cli.run("vault_ssh.read_ca")
    assert res.returncode == 0
    assert res.data == ca_pub


@pytest.mark.usefixtures("ca_setup")
def test_destroy_ca(salt_ssh_cli, container):
    res = salt_ssh_cli.run("vault_ssh.destroy_ca")
    assert res.returncode == 0
    if "openbao" in container:
        assert res.data["warnings"]
        assert "Deleted 1 issuers" in res.data["warnings"][0]
    else:
        assert res.data is True
    try:
        res = vault_read("ssh/config/ca", raise_errors=True)
    except RuntimeError as err:
        if "openbao" in container:
            assert "no default issuer currently configured" in str(err)
        else:
            assert "keys haven't been configured yet" in str(err)
    else:
        raise AssertionError(f"CA has not been deleted: {res}")


@pytest.mark.usefixtures("ca_setup", "roles_setup")
def test_sign_key_user(salt_ssh_cli, ec_pub, container):
    res = salt_ssh_cli.run(
        "vault_ssh.sign_key",
        "userrole",
        ec_pub,
        critical_options={"force-command": "rm -rf /"},
        extensions={"permit-pty": ""},
        valid_principals=["foobar"],
    )
    assert res.returncode == 0
    expected = {"serial_number", "signed_key"}
    if "openbao" in container:
        expected.add("issuer_id")
    assert set(res.data) == expected
    if CERT_CHECK:
        cert = load_cert(res.data["signed_key"])
        assert cert.type == SSHCertificateType.USER
        assert cert.critical_options == {b"force-command": b"rm -rf /"}
        assert cert.extensions == {b"permit-pty": b""}
        assert cert.valid_principals == [b"foobar"]


@pytest.mark.usefixtures("ca_setup", "roles_setup")
def test_sign_key_host(salt_ssh_cli, ec_pub, container):
    res = salt_ssh_cli.run(
        "vault_ssh.sign_key", "hostrole", ec_pub, cert_type="host", valid_principals=["foo.bar.biz"]
    )
    assert res.returncode == 0
    expected = {"serial_number", "signed_key"}
    if "openbao" in container:
        expected.add("issuer_id")
    assert set(res.data) == expected
    if CERT_CHECK:
        cert = load_cert(res.data["signed_key"])
        assert cert.type == SSHCertificateType.HOST
        assert not cert.critical_options
        assert cert.valid_principals == [b"foo.bar.biz"]


@pytest.mark.usefixtures("ca_setup", "roles_setup")
def test_generate_key_cert_user(salt_ssh_cli, container):
    res = salt_ssh_cli.run(
        "vault_ssh.generate_key_cert",
        "userrole",
        critical_options={"force-command": "rm -rf /"},
        extensions={"permit-pty": ""},
        valid_principals=["foobar"],
    )
    assert res.returncode == 0
    expected = {"private_key", "private_key_type", "serial_number", "signed_key"}
    if "openbao" in container:
        expected.add("issuer_id")
    assert set(res.data) == expected
    assert res.data["private_key_type"] == "ssh-rsa"
    assert res.data["private_key"].startswith("-----BEGIN")
    if CERT_CHECK:
        cert = load_cert(res.data["signed_key"])
        assert cert.type == SSHCertificateType.USER
        assert cert.critical_options == {b"force-command": b"rm -rf /"}
        assert cert.extensions == {b"permit-pty": b""}
        assert cert.valid_principals == [b"foobar"]


@pytest.mark.usefixtures("ca_setup", "roles_setup")
def test_generate_key_cert_host(salt_ssh_cli, container):
    res = salt_ssh_cli.run(
        "vault_ssh.generate_key_cert",
        "hostrole",
        cert_type="host",
        valid_principals=["foo.bar.biz"],
    )
    assert res.returncode == 0
    expected = {"private_key", "private_key_type", "serial_number", "signed_key"}
    if "openbao" in container:
        expected.add("issuer_id")
    assert set(res.data) == expected
    assert res.data["private_key_type"] == "ssh-rsa"
    assert res.data["private_key"].startswith("-----BEGIN")
    if CERT_CHECK:
        cert = load_cert(res.data["signed_key"])
        assert cert.type == SSHCertificateType.HOST
        assert not cert.critical_options
        assert cert.valid_principals == [b"foo.bar.biz"]


def load_cert(data):
    return load_ssh_public_identity(data.encode())
