import pytest

# pylint: disable=unused-import
from tests.fixtures.vault_ssh import ec_priv
from tests.fixtures.vault_ssh import ec_priv_file
from tests.fixtures.vault_ssh import ec_pub
from tests.fixtures.vault_ssh import ec_pub_file
from tests.fixtures.vault_ssh import hostrole
from tests.fixtures.vault_ssh import iprole
from tests.fixtures.vault_ssh import roles_setup
from tests.fixtures.vault_ssh import userrole

# pylint: enable=unused-import
from tests.support.vault import vault_delete
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")


@pytest.fixture
def ca_priv():
    return """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQScOqN2HTar84e+l3Er4Ti0ZsY3nbR9RkRsgZb0Flie
lc8SN/zIHSLroaJ21ofSqfu+mazGpGFWkNo34zSbBW5+AAAAoEaJqOBGiajgAAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJw6o3YdNqvzh76XcSvhOLRmxjedtH1GRGyBlvQW
WJ6VzxI3/MgdIuuhonbWh9Kp+76ZrMakYVaQ2jfjNJsFbn4AAAAhAL7DzNqGQYRNLOeXUt/t+DFz
R4+26CwTk8SDLHiIt2dpAAAAAAECAwQFBgc=
-----END OPENSSH PRIVATE KEY-----"""


@pytest.fixture
def ca_priv_file(ca_priv, tmp_path):
    path = tmp_path / "ca"
    path.write_text(ca_priv)
    return str(path)


@pytest.fixture
def ca_pub():
    return "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJw6o3YdNqvzh76XcSvhOLRmxjedtH1GRGyBlvQWWJ6VzxI3/MgdIuuhonbWh9Kp+76ZrMakYVaQ2jfjNJsFbn4="


@pytest.fixture
def ca_pub_file(ca_pub, tmp_path):
    path = tmp_path / "ca.pub"
    path.write_text(ca_pub)
    return str(path)


@pytest.fixture
def ca_setup(ca_priv, ca_pub):
    vault_write("ssh/config/ca", private_key=ca_priv, public_key=ca_pub)
    assert vault_read("ssh/config/ca", default=False)
    try:
        yield
    finally:
        vault_delete("ssh/config/ca")


@pytest.fixture
def vault_ssh(modules):
    return modules.vault_ssh
