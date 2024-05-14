import pytest

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
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
    }


@pytest.fixture
def userrole():
    return {
        "key_type": "ca",
        "allowed_users": "foo,bar,baz",
        "allowed_extensions": "*",
        "allow_user_certificates": True,
        "ttl": 3600,
        "max_ttl": 86400,
    }


@pytest.fixture
def hostrole():
    return {
        "key_type": "ca",
        "allowed_domains": "*",
        "allow_host_certificates": True,
        "ttl": 3600,
        "max_ttl": 86400,
    }


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


@pytest.fixture(scope="module", autouse=True)
def ssh_engine(vault_container_version):  # pylint: disable=unused-argument
    assert vault_enable_secret_engine("ssh")
    yield
    assert vault_disable_secret_engine("ssh")


@pytest.fixture
def roles_clean():
    try:
        yield
    finally:
        for role_name in ("userrole", "hostrole", "iprole"):
            if role_name in vault_list("ssh/roles"):
                vault_delete(f"ssh/roles/{role_name}")
                assert role_name not in vault_list("ssh/roles")


@pytest.fixture(params=(("userrole", "hostrole", "iprole"),))
def roles_setup(request, roles_clean):  # pylint: disable=unused-argument
    for role_name in request.param:
        role_args = request.getfixturevalue(role_name)
        vault_write(f"ssh/roles/{role_name}", **role_args)
        assert role_name in vault_list("ssh/roles")
    yield


@pytest.fixture
def vault_ssh(states):
    try:
        yield states.vault_ssh
    finally:
        pass


@pytest.fixture
def _temp_role():
    name = "testrole"
    try:
        yield name
    finally:
        vault_delete(f"ssh/roles/{name}")


@pytest.fixture
def _temp_ca():
    try:
        yield
    finally:
        vault_delete("ssh/config/ca")


@pytest.fixture
def ca_setup(ec_priv, ec_pub):
    vault_write("ssh/config/ca", private_key=ec_priv, public_key=ec_pub)
    assert vault_read("ssh/config/ca", default=False)
    try:
        yield
    finally:
        vault_delete("ssh/config/ca")


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


@pytest.mark.usefixtures("_temp_ca")
def test_ca_present(vault_ssh, testmode):
    ret = vault_ssh.ca_present("foobar", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert "created" in ret.changes
    assert bool(vault_read("ssh/config/ca", default=False)) is not testmode


@pytest.mark.usefixtures("ca_setup")
def test_ca_present_already_present(vault_ssh, testmode):
    ret = vault_ssh.ca_present("foobar", test=testmode)
    assert ret.result is True
    assert "already been initialized" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("ca_setup")
def test_ca_absent(vault_ssh, testmode):
    ret = vault_ssh.ca_absent("foobar", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert "destroyed" in ret.changes
    assert bool(vault_read("ssh/config/ca", default=False)) is testmode


def test_ca_absent_already_absent(vault_ssh, testmode):
    ret = vault_ssh.ca_absent("foobar", test=testmode)
    assert ret.result is True
    assert "There is no CA" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("roles_clean")
def test_role_present_ca(vault_ssh, userrole, testmode):
    key_type = userrole.pop("key_type")
    ret = vault_ssh.role_present_ca("userrole", **userrole, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert "created" in ret.changes
    assert bool(vault_read("ssh/roles/userrole", default=False)) is not testmode
    if not testmode:
        data = vault_read("ssh/roles/userrole")["data"]
        assert data["key_type"] == key_type
        for param, val in userrole.items():
            assert data[param] == val


@pytest.mark.usefixtures("roles_clean")
def test_role_present_otp(vault_ssh, iprole, testmode):
    key_type = iprole.pop("key_type")
    ret = vault_ssh.role_present_otp("iprole", **iprole, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert "created" in ret.changes
    assert bool(vault_read("ssh/roles/iprole", default=False)) is not testmode
    if not testmode:
        data = vault_read("ssh/roles/iprole")["data"]
        assert data["key_type"] == key_type
        for param, val in iprole.items():
            assert data[param] == val


@pytest.mark.usefixtures("roles_setup")
def test_role_present_ca_already_present(vault_ssh, userrole, testmode):
    userrole.pop("key_type")
    ret = vault_ssh.role_present_ca("userrole", **userrole, test=testmode)
    assert ret.result is True
    assert "as specified" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_role_present_otp_already_present(vault_ssh, iprole, testmode):
    iprole.pop("key_type")
    ret = vault_ssh.role_present_otp("iprole", **iprole, test=testmode)
    assert ret.result is True
    assert "as specified" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
def test_role_present_ca_changes(vault_ssh, userrole, testmode):
    change = {
        "allow_user_key_ids": True,
        "ttl": "2h",
        "allowed_user_key_lengths": {"rsa": [2048, 3072], "ec": 256},
    }
    params = userrole.copy()
    params.update(change)
    params.pop("key_type")
    ret = vault_ssh.role_present_ca("userrole", **params, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert set(ret.changes) == set(change)
    assert ret["changes"]["ttl"] == {"old": userrole.get("ttl", 0), "new": 7200}
    assert ret["changes"]["allow_user_key_ids"] == {
        "old": userrole.get("allow_user_key_ids", False),
        "new": change["allow_user_key_ids"],
    }
    assert ret["changes"]["allowed_user_key_lengths"] == {
        "added": ["ec", "rsa"],
        "changed": [],
        "removed": [],
    }

    new = vault_read("ssh/roles/userrole")["data"]
    assert (new["ttl"] != 7200) is testmode
    assert new["allow_user_key_ids"] is not testmode


@pytest.mark.usefixtures("roles_setup")
def test_role_present_otp_changes(vault_ssh, iprole, testmode):
    change = {
        "default_user": "barbaz",
        "cidr_list": ["0.0.0.0/1", "128.0.0.0/1"],
        "exclude_cidr_list": None,
    }
    iprole.update(change)
    iprole.pop("key_type")
    ret = vault_ssh.role_present_otp("iprole", **iprole, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert set(ret.changes) == set(change)
    assert ret.changes["default_user"] == {"old": "foobar", "new": "barbaz"}
    assert ret.changes["cidr_list"] == {"added": ["128.0.0.0/1"], "removed": []}
    assert ret.changes["exclude_cidr_list"] == {"added": [], "removed": ["128.0.0.0/1"]}

    new = vault_read("ssh/roles/iprole")["data"]
    assert (new["default_user"] != "barbaz") is testmode
    assert (new["cidr_list"] != "0.0.0.0/1,128.0.0.0/1") is testmode
    assert bool(new["exclude_cidr_list"]) is testmode


@pytest.mark.usefixtures("roles_setup")
def test_role_present_key_type_change(vault_ssh, iprole, testmode):
    iprole.pop("key_type")
    ret = vault_ssh.role_present_otp("userrole", **iprole, test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert set(ret.changes) == {"key_type"}
    assert ret.changes["key_type"] == {"old": "ca", "new": "otp"}
    new = vault_read("ssh/roles/userrole")["data"]
    assert (new["key_type"] == "ca") is testmode


@pytest.mark.usefixtures("roles_setup")
def test_role_absent(vault_ssh, testmode):
    ret = vault_ssh.role_absent("userrole", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert "deleted" in ret.changes
    assert bool(vault_read("ssh/roles/userrole", default=False)) is testmode


def test_role_absent_already_absent(vault_ssh, testmode):
    ret = vault_ssh.role_absent("foobar", test=testmode)
    assert ret.result is True
    assert "already absent" in ret.comment
    assert not ret.changes
