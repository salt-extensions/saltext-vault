import pytest

from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")


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
def userrole(request):
    defaults = {
        "key_type": "ca",
        "allowed_users": "*",
        "allowed_critical_options": "",
        "allowed_extensions": "*",
        "allow_user_certificates": True,
        "ttl": 3600,
        "max_ttl": 86400,
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


@pytest.fixture
def hostrole(request):
    defaults = {
        "key_type": "ca",
        "allowed_domains": "*",
        "allowed_critical_options": "",
        "allowed_extensions": "*",
        "allow_host_certificates": True,
        "ttl": 3600,
        "max_ttl": 86400,
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


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
def ssh_engine(container):  # pylint: disable=unused-argument
    assert vault_enable_secret_engine("ssh")
    yield
    assert vault_disable_secret_engine("ssh")


@pytest.fixture(params=(("userrole", "hostrole", "iprole"),))
def roles_setup(request):
    roles = {}
    try:
        for role_name in request.param:
            try:
                role_args_overrides = request.param[role_name]
            except TypeError:
                role_args = request.getfixturevalue(role_name)
            else:
                try:
                    role_args = request.getfixturevalue(role_name)
                except pytest.FixtureLookupError:
                    role_args = {}
                role_args.update(role_args_overrides)
            vault_write(f"ssh/roles/{role_name}", **role_args)
            assert role_name in vault_list("ssh/roles")
            roles[role_name] = role_args
        yield roles
    finally:
        for role_name in request.param:
            if role_name in vault_list("ssh/roles"):
                vault_delete(f"ssh/roles/{role_name}")
                assert role_name not in vault_list("ssh/roles")


@pytest.fixture
def ca_setup(ec_priv, ec_pub):
    vault_write("ssh/config/ca", private_key=ec_priv, public_key=ec_pub)
    assert vault_read("ssh/config/ca", default=False)
    try:
        yield
    finally:
        vault_delete("ssh/config/ca")


@pytest.fixture
def vault_ssh(modules):
    try:
        yield modules.vault_ssh
    finally:
        pass
