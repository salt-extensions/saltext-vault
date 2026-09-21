import logging

import pytest
from salt.utils.dictupdate import merge_recurse

from tests.common.containers import genmarks
from tests.common.helpers.vault_ssh import CERT_CHECK
from tests.common.helpers.vault_ssh import belongs_to
from tests.common.helpers.vault_ssh import get_cert
from tests.common.helpers.vault_ssh import signed_by

pytestmark = genmarks(
    "roles_setup",
    "ca_setup",
    internal_logic_only=True,
    mounts="ssh",
    policies=True,
    _check_cryptography="40.0",
)

log = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def _check_ssh_pki_available(minion):
    ret = minion.salt_call_cli().run("-d", "ssh_pki.create_private_key")
    if not ret.stdout:
        # Salt < 3008
        pytest.skip("ssh_pki modules are not available")


@pytest.fixture(scope="module", autouse=True)
def cm_wrapper(master):
    state_contents = """
    {{
        salt["ssh_pki.certificate_managed_wrapper"](
            pillar["args"]["name"],
            ca_server=pillar["args"].get("ca_server"),
            signing_policy=pillar["args"]["signing_policy"],
            backend="vault_ssh",
            backend_args=pillar["args"].get("backend_args"),
            private_key_managed=pillar["args"].get("private_key_managed"),
            private_key=pillar["args"].get("private_key"),
            private_key_passphrase=pillar["args"].get("private_key_passphrase"),
            public_key=pillar["args"].get("public_key"),
            certificate_managed=pillar["args"].get("certificate_managed"),
            test=opts.get("test")
        ) | yaml(false)
    }}
    """
    with master.state_tree.base.temp_file("cert.sls", state_contents):
        yield


@pytest.fixture
def pk_tgt(tmp_path):
    return str(tmp_path / "managed_key")


@pytest.fixture
def user_args(tmp_path, ec_priv_file, request):
    defaults = {
        "name": f"{tmp_path}/cert",
        "ca_server": "ssh",
        "signing_policy": "userrole",
        "backend": "vault_ssh",
        "private_key": ec_priv_file,
        "certificate_managed": {
            "cert_type": "user",
            "valid_principals": ["foo"],
            "ttl_remaining": 600,
        },
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


@pytest.fixture
def host_args(tmp_path, ec_priv_file, request):
    defaults = {
        "name": f"{tmp_path}/cert",
        "ca_server": "ssh",
        "signing_policy": "hostrole",
        "backend": "vault_ssh",
        "private_key": ec_priv_file,
        "certificate_managed": {
            "cert_type": "host",
            "valid_principals": ["foo.bar.baz"],
            "ttl": 86400,
            "ttl_remaining": 3600,
        },
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


@pytest.fixture
def existing_cert(
    salt_ssh_cli, ec_priv, ca_priv, request, pk_tgt, ca_setup, roles_setup
):  # pylint: disable=unused-argument
    if request.function.__name__.startswith("test_user"):
        args = request.getfixturevalue("user_args")
        exp_cert_typ = "user"
    else:
        args = request.getfixturevalue("host_args")
        exp_cert_typ = "host"
    args = merge_recurse(args, getattr(request, "param", {}))
    pk_managed = {}
    exp_key = ec_priv
    if "private_key_managed" in args:
        pk_managed = {"private_key_managed": args.pop("private_key_managed")}
        pk_managed["private_key_managed"]["name"] = pk_tgt
        exp_key = pk_tgt
    args.update(pk_managed)
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": args})
    assert ret.returncode == 0
    if CERT_CHECK:
        cert = get_cert(args["name"], exp_cert_typ)
        assert signed_by(cert, ca_priv)
        assert belongs_to(cert, exp_key)
    yield args["name"]


def test_user_certificate_managed(salt_ssh_cli, user_args, ca_priv, ec_priv):
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": user_args})
    assert ret.returncode == 0
    if CERT_CHECK:
        cert = get_cert(user_args["name"], "user")
        assert signed_by(cert, ca_priv)
        assert belongs_to(cert, ec_priv)


def test_host_certificate_managed(salt_ssh_cli, host_args, ca_priv, ec_priv):
    host_args["certificate_managed"].pop("cert_type")  # also test autodetermination of cert type
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": host_args})
    assert ret.returncode == 0
    if CERT_CHECK:
        cert = get_cert(host_args["name"], "host")
        assert signed_by(cert, ca_priv)
        assert belongs_to(cert, ec_priv)


@pytest.mark.usefixtures("existing_cert")
def test_user_certificate_managed_changes(salt_ssh_cli, user_args, ca_priv, ec_priv):
    user_args["certificate_managed"].pop("cert_type")  # also test autodetermination of cert type
    user_args["certificate_managed"]["valid_principals"].append("foo-bar")
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": user_args})
    assert ret.returncode == 0
    assert ret.data[next(iter(ret.data))]["changes"] == {
        "principals": {"added": ["foo-bar"], "removed": []}
    }
    if CERT_CHECK:
        cert = get_cert(user_args["name"], "user")
        assert signed_by(cert, ca_priv)
        assert belongs_to(cert, ec_priv)
        assert cert.valid_principals == [b"foo", b"foo-bar"]


@pytest.mark.usefixtures("existing_cert")
def test_host_certificate_managed_changes(salt_ssh_cli, host_args, ca_priv, ec_priv):
    host_args["certificate_managed"]["valid_principals"].append("bar.bar.baz")
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": host_args})
    assert ret.returncode == 0
    assert ret.data[next(iter(ret.data))]["changes"] == {
        "principals": {"added": ["bar.bar.baz"], "removed": []}
    }
    if CERT_CHECK:
        cert = get_cert(host_args["name"], "host")
        assert signed_by(cert, ca_priv)
        assert belongs_to(cert, ec_priv)
        assert cert.valid_principals == [b"bar.bar.baz", b"foo.bar.baz"]


@pytest.mark.usefixtures("existing_cert")
def test_user_certificate_managed_no_changes(salt_ssh_cli, user_args):
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": user_args})
    assert ret.returncode == 0
    assert ret.data[next(iter(ret.data))]["changes"] == {}


@pytest.mark.usefixtures("existing_cert")
def test_host_certificate_managed_no_changes(salt_ssh_cli, host_args):
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": host_args})
    assert ret.returncode == 0
    assert ret.data[next(iter(ret.data))]["changes"] == {}


@pytest.mark.usefixtures("existing_cert")
def test_user_certificate_managed_renew(salt_ssh_cli, user_args):
    cert_cur = None
    if CERT_CHECK:
        cert_cur = get_cert(user_args["name"], "user")
    user_args["certificate_managed"]["ttl_remaining"] = "999d"
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": user_args})
    assert ret.returncode == 0
    assert ret.data[next(iter(ret.data))]["changes"] == {"expiration": True}
    if CERT_CHECK and cert_cur:
        cert_new = get_cert(user_args["name"], "user")
        assert cert_new.serial != cert_cur.serial


@pytest.mark.usefixtures("existing_cert")
def test_host_certificate_managed_renew(salt_ssh_cli, host_args):
    cert_cur = None
    if CERT_CHECK:
        cert_cur = get_cert(host_args["name"], "host")
    host_args["certificate_managed"]["ttl_remaining"] = "999d"
    ret = salt_ssh_cli.run("state.apply", "cert", pillar={"args": host_args})
    assert ret.returncode == 0
    assert ret.data[next(iter(ret.data))]["changes"] == {"expiration": True}
    if CERT_CHECK and cert_cur:
        cert_new = get_cert(host_args["name"], "host")
        assert cert_new.serial != cert_cur.serial
