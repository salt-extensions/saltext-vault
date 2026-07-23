import base64
import platform
import shutil
import stat
from pathlib import Path

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
from saltfactories.utils import random_string

from tests.conftest import CONTAINER_TARGETS
from tests.support.gpg import gpg as _gpg
from tests.support.gpg import gpghome as _gpghome
from tests.support.vault import vault_delete
from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_list
from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_register
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")
pytest.importorskip("gnupg", reason="Needs python-gnupg library")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.skip_if_binaries_missing("gpg", reason="Needs gpg binary"),
    pytest.mark.usefixtures("container"),
    pytest.mark.skip_unless_on_platform(linux=True, darwin=True),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # Backend is the same, regardless of Vault vs OpenBao
]


@pytest.fixture(scope="module")
def _cached_bin(states, modules):
    """
    Cache this plugin outside of test run-specific directories
    to avoid repeated downloads.
    """
    machine = platform.machine()
    if machine in {"arm64", "aarch64"}:
        arch = "arm64"
    elif machine in {"amd64", "x86_64"}:
        arch = "amd64"
    else:
        return pytest.skip("Architecture not accounted for in gnupg plugin setup")
    cache_path = Path(f"/tmp/saltext-vault-testsuite/vault-gpg-plugin/0.6.3/linux_{arch}")
    bin_path = cache_path / "vault-gpg-plugin"
    sum_path = bin_path.with_suffix(".sum")
    if not cache_path.exists():
        cache_path.mkdir(parents=True)
    if not bin_path.exists():
        # For Docker Desktop, macOS needs Linux binary as well.
        ret = states.archive.extracted(
            str(cache_path) + "/",
            source=f"https://github.com/LeSuisse/vault-gpg-plugin/releases/download/v0.6.3/linux_{arch}.zip",
            source_hash="https://github.com/LeSuisse/vault-gpg-plugin/releases/download/v0.6.3/checksums.txt",
            enforce_toplevel=False,
        )
        assert ret.result is True
    assert bin_path.exists()
    if sum_path.exists():
        checksum = sum_path.read_text()
    else:
        checksum = modules.hashutil.digest_file(str(bin_path), checksum="sha256")
        sum_path.write_text(checksum)
    return bin_path, checksum


@pytest.fixture(scope="module")
def gpg_plugin(vault_plugins, container, states, _cached_bin):  # pylint: disable=unused-argument
    bin_path, checksum = _cached_bin
    tgt = vault_plugins / "vault-gpg-plugin"
    try:
        ret = states.file.managed(
            str(tgt),
            source="file://" + str(bin_path),
            mode="0755",
        )
        assert ret.result is True
        reg = {
            "name": "gpg",
            "plugin_type": "secret",
            "sha256": checksum,
            "command": "vault-gpg-plugin",
            "version": "v0.6.3",
        }
        assert vault_plugin_register(**reg)
        yield
    finally:
        vault_plugin_deregister("secret", "gpg", version="v0.6.3")
        tgt.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def gpg_mount(gpg_plugin):  # pylint: disable=unused-argument
    name = random_string("gpg-test", uppercase=False)
    assert vault_enable_secret_engine("gpg", name)
    try:
        yield name
    finally:
        assert vault_disable_secret_engine(name)


@pytest.fixture(scope="class")
def vault_gpg(modules, gpg_mount):  # pylint: disable=unused-argument
    try:
        yield modules.vault_gpg
    finally:
        for key in vault_list(f"{gpg_mount}/keys"):
            assert vault_delete(f"{gpg_mount}/keys/{key}")


gpg = pytest.fixture(scope="class")(_gpg)
gpghome = pytest.fixture(scope="class")(_gpghome)


@pytest.fixture(scope="class")
def tmp_path_(tmp_path_factory):
    tmpdir = tmp_path_factory.mktemp("vault-gpg")
    try:
        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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


@pytest.fixture(scope="class")
def existing_key(gpg_mount, request):
    name = "testkey"
    exportable = getattr(request, "param", False)
    assert vault_write(
        f"{gpg_mount}/keys/{name}",
        generate=True,
        real_name="Salt Test",
        email="salt@te.st",
        comment="Hello",
        exportable=exportable,
    )
    try:
        yield name
    finally:
        assert vault_delete(f"{gpg_mount}/keys/{name}")


def test_create_key(vault_gpg, gpg_mount, salt_version, gpg):
    res = vault_gpg.create_key(
        "foobar",
        real_name="Salt Test",
        email="salt@te.st",
        comment="Hello",
        key_bits=3192,
        mount=gpg_mount,
    )
    assert res is True
    data = vault_read(f"{gpg_mount}/keys/foobar")["data"]
    assert data
    assert "fingerprint" in data
    assert "public_key" in data
    assert data["exportable"] is False
    if salt_version[0] >= 3008:
        with pytest.helpers.temp_file("pubkey", contents=data["public_key"]) as f:  # type: ignore
            # Use path for wrapper tests
            key_info = gpg.read_key(path=str(f))[0]
        assert key_info["uids"] == ["Salt Test (Hello) <salt@te.st>"]
        assert key_info["keyLength"] == "3192"


def test_import_key(vault_gpg, gpg_mount, salt_version, gpg, key_a_priv):
    res = vault_gpg.import_key(
        "barbaz",
        _unpem(key_a_priv),
        mount=gpg_mount,
    )
    assert res is True
    data = vault_read(f"{gpg_mount}/keys/barbaz")["data"]
    assert data
    assert "fingerprint" in data
    assert "public_key" in data
    assert data["exportable"] is False
    if salt_version[0] >= 3008:
        # Use path for wrapper tests
        with pytest.helpers.temp_file("pubkey", contents=data["public_key"]) as f:  # type: ignore
            key_info = gpg.read_key(path=str(f))[0]
        assert key_info["uids"] == ["Key A (Generated by SaltStack) <keya@example>"]
        assert key_info["keyLength"] == "1024"


def test_import_key_fail(vault_gpg, gpg_mount):
    with pytest.raises(CommandExecutionError, match="Expected key to be.*got neither"):
        vault_gpg.import_key(
            "quux",
            "foo bar boom",
            mount=gpg_mount,
        )


def test_import_from_file(vault_gpg, gpg_mount, key_a_priv_file, key_a_fp):
    res = vault_gpg.import_key("from_file", path=str(key_a_priv_file), mount=gpg_mount)
    assert res is True
    data = vault_read(f"{gpg_mount}/keys/from_file")["data"]
    assert data["fingerprint"].upper() == key_a_fp


@pytest.mark.requires_salt(3007)
def test_import_from_gpg(vault_gpg, gpg_mount, gpg, gpghome, key_a_priv_file, key_a_fp):
    signer_res = gpg.import_key(filename=str(key_a_priv_file), gnupghome=str(gpghome))
    assert signer_res["res"]
    res = vault_gpg.import_key(
        "from_gpg", fingerprint=key_a_fp, gnupghome=str(gpghome), mount=gpg_mount
    )
    assert res is True
    data = vault_read(f"{gpg_mount}/keys/from_gpg")["data"]
    assert data["fingerprint"].upper() == key_a_fp


def test_list_keys(vault_gpg, gpg_mount, existing_key):
    res = vault_gpg.list_keys(mount=gpg_mount)
    assert res == [existing_key]


def test_list_keys_empty(vault_gpg, gpg_mount):
    res = vault_gpg.list_keys(mount=gpg_mount)
    assert res == []


def test_read_key(vault_gpg, gpg_mount, existing_key):
    res = vault_gpg.read_key(existing_key, mount=gpg_mount)
    assert "fingerprint" in res
    assert "public_key" in res
    assert res["exportable"] is False


def test_read_key_missing(vault_gpg, gpg_mount):
    res = vault_gpg.read_key("missing_key", mount=gpg_mount)
    assert res is None


def test_delete_key(vault_gpg, gpg_mount, existing_key):
    res = vault_gpg.delete_key(existing_key, mount=gpg_mount)
    assert res is True
    assert not vault_list(f"{gpg_mount}/keys")


def test_delete_key_missing(vault_gpg, gpg_mount):
    res = vault_gpg.delete_key("missing_key", mount=gpg_mount)
    assert res is True


@pytest.mark.parametrize("existing_key", (True,), indirect=True)
def test_export_private_key(vault_gpg, gpg_mount, existing_key):
    res = vault_gpg.export_private_key(existing_key, mount=gpg_mount)
    assert res.startswith("-----BEGIN PGP PRIVATE")


def test_export_private_key_fail(vault_gpg, gpg_mount, existing_key):
    with pytest.raises(CommandExecutionError, match=".*key is not exportable.*"):
        vault_gpg.export_private_key(existing_key, mount=gpg_mount)


@pytest.mark.parametrize("existing_key", (True,), indirect=True)
def test_export_private_key_to_file(vault_gpg, gpg_mount, existing_key, tmp_path):
    dst = tmp_path / "subdir" / "exported.key"
    res = vault_gpg.export_private_key(existing_key, path=str(dst), mount=gpg_mount)
    assert "written to" in res
    assert dst.exists()
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert dst.read_text().startswith("-----BEGIN PGP PRIVATE")


@pytest.mark.requires_salt(3007)
@pytest.mark.parametrize("existing_key", (True,), indirect=True)
def test_export_private_key_to_gpg(vault_gpg, gpg_mount, existing_key, gpg, gpghome):
    fp = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]["fingerprint"].upper()
    res = vault_gpg.export_private_key(
        existing_key, gnupg=True, gnupghome=str(gpghome), mount=gpg_mount
    )
    assert "exported to GnuPG" in res
    keys = gpg.list_secret_keys(gnupghome=str(gpghome))
    assert any(key["fingerprint"] == fp for key in keys)


@pytest.mark.parametrize("existing_key", (True,), indirect=True)
def test_export_public_key(vault_gpg, gpg_mount, existing_key):
    res = vault_gpg.export_public_key(existing_key, mount=gpg_mount)
    assert res.startswith("-----BEGIN PGP PUBLIC")


def test_export_public_key_missing(vault_gpg, gpg_mount):
    with pytest.raises(CommandExecutionError):
        vault_gpg.export_public_key("missing_key", mount=gpg_mount)


@pytest.mark.parametrize("existing_key", (True,), indirect=True)
def test_export_public_key_to_file(vault_gpg, gpg_mount, existing_key, tmp_path):
    dst = tmp_path / "subdir" / "exported.pub"
    res = vault_gpg.export_public_key(existing_key, path=str(dst), mount=gpg_mount)
    assert "written to" in res
    assert dst.exists()
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert dst.read_text().startswith("-----BEGIN PGP PUBLIC")


@pytest.mark.requires_salt(3007)
@pytest.mark.parametrize("existing_key", (True,), indirect=True)
def test_export_public_key_to_gpg(vault_gpg, gpg_mount, existing_key, gpg, gpghome):
    fp = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]["fingerprint"].upper()
    res = vault_gpg.export_public_key(
        existing_key, gnupg=True, gnupghome=str(gpghome), mount=gpg_mount
    )
    assert "exported to GnuPG" in res
    keys = gpg.list_keys(gnupghome=str(gpghome))
    assert any(key["fingerprint"] == fp for key in keys)


@pytest.mark.parametrize("encoding", ("base64", "ascii-armor"))
def test_sign_verify(vault_gpg, gpg_mount, existing_key, encoding):
    message = "Hi there"
    res = vault_gpg.sign(existing_key, message, encoding=encoding, mount=gpg_mount)
    assert isinstance(res, str)
    if encoding == "ascii-armor":
        assert res.startswith("-----BEGIN PGP SIGNATURE")
    else:
        _ = base64.b64decode(res)
    verify = vault_gpg.verify(existing_key, message, res, mount=gpg_mount)
    assert verify is True


def test_sign_verify_path(vault_gpg, gpg_mount, existing_key, tmp_path):
    tosign = tmp_path / "signed_message"
    sig = tmp_path / "signed_message.sig"
    message = b"\x00\xca\xfe\xba\xbe\x00"
    tosign.write_bytes(message)
    res = vault_gpg.sign(existing_key, path=str(tosign), mount=gpg_mount)
    assert isinstance(res, str)
    sig_data = base64.b64decode(res)
    sig.write_bytes(sig_data)
    verify = vault_gpg.verify(existing_key, path=str(tosign), sig_path=str(sig), mount=gpg_mount)
    assert verify is True


def test_sign_verify_encoded_message(vault_gpg, gpg_mount, existing_key):
    message = b"\x00\xca\xfe\xba\xbe\x00"
    message_encoded = base64.b64encode(message).decode()
    res = vault_gpg.sign(existing_key, message_encoded=message_encoded, mount=gpg_mount)
    assert isinstance(res, str)
    verify = vault_gpg.verify(
        existing_key, message_encoded=message_encoded, sig=res, mount=gpg_mount
    )
    assert verify is True


def test_import_key_any_source_required(vault_gpg):
    with pytest.raises(SaltInvocationError, match="Either `text`.*is required"):
        vault_gpg.import_key("foobar")


def test_import_key_at_most_one_source_allowed(vault_gpg):
    with pytest.raises(SaltInvocationError, match=r"Only specify either `text`.*\(exclusive\)"):
        vault_gpg.import_key("foobar", text="bar", path="baz")


@pytest.mark.requires_salt(3007)
def test_import_key_unknown_fingerprint(vault_gpg, gpghome):
    with pytest.raises(CommandExecutionError, match="Failed exporting the secret key from GnuPG.*"):
        vault_gpg.import_key(
            "foobar", fingerprint="96F136AC4C92D78DAF33105E35C03186001C6E31", gnupghome=gpghome
        )


def test_sign_data_or_path_required(vault_gpg):
    with pytest.raises(SaltInvocationError, match="Either `message`.*is required"):
        vault_gpg.sign("foobar")


def test_verify_message_or_path_required(vault_gpg):
    with pytest.raises(SaltInvocationError, match="Either `message`.*is required"):
        vault_gpg.verify("foobar", sig="/tmp/sig")


def test_verify_sig_or_sig_path_required(vault_gpg):
    with pytest.raises(SaltInvocationError, match="Either `sig`.*is required"):
        vault_gpg.verify("foobar", "bar")


def test_decrypt_message_or_path_required(vault_gpg):
    with pytest.raises(SaltInvocationError, match="Either `message`.*is required"):
        vault_gpg.decrypt("foobar")


def test_decrypt_cannot_specify_both_signer_key_and_its_path(vault_gpg):
    with pytest.raises(SaltInvocationError, match="At most one of `signer_key`.*"):
        vault_gpg.decrypt("foobar", "bar", signer_key="quux", signer_key_path="wut")


def _unpem(data):
    secret_lines = [line for line in data.splitlines() if line][1:-1]
    if len(secret_lines[-1]) == 5 and secret_lines[-1][0] == "=":
        # Strip deprecated CRC24 checksum
        secret_lines = secret_lines[:-1]
    return "".join(secret_lines)


@pytest.fixture(scope="class")
def secret_message(gpg_mount, existing_key, gpg, gpghome, key_a_priv, key_a_fp):
    signer_res = gpg.import_key(text=key_a_priv, gnupghome=str(gpghome))
    assert signer_res["res"]
    recipient = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]
    secret = "I like turtles"
    import_res = gpg.import_key(recipient["public_key"], gnupghome=str(gpghome))
    assert import_res["res"]
    secret_msg = gpg.encrypt(
        recipients=recipient["fingerprint"],
        text=secret,
        sign=key_a_fp,
        bare=True,
        always_trust=True,
        gnupghome=str(gpghome),
    )
    assert secret_msg
    return secret_msg.decode()


@pytest.fixture(scope="class")
def secret_message_b64(secret_message):
    # turn into raw base64 string for wrapper tests
    return _unpem(secret_message)


class TestDecrypt:
    @pytest.mark.parametrize("file", (False, True))
    @pytest.mark.parametrize("armor", ("none", "base64", "ascii"))
    def test_decode_utf8(
        self, vault_gpg, gpg_mount, existing_key, file, secret_message, tmp_path, armor
    ):
        if armor != "ascii":
            secret_message = _unpem(secret_message)
            if armor != "base64":
                secret_message = base64.b64decode(secret_message)
        params = {}
        if file:
            secret_file = tmp_path / "secret"
            if armor == "none":
                secret_file.write_bytes(secret_message)
            else:
                secret_file.write_text(secret_message)
            params["path"] = str(secret_file)
        else:
            params["message"] = secret_message
        res = vault_gpg.decrypt(existing_key, **params, mount=gpg_mount)
        assert res == "I like turtles"

    def test_decode_base64(self, vault_gpg, gpg_mount, existing_key, secret_message_b64):
        res = vault_gpg.decrypt(
            existing_key, secret_message_b64, decode_utf8=False, mount=gpg_mount
        )
        assert res == b"I like turtles"

    def test_decode_nothing(self, vault_gpg, gpg_mount, existing_key, secret_message_b64):
        res = vault_gpg.decrypt(existing_key, secret_message_b64, decode=False, mount=gpg_mount)
        assert res == "SSBsaWtlIHR1cnRsZXM="

    def test_signer_key(self, vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_pub):
        res = vault_gpg.decrypt(
            existing_key, secret_message_b64, signer_key=_unpem(key_a_pub), mount=gpg_mount
        )
        assert res == "I like turtles"

    def test_signer_key_path(
        self, vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_pub_file
    ):
        res = vault_gpg.decrypt(
            existing_key, secret_message_b64, signer_key_path=str(key_a_pub_file), mount=gpg_mount
        )
        assert res == "I like turtles"

    @pytest.mark.requires_salt(3007)
    def test_signer_key_fingerprint(
        self, vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_fp, gpghome
    ):
        res = vault_gpg.decrypt(
            existing_key,
            secret_message_b64,
            signer_key_fingerprint=key_a_fp,
            gnupghome=str(gpghome),
            mount=gpg_mount,
        )
        assert res == "I like turtles"

    def test_signer_fail(self, vault_gpg, gpg_mount, existing_key, secret_message_b64, key_b_pub):
        with pytest.raises(CommandExecutionError, match=".*Signature is invalid or not present.*"):
            vault_gpg.decrypt(
                existing_key, secret_message_b64, signer_key=_unpem(key_b_pub), mount=gpg_mount
            )

    def test_decrypt_missing_path(self, vault_gpg, gpg_mount, existing_key):
        with pytest.raises(CommandExecutionError, match=".*path.*does not exist.*"):
            vault_gpg.decrypt(existing_key, path="/does/not/exist/hope_fully", mount=gpg_mount)

    def test_decrypt_missing_signer_key_path(
        self, vault_gpg, gpg_mount, existing_key, secret_message_b64
    ):
        with pytest.raises(CommandExecutionError, match=".*path.*does not exist.*"):
            vault_gpg.decrypt(
                existing_key,
                secret_message_b64,
                signer_key_path="/does/not/exist/hope_fully",
                mount=gpg_mount,
            )

    def test_show_session_key(self, vault_gpg, gpg_mount, existing_key, secret_message_b64):
        res = vault_gpg.show_session_key(existing_key, secret_message_b64, mount=gpg_mount)
        assert isinstance(res, str)
        assert ":" in res
        first, rest = res.split(":", maxsplit=1)
        _ = int(first)  # cipherfunction 2: TripleDES 3: CAST5 7: AES128 8: AES192 9: AES256
        _ = bytes.fromhex(rest)  # key

    def test_show_session_key_signer(
        self, vault_gpg, gpg_mount, existing_key, key_a_pub, secret_message_b64
    ):
        res = vault_gpg.show_session_key(
            existing_key, secret_message_b64, signer_key=_unpem(key_a_pub), mount=gpg_mount
        )
        assert isinstance(res, str)
        assert res
        assert ":" in res

    # NOTE: In contrast to the documentation, the signer key is ignored as of commit 45a0c98b603cb15261d6f485fecc6562e6d0590f
    # def test_show_session_key_signer_fail(
    #     self, vault_gpg, gpg_mount, existing_key, key_b_pub, secret_message
    # ):
    #     with pytest.raises(CommandExecutionError, match=".*Signature is invalid or not present.*"):
    #         vault_gpg.show_session_key(
    #             existing_key, secret_message, signer_key=key_b_pub, mount=gpg_mount
    #         )
