"""
Shared fixtures for the vault_gpg test suites.
"""

import platform
import shutil
import subprocess
from pathlib import Path

import psutil
import pytest
from saltfactories.utils import random_string

from tests.support.vault import vault_disable_secret_engine
from tests.support.vault import vault_enable_secret_engine
from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_register


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


@pytest.fixture(scope="module")
def cached_vault_gpg_bin(states, modules):
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
def gpg_plugin(
    vault_plugins, container, states, cached_vault_gpg_bin
):  # pylint: disable=unused-argument
    bin_path, checksum = cached_vault_gpg_bin
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


def _gpg_def(modules, gpghome):  # pylint: disable=unused-argument
    return modules.gpg


def _gpghome_def(tmp_path_factory):
    root = tmp_path_factory.mktemp("gpghome")
    root.chmod(mode=0o0700)
    # just use /tmp, this test module does not run on OSes other than Linux/macOS
    syml = Path("/tmp/" + random_string("gnupg"))
    syml.symlink_to(root)  # the actual path can get too long for gpg
    try:
        yield syml
    finally:
        # Make sure we don't leave any gpg-agents running behind
        _kill_gpg_agent(root)
        syml.unlink()
        shutil.rmtree(root, ignore_errors=True)


gpg = pytest.fixture(scope="module")(_gpg_def)
gpghome = pytest.fixture(scope="module")(_gpghome_def)

# Some specific tests need the gpg/gpghome fixtures as class-scoped ones.
# Others can work with the default module-scoped ones above.
# When importing the class-scoped ones, ensure they are renamed to `gpg`/`gpghome`.
gpg_class = pytest.fixture(scope="class")(_gpg_def)
gpghome_class = pytest.fixture(scope="class")(_gpghome_def)


def _kill_gpg_agent(root):
    gpg_connect_agent = shutil.which("gpg-connect-agent")
    if gpg_connect_agent:
        gnupghome = root / ".gnupg"
        if not gnupghome.is_dir():
            gnupghome = root
        try:
            subprocess.run(
                [gpg_connect_agent, "killagent", "/bye"],
                env={"GNUPGHOME": str(gnupghome)},
                shell=False,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            # This is likely CentOS 7 or Amazon Linux 2
            pass

    # If the above errored or was not enough, as a last resort, let's check
    # the running processes.
    for proc in psutil.process_iter():
        try:
            if "gpg-agent" in proc.name():
                for arg in proc.cmdline():
                    if str(root) in arg:
                        proc.terminate()
        except Exception:  # pylint: disable=broad-except
            pass
