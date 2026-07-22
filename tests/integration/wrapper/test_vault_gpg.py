import ast
import json
import platform
from pathlib import Path

import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_gpg import TestDecrypt as _TestDecrypt
from tests.functional.modules.test_vault_gpg import existing_key
from tests.functional.modules.test_vault_gpg import gpg_mount
from tests.functional.modules.test_vault_gpg import gpghome
from tests.functional.modules.test_vault_gpg import key_a_fp
from tests.functional.modules.test_vault_gpg import key_a_priv
from tests.functional.modules.test_vault_gpg import key_a_priv_file
from tests.functional.modules.test_vault_gpg import key_a_pub
from tests.functional.modules.test_vault_gpg import key_a_pub_file
from tests.functional.modules.test_vault_gpg import key_b_pub
from tests.functional.modules.test_vault_gpg import secret_message_b64
from tests.functional.modules.test_vault_gpg import test_create_key
from tests.functional.modules.test_vault_gpg import test_delete_key
from tests.functional.modules.test_vault_gpg import test_export_private_key
from tests.functional.modules.test_vault_gpg import test_export_private_key_to_file
from tests.functional.modules.test_vault_gpg import test_export_private_key_to_gpg
from tests.functional.modules.test_vault_gpg import test_export_public_key
from tests.functional.modules.test_vault_gpg import test_export_public_key_to_file
from tests.functional.modules.test_vault_gpg import test_export_public_key_to_gpg
from tests.functional.modules.test_vault_gpg import test_import_from_file
from tests.functional.modules.test_vault_gpg import test_import_from_gpg
from tests.functional.modules.test_vault_gpg import test_import_key
from tests.functional.modules.test_vault_gpg import test_list_keys
from tests.functional.modules.test_vault_gpg import test_read_key
from tests.functional.modules.test_vault_gpg import test_sign_verify as _test_sign_verify
from tests.functional.modules.test_vault_gpg import test_sign_verify_path
from tests.functional.modules.test_vault_gpg import tmp_path_

# pylint: enable=unused-import
from tests.support.helpers import WrapperFuncProxy
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_register
from tests.support.vault import vault_read

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "gpg_admin",
                ],
            },
        }
    }


@pytest.fixture(scope="class")
def vault_gpg(salt_ssh_cli, gpg_mount):
    try:
        yield WrapperFuncProxy("vault_gpg", salt_ssh_cli)
    finally:
        for key in vault_list(f"{gpg_mount}/keys"):
            assert vault_delete(f"{gpg_mount}/keys/{key}")


@pytest.fixture(scope="class")
def gpg(minion, gpghome):  # pylint: disable=unused-argument
    return WrapperFuncProxy("gpg", minion.salt_call_cli())


@pytest.fixture(scope="module")
def _check_gnupglib(salt_ssh_cli):
    # Cannot use `pip.list` since it fails in the test suite as well
    # with missing `pkg_resources`.
    ret = salt_ssh_cli.run("--raw", "python3 -m pip list --format=json")
    assert ret.returncode == 0
    assert isinstance(ret.data, dict)
    res = json.loads(ret.data["stdout"])
    for pkg in res:
        if pkg["name"] == "python-gnupg":
            version = tuple(int(x) for x in pkg["version"].split("."))
            break
    else:
        pytest.skip("The host Python does not have python-gnupg")
    return version


@pytest.fixture(scope="module")
def _cached_bin(minion):
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
        ret = minion.salt_call_cli().run(
            "state.single",
            "archive.extracted",
            str(cache_path) + "/",
            source=f"https://github.com/LeSuisse/vault-gpg-plugin/releases/download/v0.6.3/linux_{arch}.zip",
            source_hash="https://github.com/LeSuisse/vault-gpg-plugin/releases/download/v0.6.3/checksums.txt",
            enforce_toplevel=False,
        )
        assert ret.returncode == 0
    assert bin_path.exists()
    if sum_path.exists():
        checksum = sum_path.read_text()
    else:
        ret = minion.salt_call_cli().run("hashutil.digest_file", str(bin_path), checksum="sha256")
        assert ret.returncode == 0
        checksum = ret.data
        sum_path.write_text(checksum)
    return bin_path, checksum


@pytest.fixture(scope="module")
def gpg_plugin(vault_plugins, container, _cached_bin, minion):  # pylint: disable=unused-argument
    bin_path, checksum = _cached_bin
    tgt = vault_plugins / "vault-gpg-plugin"
    try:
        ret = minion.salt_call_cli().run(
            "state.single",
            "file.managed",
            str(tgt),
            source="file://" + str(bin_path),
            mode="0755",
        )
        assert ret.returncode == 0
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


test_import_from_gpg = pytest.mark.usefixtures("_check_gnupglib")(test_import_from_gpg)
test_export_private_key_to_gpg = pytest.mark.usefixtures("_check_gnupglib")(
    test_export_private_key_to_gpg
)
test_export_public_key_to_gpg = pytest.mark.usefixtures("_check_gnupglib")(
    test_export_public_key_to_gpg
)


@pytest.mark.parametrize("encoding", ("base64",))
def test_sign_verify(vault_gpg, gpg_mount, existing_key, encoding):
    _test_sign_verify(vault_gpg, gpg_mount, existing_key, encoding)


@pytest.fixture(scope="class")
def secret_message(gpg_mount, existing_key, gpg, gpghome, key_a_priv_file, key_a_fp, tmp_path_):
    signer_res = gpg.import_key(filename=str(key_a_priv_file), gnupghome=str(gpghome))
    assert signer_res["res"]
    recipient = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]
    secret = "I like turtles"
    rec_pub = tmp_path_ / "rec.pub"
    rec_pub.write_text(recipient["public_key"])
    import_res = gpg.import_key(filename=str(rec_pub), gnupghome=str(gpghome))
    assert import_res["res"]
    # gpg module only returns bytes, which are str()'d by pytest-salt-factories'
    secret_msg = ast.literal_eval(
        gpg.encrypt(
            recipients=recipient["fingerprint"],
            text=secret,
            sign=key_a_fp,
            bare=True,
            always_trust=True,
            gnupghome=str(gpghome),
        )
    )
    assert secret_msg
    return secret_msg.decode()


class TestDecryptWrapper(_TestDecrypt):
    @pytest.mark.parametrize("armor,file", (("none", True), ("base64", False)))
    def test_decode_utf8(
        self, vault_gpg, gpg_mount, existing_key, file, secret_message, tmp_path, armor
    ):
        super().test_decode_utf8(
            vault_gpg, gpg_mount, existing_key, file, secret_message, tmp_path, armor
        )

    def test_decode_base64(self, *_, **__):
        pytest.skip("Salt-SSH can't handle byte returns")

    @pytest.mark.requires_salt(3007)
    @pytest.mark.usefixtures("_check_gnupglib")
    def test_signer_key_fingerprint(
        self, vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_fp, gpghome
    ):
        super().test_signer_key_fingerprint(
            vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_fp, gpghome
        )
