import ast
import json

import pytest

from tests.common import CliFuncProxy
from tests.common import gen_master_opts
from tests.common.containers import genmarks

# pylint: disable=unused-import
from tests.common.fixtures.vault_gpg import cached_vault_gpg_bin
from tests.common.fixtures.vault_gpg import clean_gpg_keys
from tests.common.fixtures.vault_gpg import existing_key
from tests.common.fixtures.vault_gpg import gpg_mount
from tests.common.fixtures.vault_gpg import gpg_plugin
from tests.common.fixtures.vault_gpg import gpghome
from tests.common.fixtures.vault_gpg import key_a_fp
from tests.common.fixtures.vault_gpg import key_a_priv
from tests.common.fixtures.vault_gpg import key_a_priv_file
from tests.common.fixtures.vault_gpg import key_a_pub
from tests.common.fixtures.vault_gpg import key_a_pub_file
from tests.common.fixtures.vault_gpg import key_b_pub
from tests.common.fixtures.vault_gpg import tmp_path_
from tests.functional.modules.test_vault_gpg import TestDecrypt as _TestDecrypt
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

# pylint: enable=unused-import
from tests.support.vault import vault_read

pytestmark = genmarks("clean_gpg_keys", internal_logic=True, policies=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    return gen_master_opts(policies="gpg_admin")


@pytest.fixture(scope="class")
def vault_gpg(salt_ssh_cli, gpg_mount):  # pylint: disable=unused-argument
    return CliFuncProxy(salt_ssh_cli).vault_gpg


@pytest.fixture(scope="class")
def gpg(minion, gpghome):  # pylint: disable=unused-argument
    return CliFuncProxy(minion.salt_call_cli()).gpg


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

    @pytest.mark.skip("Salt-SSH can't handle byte returns")
    def test_decode_base64(self, *_, **__):
        pass

    @pytest.mark.requires_salt(3007)
    @pytest.mark.usefixtures("_check_gnupglib")
    def test_signer_key_fingerprint(
        self, vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_fp, gpghome
    ):
        super().test_signer_key_fingerprint(
            vault_gpg, gpg_mount, existing_key, secret_message_b64, key_a_fp, gpghome
        )
