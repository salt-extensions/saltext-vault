import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.fixtures.vault_gpg import key_a_fp
from tests.fixtures.vault_gpg import key_a_priv
from tests.fixtures.vault_gpg import key_a_priv_file
from tests.fixtures.vault_gpg import key_a_pub
from tests.fixtures.vault_gpg import key_a_pub_file
from tests.fixtures.vault_gpg import key_b_pub
from tests.functional.modules.test_vault_gpg import _cached_bin
from tests.functional.modules.test_vault_gpg import gpg
from tests.functional.modules.test_vault_gpg import gpg_mount
from tests.functional.modules.test_vault_gpg import gpg_plugin
from tests.functional.modules.test_vault_gpg import gpghome

# pylint: enable=unused-import
from tests.support.gpg import gpg as _gpg
from tests.support.gpg import gpghome as _gpghome
from tests.support.vault import vault_delete
from tests.support.vault import vault_list
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

gpg = pytest.fixture(scope="module")(_gpg)
gpghome = pytest.fixture(scope="module")(_gpghome)


@pytest.fixture
def vault_gpg(states, gpg_mount):  # pylint: disable=unused-argument
    try:
        yield states.vault_gpg
    finally:
        for key in vault_list(f"{gpg_mount}/keys"):
            assert vault_delete(f"{gpg_mount}/keys/{key}")


@pytest.fixture
def existing_key(gpg_mount, request):
    name = "testkey"
    defaults = {
        "real_name": "Salt Test",
        "email": "salt@te.st",
        "comment": "Hello",
        "key_bits": 2048,
        "exportable": False,
    }
    params = getattr(request, "param", {})
    defaults.update(params)
    assert vault_write(f"{gpg_mount}/keys/{name}", generate=True, **defaults)

    try:
        yield name
    finally:
        assert vault_delete(f"{gpg_mount}/keys/{name}")


def test_key_present_create(vault_gpg, testmode, gpg_mount, gpg, salt_version):
    key = vault_read(f"{gpg_mount}/keys/testkey", default=None)
    assert not key
    ret = vault_gpg.key_present(
        "testkey",
        real_name="Salt Test",
        email="salt@te.st",
        comment="Hello",
        key_bits=3192,
        exportable=True,
        mount=gpg_mount,
        test=testmode,
    )
    assert (ret.result is None) is testmode
    assert ("Would have" in ret.comment) is testmode
    assert "reated the key" in ret.comment
    assert ret.changes["created"] == "testkey"
    assert "fingerprint" in ret.changes
    key = vault_read(f"{gpg_mount}/keys/testkey", default=None)
    assert bool(key) is not testmode
    if testmode:
        return
    key = key["data"]
    assert "fingerprint" in key
    assert "public_key" in key
    assert key["exportable"] is True
    assert ret.changes["fingerprint"] == {"old": None, "new": key["fingerprint"]}
    if salt_version[0] >= 3008:
        key_info = gpg.read_key(text=key["public_key"])[0]
        assert key_info["uids"] == ["Salt Test (Hello) <salt@te.st>"]
        assert key_info["keyLength"] == "3192"


def test_key_present_ok(existing_key, vault_gpg, testmode, gpg_mount):
    ret = vault_gpg.key_present(
        existing_key,
        real_name="Salt Test New",
        email="salt@tee.st",
        comment="Hello!",
        key_bits=4096,
        exportable=False,
        mount=gpg_mount,
        test=testmode,
    )
    assert ret.result is True
    assert "already configured" in ret.comment
    assert not ret.changes


@pytest.mark.requires_salt(3008)
def test_key_present_regenerate_changes(
    existing_key, vault_gpg, testmode, gpg_mount, gpg, salt_version
):
    old = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]
    ret = vault_gpg.key_present(
        existing_key,
        real_name="Salt Test New",
        email="salt@tee.st",
        comment="Hello!",
        key_bits=3192,
        exportable=True,
        regenerate=True,
        mount=gpg_mount,
        test=testmode,
    )
    assert (ret.result is None) is testmode
    assert ("Would have" in ret.comment) is testmode
    assert "egenerated the key" in ret.comment
    assert ret.changes
    assert ret.changes["real_name"] == {"old": "Salt Test", "new": "Salt Test New"}
    assert ret.changes["email"] == {"old": "salt@te.st", "new": "salt@tee.st"}
    assert ret.changes["comment"] == {"old": "Hello", "new": "Hello!"}
    assert ret.changes["key_bits"] == {"old": 2048, "new": 3192}
    assert "fingerprint" in ret.changes
    new = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]
    assert "fingerprint" in new
    assert "public_key" in new
    assert (new["exportable"] is True) is not testmode
    if testmode:
        assert ret.changes["fingerprint"] == {"old": old["fingerprint"], "new": "<TBD>"}
    else:
        assert ret.changes["fingerprint"] == {"old": old["fingerprint"], "new": new["fingerprint"]}
    if salt_version[0] >= 3008:
        key_info = gpg.read_key(text=new["public_key"])[0]
        assert (key_info["uids"] == ["Salt Test New (Hello!) <salt@tee.st>"]) is not testmode
        assert (key_info["keyLength"] == "2048") is testmode


@pytest.mark.parametrize(
    "existing_key, exp",
    (
        (
            {"real_name": "Elliot Alderson", "email": None, "comment": None},
            {
                "real_name": {"old": "Elliot Alderson"},
                "email": {"old": ""},
                "comment": {"old": ""},
            },
        ),
        (
            {"real_name": None, "email": "elliot@protonmail.ch", "comment": None},
            {
                "real_name": {"old": ""},
                "email": {"old": "elliot@protonmail.ch"},
                "comment": {"old": ""},
            },
        ),
        (
            {"real_name": None, "email": None, "comment": "Chaos is a ladder"},
            {
                "real_name": {"old": ""},
                "email": {"old": ""},
                "comment": {"old": "Chaos is a ladder"},
            },
        ),
        (
            {"real_name": None, "email": "elliot@protonmail.ch", "comment": "Foo"},
            {
                "real_name": {"old": ""},
                "email": {"old": "elliot@protonmail.ch"},
                "comment": {"old": "Foo"},
            },
        ),
        (
            {"real_name": "Elliot Alderson", "email": "elliot@protonmail.ch", "comment": None},
            {
                "real_name": {"old": "Elliot Alderson"},
                "email": {"old": "elliot@protonmail.ch"},
                "comment": {"old": ""},
            },
        ),
    ),
    indirect=("existing_key",),
)
@pytest.mark.requires_salt(3008)
def test_key_present_regenerate_changes_uid(existing_key, vault_gpg, gpg_mount, exp):
    ret = vault_gpg.key_present(
        existing_key,
        real_name="Salt Test New",
        email="salt@tee.st",
        comment="Hello!",
        key_bits=2048,
        exportable=True,
        regenerate=True,
        mount=gpg_mount,
    )
    exp["real_name"]["new"] = "Salt Test New"
    exp["email"]["new"] = "salt@tee.st"
    exp["comment"]["new"] = "Hello!"
    assert ret.result is True
    assert "Regenerated the key" in ret.comment
    assert ret.changes
    assert ret.changes["real_name"] == exp["real_name"]
    assert ret.changes["email"] == exp["email"]
    assert ret.changes["comment"] == exp["comment"]


@pytest.mark.requires_salt(3008)
def test_key_present_regenerate_ok(existing_key, vault_gpg, testmode, gpg_mount):
    ret = vault_gpg.key_present(
        existing_key,
        real_name="Salt Test",
        email="salt@te.st",
        comment="Hello",
        key_bits=2048,
        exportable=False,
        regenerate=True,
        mount=gpg_mount,
        test=testmode,
    )
    assert ret.result is True
    assert "already configured" in ret.comment
    assert not ret.changes


def test_key_absent_ok(vault_gpg, testmode, gpg_mount):
    ret = vault_gpg.key_absent("missing", mount=gpg_mount, test=testmode)
    assert ret.result is True
    assert "already absent" in ret.comment
    assert not ret.changes


def test_key_absent_changes(existing_key, vault_gpg, testmode, gpg_mount):
    ret = vault_gpg.key_absent(existing_key, mount=gpg_mount, test=testmode)
    assert (ret.result is None) is testmode
    assert ("Would have" in ret.comment) is testmode
    assert "eleted the key" in ret.comment
    assert ret.changes == {"deleted": existing_key}
    key = vault_read(f"{gpg_mount}/keys/{existing_key}", default=None)
    assert bool(key) is testmode


@pytest.mark.requires_salt(3008)
def test_keychain_present(existing_key, vault_gpg, gpg_mount, gpghome, gpg, testmode):
    ret = vault_gpg.keychain_present(
        existing_key, mount=gpg_mount, gnupghome=gpghome, test=testmode
    )
    assert (ret.result is None) is testmode
    assert ("Would have" in ret.comment) is testmode
    assert "dded" in ret.comment
    assert ret.changes
    info = vault_read(f"{gpg_mount}/keys/{existing_key}")["data"]
    keyid = info["fingerprint"][-16:].upper()
    assert keyid in ret.changes
    assert ret.changes[keyid]["added"]
    keys = gpg.list_keys(gnupghome=gpghome)
    assert keys
    assert any(key["fingerprint"] == info["fingerprint"].upper() for key in keys) is not testmode
    if testmode:
        return
    ret2 = vault_gpg.keychain_present(existing_key, mount=gpg_mount, gnupghome=gpghome)
    assert ret2.result is True
    assert not ret2.changes


@pytest.mark.requires_salt(3008)
def test_keychain_present_missing(vault_gpg, gpg_mount, gpghome, testmode):
    ret = vault_gpg.keychain_present("missing", mount=gpg_mount, gnupghome=gpghome, test=testmode)
    assert ret.result in (None, False)
    assert (ret.result is None) is testmode
    assert "does not exist" in ret.comment
    assert ("ignore this message" in ret.comment) is testmode
    assert not ret.changes
