import logging

import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "_cleanup"),
    pytest.mark.parametrize(
        "secret_mounts",
        [[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
        indirect=True,
    ),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture
def vault(loaders, secret_mounts):  # pylint: disable=unused-argument
    return loaders.sdb.vault


@pytest.mark.parametrize(
    "key",
    (
        "some/nested_item/key",
        "root_item/root_key",
        "questionmark/nested_item?key",
        "questionmark_root?item",
    ),
)
def test_set_get(vault, secret_mount, key):
    key = f"{secret_mount}/{key}"
    vault_path, data_key = _split(key)
    vault.set(key, "success")
    assert vault_read_secret(vault_path) == {data_key: "success"}
    assert vault.get(key) == "success"


@pytest.mark.parametrize(
    "key",
    (
        "some/nested_item/key",
        "root_item/root_key",
        "questionmark/nested_item?key",
        "questionmark_root?item",
    ),
)
@pytest.mark.parametrize("patch", (False, True))
def test_set_patch(vault, secret_mount, key, patch):
    key = f"{secret_mount}/{key}"
    vault_path, data_key = _split(key)
    vault.set(key, "success", {"patch": patch})
    vault.set(f"{vault_path}/other_{data_key}", "patched", {"patch": patch})
    if patch:
        assert vault_read_secret(vault_path) == {
            f"other_{data_key}": "patched",
            data_key: "success",
        }
    else:
        assert vault_read_secret(vault_path) == {f"other_{data_key}": "patched"}


@pytest.fixture
def _whole_secret_values(secret_mount):
    paths = ("root_item", "nested/item")
    data = {"password": "p4ssw0rd", "desc": "test_user"}
    ret = []
    for path in paths:
        full = f"{secret_mount}/{path}"
        vault_write_secret(full, **data)
        ret.append(full)
    return tuple(ret), data


@pytest.mark.usefixtures("secret_mount")
def test_get_whole_secret(vault, _whole_secret_values):
    paths, data = _whole_secret_values
    for path in paths:
        assert vault.get(path) == data


@pytest.fixture
def _shadowed_values():
    path = "secret/foo/bar/baz"
    vault_write_secret(path, baz="success", other_val="hi")
    return path


def test_get_shadowed_path(vault, _shadowed_values):
    """
    Show that the syntax using slashes is not injective (i.e. secrets can be shadowed).
    Consider introducing an option that requires the ...?secret_key syntax, which prevents this problem.
    """
    res = vault.get(_shadowed_values)
    assert res == {"baz": "success", "other_val": "hi"}
    new_path, key = _split(_shadowed_values)
    vault_write_secret(new_path, **{key: "shadowed"})
    res = vault.get(_shadowed_values)
    assert res == "shadowed"


def _split(key):
    if "?" in key:
        pos = key.rfind("?")
    else:
        pos = key.rfind("/")
    return key[:pos], key[pos + 1 :]
