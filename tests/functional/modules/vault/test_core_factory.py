import logging
from pathlib import Path

import pytest

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "secret_mounts", "vault_secrets"),
]

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {"secret/foo": {"bar": "baz"}}


@pytest.fixture
def vault(modules, vault_secrets):  # pylint: disable=unused-argument
    return modules.vault


@pytest.fixture(scope="module")
def minion_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "disk",
            }
        }
    }


@pytest.fixture
def minion_cache(minion):
    return Path(minion.config["cachedir"]) / "vault"


def test_query(vault, minion):
    res = vault.query("GET", "auth/token/lookup-self")
    assert res
    assert res["data"]["id"] == minion.config["vault"]["auth"]["token"]
    accessor = res["data"]["accessor"]
    res = vault.query("POST", "auth/token/lookup-accessor", {"accessor": accessor})
    assert "root" in res["data"]["policies"]


def test_get_server_config(vault, minion):
    res = vault.get_server_config()
    assert "url" in res
    assert "url_alts" in res
    assert "namespace" in res
    assert "verify" in res
    for conf, val in res.items():
        default = None
        if conf == "url_alts":
            default = [minion.config["vault"]["server"]["url"]]
        assert val == minion.config["vault"]["server"].get(conf, default)


def test_clear_cache(vault, minion_cache):
    token_cache = minion_cache / "connection" / "session" / "__token.p"
    metadata_cache = minion_cache / "connection" / "secret_path_metadata.p"

    def _assert_exists(tok, meta):
        assert token_cache.exists() is tok
        assert metadata_cache.exists() is meta

    vault.read_secret("secret/foo")
    _assert_exists(True, True)
    vault.clear_cache(session=True)
    _assert_exists(False, True)
    vault.query("GET", "auth/token/lookup-self")
    _assert_exists(True, True)
    vault.clear_cache()
    _assert_exists(False, False)
    vault.read_secret("secret/foo")
    vault.clear_token_cache()  # test deprecated alias
    _assert_exists(False, False)
    vault.read_secret("secret/foo")
    _assert_exists(True, True)
    vault.clear_cache(connection=False)
    _assert_exists(False, False)


def test_update_config(vault):
    # This does nothing when local config is in use
    assert vault.update_config() is True
