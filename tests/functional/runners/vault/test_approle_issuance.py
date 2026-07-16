import logging
import sys
from unittest.mock import patch

import pytest

from tests.support.vault import vault_delete_approle
from tests.support.vault import vault_list
from tests.support.vault import vault_read

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
]

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_overrides(vault_port):
    return {
        "vault": {
            "auth": {
                "method": "token",
                "token": "testsecret",
            },
            "issue": {
                "type": "approle",
                "approle": {
                    "params": {
                        "secret_id_ttl": "1h",
                        "token_explicit_max_ttl": "1h",
                    }
                },
                "allow_minion_override_params": True,
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        }
    }


def _get_approle(name):
    return vault_read(f"auth/salt-minions/role/{name}", raise_errors=True)["data"]


def _get_config(vault, name, impersonated_by_master=False, issue_params=None):
    config = vault.get_config(
        name, signature="", impersonated_by_master=impersonated_by_master, issue_params=issue_params
    )
    assert "error" not in config
    assert all(key in config for key in ("auth", "cache", "client", "server"))
    assert config["auth"]["method"] == "approle"
    assert "role_id" in config["auth"]
    assert "secret_id" in config["auth"]
    assert isinstance(config["auth"]["secret_id"], bool)
    return config


def _generate_secret_id(vault, name, impersonated_by_master=False, issue_params=None):
    secret_id = vault.generate_secret_id(
        name, signature="", impersonated_by_master=impersonated_by_master, issue_params=issue_params
    )
    assert "error" not in secret_id
    assert "server" in secret_id
    assert secret_id["data"] or "wrap_info" in secret_id
    return secret_id


@pytest.fixture(autouse=True)
def reset_approles():
    for approle in vault_list("auth/salt-minions/role"):
        vault_delete_approle(approle, mount="salt-minions")
    yield
    for approle in vault_list("auth/salt-minions/role"):
        vault_delete_approle(approle, mount="salt-minions")


@pytest.fixture(autouse=True)
def vault(runners, loaders):
    runner = runners.vault
    with patch.object(
        sys.modules[f"{loaders.loaded_base_name}.ext.runners.vault"], "_validate_signature"
    ):
        yield runner


def test_get_config_and_generate_secret_id_do_not_rewrite_approle_with_timestring_config(
    vault, loaders
):
    """
    The Vault server always reports seconds in ttl config values.
    If ttl values like secret_id_ttl are configured via a time string like 1h,
    the runner should recognize that 1h equals 3600s and not rewrite the approle.
    """
    _get_config(vault, "foobar")
    # make _manage_approle raise an exception if called
    with patch.object(
        sys.modules[f"{loaders.loaded_base_name}.ext.runners.vault"],
        "_manage_approle",
        side_effect=RuntimeError,
    ):
        _get_config(vault, "foobar")
        _generate_secret_id(vault, "foobar")


def test_get_config_and_generate_secret_id_rewrite_approle_when_necessary(vault):
    _get_config(vault, "foobar", issue_params={"secret_id_ttl": "1d"})
    approle = _get_approle("foobar")
    assert approle["secret_id_ttl"] == 86400
    _generate_secret_id(vault, "foobar", issue_params={"secret_id_ttl": "1h"})
    approle = _get_approle("foobar")
    assert approle["secret_id_ttl"] == 3600
