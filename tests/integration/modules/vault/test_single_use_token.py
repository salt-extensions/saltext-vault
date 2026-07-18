import logging

import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_list_secrets
from tests.support.vault import vault_read_secret

pytest.importorskip("docker")

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "pillar_base", "vault_secrets"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/test/jvmdump/ssh_key": {"public_key": "yup_dump"},
        "secret/test/jenkins/master/ssh_key": {"public_key": "yup_master"},
        "secret/test/deleteme": {"pls": ":)"},
    }


@pytest.fixture(scope="module")
def pillar_defaults():
    return {
        "testvault": {
            "test": {
                # Access Vault twice in the same pillar file
                "foo": "bar",
                "jvmdump_pubkey": "{{ salt['vault.read_secret']('secret/test/jvmdump/ssh_key', 'public_key') }}",
                "jenkins_pubkey": "{{ salt['vault.read_secret']('secret/test/jenkins/master/ssh_key', 'public_key') }}",
            }
        }
    }


@pytest.fixture(scope="module", autouse=True)
def _cleanup(container):  # pylint: disable=unused-argument
    try:
        yield
    finally:
        vault_delete_secret("secret/test/write", metadata=True)


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "cache": {
                "backend": "file",
            },
            "issue": {
                "token": {
                    "params": {
                        "num_uses": 1,
                    }
                }
            },
        }
    }


def test_vault_read_secret(salt_call_cli):
    """
    Test that the Vault module can fetch a single secret when tokens
    are issued with uses=1.
    """
    ret = salt_call_cli.run("vault.read_secret", "secret/test/jvmdump/ssh_key")
    assert ret.returncode == 0
    assert ret.data == {"public_key": "yup_dump"}


def test_vault_read_secret_can_fetch_more_than_one_secret_in_one_run(
    salt_call_cli,
    caplog,
    salt_version,
):
    """
    Test that the Vault module can fetch multiple secrets during
    a single run when tokens are issued with uses=1.
    Salt core issue #57561
    """
    ret = salt_call_cli.run("saltutil.refresh_pillar", wait=True)
    assert ret.returncode == 0
    assert ret.data is True
    if salt_version[0] >= 3008:
        ret = salt_call_cli.run("pillar.items", unmask=True)
    else:
        ret = salt_call_cli.run("pillar.items")
    assert ret.returncode == 0
    assert ret.data
    assert "Pillar render error" not in caplog.text
    assert "test" in ret.data
    assert "jvmdump_pubkey" in ret.data["test"]
    assert ret.data["test"]["jvmdump_pubkey"] == "yup_dump"
    assert "jenkins_pubkey" in ret.data["test"]
    assert ret.data["test"]["jenkins_pubkey"] == "yup_master"


def test_vault_write_secret(salt_call_cli):
    """
    Test that the Vault module can write a single secret when tokens
    are issued with uses=1.
    """
    ret = salt_call_cli.run("vault.write_secret", "secret/test/write", success="yup")
    assert ret.returncode == 0
    assert ret.data
    assert "write" in vault_list_secrets("secret/test")


def test_vault_delete_secret(salt_call_cli):
    """
    Test that the Vault module can delete a single secret when tokens
    are issued with uses=1.
    """
    ret = salt_call_cli.run("vault.delete_secret", "secret/test/deleteme")
    assert ret.returncode == 0
    assert ret.data
    assert vault_read_secret("secret/test/deleteme") is None
