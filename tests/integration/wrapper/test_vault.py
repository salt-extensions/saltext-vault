import pytest

from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_list_policies
from tests.support.vault import vault_read_secret
from tests.support.vault import vault_write_policy
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.usefixtures("vault_container_version"),
    pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True),
]


@pytest.fixture(scope="module")
def master_config_overrides():
    """
    You can override the default configuration per package by overriding this
    fixture in a conftest.py file.
    """
    return {
        "vault": {
            "cache": {
                "backend": "disk",
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "policy_admin",
                ],
            },
        }
    }


@pytest.fixture
def existing_secret():
    key = "secret/foo"
    vault_write_secret(key, user="foo", password="bar")
    try:
        yield key
    finally:
        vault_delete_secret(key, metadata=True)


@pytest.fixture
def existing_secret_version(existing_secret):
    vault_write_secret(existing_secret, user="foo", password="hunter1")
    yield existing_secret


def test_read_secret(salt_ssh_cli, existing_secret):
    ret = salt_ssh_cli.run("vault.read_secret", existing_secret)
    assert ret.returncode == 0
    assert ret.data == {"user": "foo", "password": "bar"}


def test_write_secret(salt_ssh_cli, existing_secret):
    ret = salt_ssh_cli.run("vault.write_secret", existing_secret, bar="baz")
    assert ret.returncode == 0
    new = vault_read_secret(existing_secret)
    assert new == {"bar": "baz"}


def test_write_raw(salt_ssh_cli, existing_secret):
    ret = salt_ssh_cli.run("vault.write_raw", existing_secret, {"bar": "baz"})
    assert ret.returncode == 0
    new = vault_read_secret(existing_secret)
    assert new == {"bar": "baz"}


def test_patch_secret(salt_ssh_cli, existing_secret):
    ret = salt_ssh_cli.run("vault.patch_secret", existing_secret, bar="baz")
    assert ret.returncode == 0
    new = vault_read_secret(existing_secret)
    assert new == {"user": "foo", "password": "bar", "bar": "baz"}


def test_delete_secret(salt_ssh_cli, existing_secret):
    ret = salt_ssh_cli.run("vault.delete_secret", existing_secret)
    assert ret.returncode == 0
    assert vault_read_secret(existing_secret) is None


@pytest.mark.usefixtures("existing_secret")
def test_list_secrets(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault.list_secrets", "secret", keys_only=True)
    assert ret.returncode == 0
    assert ret.data == ["foo"]


def test_clear_cache(salt_ssh_cli):
    """
    Ensure that the revocation client also respects Salt-SSH master opts
    and does not crash with InvalidConfig.
    """
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    token_id = ret.data["data"]["id"]
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data["data"]["id"] == token_id
    ret = salt_ssh_cli.run("vault.clear_cache")
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_ssh_cli.run("vault.query", "GET", "auth/token/lookup-self")
    assert ret.returncode == 0
    assert ret.data["data"]["id"] != token_id


def test_policies_list(salt_ssh_cli):
    ret = salt_ssh_cli.run("vault.policies_list")
    assert ret.returncode == 0
    assert isinstance(ret.data, list)
    for policy in ("database_admin", "policy_admin", "salt_master", "salt_minion"):
        assert policy in ret.data


@pytest.fixture
def _cleanup_dummy_policy():
    yield
    vault_delete_policy("foobar")


@pytest.fixture
def _dummy_policy_contents():
    return """
path "foobar/*" {
    capabilities = ["read", "create", "update", "delete", "list", "patch"]
}
    """.strip()


@pytest.fixture
def _dummy_policy(_dummy_policy_contents, _cleanup_dummy_policy):  # pylint: disable=unused-argument
    name = "foobar"
    vault_write_policy(name, _dummy_policy_contents)
    yield name


@pytest.mark.usefixtures("_cleanup_dummy_policy")
def test_policy_write(salt_ssh_cli, _dummy_policy_contents):
    assert "foobar" not in vault_list_policies()
    ret = salt_ssh_cli.run("vault.policy_write", "foobar", _dummy_policy_contents)
    assert ret.returncode == 0
    assert ret.data is True
    assert "foobar" in vault_list_policies()


def test_policy_fetch(salt_ssh_cli, _dummy_policy, _dummy_policy_contents):
    ret = salt_ssh_cli.run("vault.policy_fetch", _dummy_policy)
    assert ret.returncode == 0
    assert ret.data == _dummy_policy_contents


def test_policy_delete(salt_ssh_cli, _dummy_policy):
    ret = salt_ssh_cli.run("vault.policy_delete", _dummy_policy)
    assert ret.returncode == 0
    assert ret.data is True
