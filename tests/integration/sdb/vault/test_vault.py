import logging

import pytest

from tests.conftest import CONTAINER_TARGETS
from tests.support.vault import vault_delete_secret
from tests.support.vault import vault_write_secret

pytest.importorskip("docker")

log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(params=("secret", "secret-v1"))
def secret_mount(request):
    return request.param


def test_sdb_kv_kvv2_path_local(salt_call_cli):
    ret = salt_call_cli.run(
        "--local",
        "sdb.set",
        uri="sdb://sdbvault/salt/test/test_sdb_local/foo",
        value="local",
    )
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_call_cli.run("--local", "sdb.get", "sdb://sdbvault/salt/test/test_sdb_local/foo")
    assert ret.data
    assert ret.data == "local"


@pytest.fixture
def _kv_root_dual_item(container):  # pylint: disable=unused-argument
    vault_write_secret("salt/user1", password="p4ssw0rd", desc="test user")
    vault_write_secret("salt/user/user1", password="p4ssw0rd", desc="test user")
    try:
        yield
    finally:
        vault_delete_secret("salt/user1", metadata=True)
        vault_delete_secret("salt/user/user1", metadata=True)


@pytest.mark.usefixtures("_kv_root_dual_item")
def test_sdb_kv_dual_item(salt_call_cli):
    ret = salt_call_cli.run("--local", "sdb.get", "sdb://sdbvault/salt/data/user1")
    assert ret.data
    assert ret.data == {"desc": "test user", "password": "p4ssw0rd"}


def test_sdb_runner(salt_run_cli, secret_mount):
    ret = salt_run_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb_runner/foo", value="runner"
    )
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_run_cli.run("sdb.get", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb_runner/foo")
    assert ret.returncode == 0
    assert ret.stdout
    assert ret.stdout == "runner"


def test_sdb(salt_call_cli, secret_mount):
    ret = salt_call_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb/foo", value="bar"
    )
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_call_cli.run("sdb.get", uri=f"sdb://sdbvault/{secret_mount}/test/test_sdb/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data == "bar"


@pytest.fixture(scope="module")
def pillar_defaults():
    return {
        "sdb": {
            "test_vault_pillar_sdb": "sdb://sdbvault/secret/test/test_pillar_sdb/foo",
        }
    }


@pytest.mark.usefixtures("pillar_base")
def test_config_get(salt_call_cli, secret_mount):
    ret = salt_call_cli.run(
        "sdb.set", uri=f"sdb://sdbvault/{secret_mount}/test/test_pillar_sdb/foo", value="baz"
    )
    assert ret.returncode == 0
    assert ret.data is True
    ret = salt_call_cli.run("config.get", "test_vault_pillar_sdb")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data == "baz"
