import logging

import pytest

from tests.conftest import CONTAINER_TARGETS

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
def sdb(modules, secret_mounts):  # pylint: disable=unused-argument
    return modules.sdb


@pytest.fixture
def sdb_runner(master_loaders, secret_mounts):  # pylint: disable=unused-argument
    return master_loaders.runners.sdb


def test_sdb_module(sdb, secret_mount):
    uri = f"sdb://sdbvault/{secret_mount}/test_sdb/foo"
    ret = sdb.set(uri, value="bar")
    assert ret is True
    ret = sdb.get(uri)
    assert ret == "bar"


def test_sdb_runner(sdb_runner, secret_mount):
    uri = f"sdb://sdbvault/{secret_mount}/test_sdb_runner/foo"
    ret = sdb_runner.set(uri, value="bar")
    assert ret is True
    ret = sdb_runner.get(uri)
    assert ret == "bar"
