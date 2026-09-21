import logging

import pytest

from tests.common.containers import genmarks

pytestmark = genmarks(
    "_cleanup",
    internal_logic_only=True,
    mounts=[[("kv", "secret-v1", "-version=1"), ("kv", "secret", "-version=2")]],
)

log = logging.getLogger(__name__)


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
