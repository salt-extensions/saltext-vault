import shutil
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def _minion_conn_cachedir(minion):
    ret = minion.salt_call_cli().run("config.get", "cachedir")
    assert ret.returncode == 0
    assert ret.data
    return Path(ret.data) / "vault" / "connection"


@pytest.fixture
def minion_conn_cachedir(_minion_conn_cachedir):
    if not _minion_conn_cachedir.exists():
        _minion_conn_cachedir.mkdir(parents=True)
    return _minion_conn_cachedir


@pytest.fixture
def conn_cache_absent(minion_conn_cachedir):
    if minion_conn_cachedir.exists():
        shutil.rmtree(minion_conn_cachedir)
        assert not minion_conn_cachedir.exists()
    yield


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/path/foo": {"success": "yeehaaw"},
    }
