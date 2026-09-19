import shutil
from pathlib import Path

import pytest
from saltfactories.utils import random_string

from tests.helpers.vault import outdated_cached_config


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


@pytest.fixture
def _cache_server_outdated(minion_conn_cachedir, salt_call_cli):
    def _mutate(cached_config):
        # change server URL
        cached_config["server"]["url"] = "http://127.0.0.1:8"
        cached_config["server"]["url_alts"] = ["http://127.0.0.1:8"]

    with outdated_cached_config(minion_conn_cachedir, salt_call_cli, _mutate):
        yield


@pytest.fixture(scope="module")
def vault_secrets_defaults():
    return {
        "secret/path/foo": {"success": "yeehaaw"},
    }


@pytest.fixture(scope="module")
def overriding_minion(master, issue_overrides):
    assert master.is_running()
    factory = master.salt_minion_daemon(
        random_string("overriding-minion", uppercase=False),
        defaults={"open_mode": True, "grains": {}},
        overrides={"vault": {"issue_params": issue_overrides}},
    )
    with factory.started():
        # Sync All
        salt_call_cli = factory.salt_call_cli()
        ret = salt_call_cli.run("saltutil.sync_all", _timeout=120)
        assert ret.returncode == 0, ret
        yield factory
