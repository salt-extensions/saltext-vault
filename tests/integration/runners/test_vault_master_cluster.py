import logging
import subprocess

import pytest
import salt.utils.platform
import salt.version

pytest.importorskip("docker")

log = logging.getLogger(__name__)
salt_version = int(salt.version.__version__.split(".")[0])

pytestmark = [
    pytest.mark.slow_test,
    pytest.mark.skip_if_binaries_missing("vault", "getent"),
    pytest.mark.skipif(salt_version < 3007, reason="Master cluster requires Salt 3007+"),
    pytest.mark.usefixtures("vault_container_version", "vault_testing_values"),
    pytest.mark.parametrize("vault_container_version", ("latest",), indirect=True),
]


@pytest.fixture(scope="module")
def vault_master_config(vault_port):
    return {
        "open_mode": True,
        "ext_pillar": [{"vault": "secret/path/foo"}],
        "peer_run": {
            ".*": [
                "vault.get_config",
                "vault.generate_new_token",
            ],
        },
        "vault": {
            "auth": {"token": "testsecret"},
            "cache": {
                "backend": "file",
            },
            "issue": {
                "type": "token",
                "token": {
                    "params": {
                        "num_uses": 0,
                    }
                },
            },
            "policies": {
                "assign": [
                    "salt_minion",
                    "salt_minion_{minion}",
                    "salt_role_{pillar[roles]}",
                ],
                "cache_time": 0,
            },
            "server": {
                "url": f"http://127.0.0.1:{vault_port}",
            },
        },
        "minion_data_cache": True,
    }


@pytest.fixture(scope="module")
def cluster_shared_path(tmp_path_factory):
    return tmp_path_factory.mktemp("cluster")


@pytest.fixture(scope="module")
def cluster_pki_path(cluster_shared_path):
    path = cluster_shared_path / "pki"
    path.mkdir()
    (path / "peers").mkdir()
    return path


@pytest.fixture(scope="module")
def cluster_cache_path(cluster_shared_path):
    path = cluster_shared_path / "cache"
    path.mkdir()
    return path


@pytest.fixture(scope="module")
def cluster_master_1(salt_factories, cluster_pki_path, cluster_cache_path, vault_master_config):
    config_overrides = {
        "interface": "127.0.0.1",
        "cluster_id": "master_cluster",
        "cluster_peers": [
            "127.0.0.2",
            "127.0.0.3",
        ],
        "cluster_pki_dir": str(cluster_pki_path),
        "cache_dir": str(cluster_cache_path),
    }
    factory = salt_factories.salt_master_daemon(
        "127.0.0.1",
        defaults=vault_master_config,
        overrides=config_overrides,
        extra_cli_arguments_after_first_start_failure=["--log-level=info"],
    )
    with factory.started(start_timeout=120):
        yield factory


@pytest.fixture(scope="module")
def cluster_master_2(salt_factories, cluster_master_1, vault_master_config):
    if salt.utils.platform.is_darwin() or salt.utils.platform.is_freebsd():
        subprocess.check_output(["ifconfig", "lo0", "alias", "127.0.0.2", "up"])

    config_overrides = {
        "interface": "127.0.0.2",
        "cluster_id": "master_cluster",
        "cluster_peers": [
            "127.0.0.1",
            "127.0.0.3",
        ],
        "cluster_pki_dir": cluster_master_1.config["cluster_pki_dir"],
        "cache_dir": cluster_master_1.config["cache_dir"],
    }

    # Use the same ports for both masters, they are binding to different interfaces
    for key in (
        "ret_port",
        "publish_port",
    ):
        config_overrides[key] = cluster_master_1.config[key]
    factory = salt_factories.salt_master_daemon(
        "127.0.0.2",
        defaults=vault_master_config,
        overrides=config_overrides,
        extra_cli_arguments_after_first_start_failure=["--log-level=info"],
    )
    with factory.started(start_timeout=120):
        yield factory


@pytest.fixture(scope="module")
def cluster_minion_1(cluster_master_1, vault_master_config):
    port = cluster_master_1.config["ret_port"]
    addr = cluster_master_1.config["interface"]
    config_overrides = {
        "master": f"{addr}:{port}",
    }
    factory = cluster_master_1.salt_minion_daemon(
        "cluster-minion-1",
        defaults=vault_master_config,
        overrides=config_overrides,
        extra_cli_arguments_after_first_start_failure=["--log-level=info"],
    )
    with factory.started(start_timeout=120):
        yield factory


@pytest.fixture
def salt_call_cli(cluster_minion_1):
    return cluster_minion_1.salt_call_cli(timeout=120)


def test_minion_can_authenticate(salt_call_cli):
    ret = salt_call_cli.run("vault.read_secret", "secret/path/foo")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"


def test_minion_pillar_is_populated_as_expected(salt_call_cli):
    ret = salt_call_cli.run("pillar.items")
    assert ret.returncode == 0
    assert ret.data
    assert ret.data.get("success") == "yeehaaw"
