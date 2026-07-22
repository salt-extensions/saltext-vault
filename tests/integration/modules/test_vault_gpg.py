import platform
from pathlib import Path

import pytest

from tests.conftest import CONTAINER_TARGETS

# pylint: disable=unused-import
from tests.functional.modules.test_vault_gpg import existing_key
from tests.functional.modules.test_vault_gpg import gpg_mount

# pylint: enable=unused-import
from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_register

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "vault_policies"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]


@pytest.fixture(scope="module")
def master_config_overrides():
    return {
        "vault": {
            "policies": {
                "assign": [
                    "salt_minion",
                    "gpg_sign_fallback",  # this fails to sign on the general API and should use the algo-specific ones
                ],
            },
        }
    }


@pytest.fixture(scope="module")
def _cached_bin(minion):
    """
    Cache this plugin outside of test run-specific directories
    to avoid repeated downloads.
    """
    machine = platform.machine()
    if machine in {"arm64", "aarch64"}:
        arch = "arm64"
    elif machine in {"amd64", "x86_64"}:
        arch = "amd64"
    else:
        return pytest.skip("Architecture not accounted for in gnupg plugin setup")
    cache_path = Path(f"/tmp/saltext-vault-testsuite/vault-gpg-plugin/0.6.3/linux_{arch}")
    bin_path = cache_path / "vault-gpg-plugin"
    sum_path = bin_path.with_suffix(".sum")
    if not cache_path.exists():
        cache_path.mkdir(parents=True)
    if not bin_path.exists():
        # For Docker Desktop, macOS needs Linux binary as well.
        ret = minion.salt_call_cli().run(
            "state.single",
            "archive.extracted",
            str(cache_path) + "/",
            source=f"https://github.com/LeSuisse/vault-gpg-plugin/releases/download/v0.6.3/linux_{arch}.zip",
            source_hash="https://github.com/LeSuisse/vault-gpg-plugin/releases/download/v0.6.3/checksums.txt",
            enforce_toplevel=False,
        )
        assert ret.returncode == 0
    assert bin_path.exists()
    if sum_path.exists():
        checksum = sum_path.read_text()
    else:
        ret = minion.salt_call_cli().run("hashutil.digest_file", str(bin_path), checksum="sha256")
        assert ret.returncode == 0
        checksum = ret.data
        sum_path.write_text(checksum)
    return bin_path, checksum


@pytest.fixture(scope="module")
def gpg_plugin(vault_plugins, container, _cached_bin, minion):  # pylint: disable=unused-argument
    bin_path, checksum = _cached_bin
    tgt = vault_plugins / "vault-gpg-plugin"
    try:
        ret = minion.salt_call_cli().run(
            "state.single",
            "file.managed",
            str(tgt),
            source="file://" + str(bin_path),
            mode="0755",
        )
        assert ret.returncode == 0
        reg = {
            "name": "gpg",
            "plugin_type": "secret",
            "sha256": checksum,
            "command": "vault-gpg-plugin",
            "version": "v0.6.3",
        }
        assert vault_plugin_register(**reg)
        yield
    finally:
        vault_plugin_deregister("secret", "gpg", version="v0.6.3")
        tgt.unlink(missing_ok=True)


def test_sign_fallback(salt_call_cli, gpg_mount, existing_key):
    salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
    res = salt_call_cli.run(
        "vault_gpg.sign", existing_key, "Boop", encoding="ascii-armor", mount=gpg_mount
    )
    assert res.returncode == 0
    assert res.data
    assert isinstance(res.data, str)
    assert res.data.startswith("-----BEGIN PGP SIGNATURE")
