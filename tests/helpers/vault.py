"""
Shared helpers for the core vault test suites.
"""

import json
from contextlib import contextmanager

import pytest
import salt.utils.data
import salt.utils.files
import salt.utils.msgpack


def clear_auth_cache(minion_conn_cachedir):
    token_cachefile = minion_conn_cachedir / "session" / "__token.p"
    secret_id_cachefile = minion_conn_cachedir / "secret_id.p"
    for file in (secret_id_cachefile, token_cachefile):
        if file.exists():
            file.unlink()


@contextmanager
def outdated_cached_config(minion_conn_cachedir, salt_call_cli, mutate, clear_auth=True):
    """
    Overwrite the minion's cached Vault configuration with the result of
    ``mutate(cached_config)`` (in-place mutation or returned replacement),
    optionally clearing cached auth credentials as well.
    Yields the configuration as read from the cache.
    """
    config_cachefile = minion_conn_cachedir / "config.p"
    if not config_cachefile.exists():
        salt_call_cli.run("vault.query", "GET", "auth/token/lookup-self")
        assert config_cachefile.exists()
    cached_config = salt.utils.data.decode(salt.utils.msgpack.loads(config_cachefile.read_bytes()))
    new_config = mutate(cached_config) or cached_config
    config_msgpack = salt.utils.msgpack.dumps(new_config)
    with salt.utils.files.fopen(config_cachefile, "wb") as f:
        f.write(config_msgpack)
    if clear_auth:
        clear_auth_cache(minion_conn_cachedir)
    try:
        yield cached_config
    finally:
        if config_cachefile.exists():
            config_cachefile.unlink()


def check_cryptography(salt_ssh_cli, minimum, modules):
    """
    Skip when the host Python's cryptography library is missing or older
    than ``minimum`` (version tuple). Returns the installed version.
    """
    # Cannot use `pip.list` since it fails in the test suite as well
    # with missing `pkg_resources`.
    ret = salt_ssh_cli.run("--raw", "python3 -m pip list --format=json")
    assert ret.returncode == 0
    assert isinstance(ret.data, dict)
    res = json.loads(ret.data["stdout"])
    for pkg in res:
        if pkg["name"] == "cryptography":
            version = tuple(int(x) for x in pkg["version"].split("."))
            break
    else:
        pytest.skip("The host Python does not have cryptography")
    if version < minimum:
        minimum_str = ".".join(str(x) for x in minimum)
        pytest.skip(
            f"The {modules} modules require at least cryptography v{minimum_str} on the host. "
            f"Installed: {'.'.join(str(x) for x in version)}"
        )
    return version
