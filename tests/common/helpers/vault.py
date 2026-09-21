"""
Shared helpers for the core vault test suites.
"""

from contextlib import contextmanager

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
