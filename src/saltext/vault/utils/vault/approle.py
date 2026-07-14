"""
Vault approle helpers

.. versionadded:: 1.8.0
"""

import fnmatch
import logging
import typing

from salt.exceptions import CommandExecutionError

from saltext.vault.utils.vault import cache as vcache
from saltext.vault.utils.vault import helpers as hlp
from saltext.vault.utils.vault import leases as vleases
from saltext.vault.utils.vault.exceptions import VaultException
from saltext.vault.utils.vault.exceptions import VaultInvocationError
from saltext.vault.utils.vault.exceptions import VaultNotFoundError
from saltext.vault.utils.vault.exceptions import VaultPermissionDeniedError
from saltext.vault.utils.vault.factory import get_approle_api

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils.vault import api as vapi


log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore


def get_store(opts: dict[str, typing.Any], context: dict[str, typing.Any]) -> "SecretIdStore":
    """
    Return an instance of SecretIdStore.

    opts
        Pass ``__opts__``.

    context
        Pass ``__context__``.
    """
    opts = hlp.check_salt_ssh_opts(opts)
    try:
        api, config = get_approle_api(opts, context, get_config=True)
    except VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    vault_cbank = vcache._get_cache_bank(opts)
    cache = vcache.VaultLeaseCache(
        context,
        vault_cbank + "/secid",
        cache_backend=vcache._get_cache_backend(config, opts),
        lease_cls=vleases.VaultSecretId,
    )
    return SecretIdStore(api, cache)


def create_cache_pattern(
    name: str | None = None,
    cache: str | typing.Literal[True] | None = None,
    mount: str | None = None,
) -> str:
    """
    Render a match pattern for operating on cached leases.
    Unset parameters result in a ``*`` glob.

    name
        Name of the database role.

    cache
        Filter by cache name (refer to get_secret_id for details).

    mount
        Mount path the associated database backend is mounted to.
    """
    ptrn = ["secid"]
    ptrn.append("*" if mount is None else mount)
    ptrn.append("*" if name is None else name)
    if cache is True:
        ptrn.append("default")
    elif cache:
        ptrn.append(cache)
    else:
        ptrn.append("*")
    return ".".join(ptrn)


class SecretIdStore:
    """
    Caches SecretIDs and handles revocation
    """

    def __init__(
        self, api: "vapi.AppRoleApi", cache: vcache.VaultLeaseCache[vleases.VaultSecretId]
    ):
        self.api = api
        self.cache = cache

    def get(
        self,
        ckey: str,
        valid_for: int | str = 0,
        destroy: bool = True,
    ) -> vleases.VaultSecretId | None:
        """
        Return a valid cached SecretID or None.

        ckey
            Cache key the SecretID has been saved in.

        valid_for
            Ensure the returned SecretID or wrapping token is valid for at least
            this amount of time.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        destroy
            If the SecretID is invalid or not valid for ``valid_for``,
            attempt to destroy it if possible and flush the cache.
            Defaults to true.
        """
        # Since we need to destroy SecretIDs, do not check for future validity in cache
        secid = self.cache.get(ckey, flush=destroy)
        if secid is None:
            return None
        meta = self._lookup(secid, ckey, destroy)
        if meta is None:
            return None
        if meta.is_valid_for(valid_for):
            return secid
        if destroy:
            self.destroy_cached(ckey)
        return None

    def _list_cached_secids(
        self, match: str = "*", flush: bool = False
    ) -> list[tuple[str, vleases.VaultSecretId]]:
        """
        Helper for functions that operate on the cached SecretIDs.
        """
        secids = []
        for ckey in self.list():
            if not fnmatch.fnmatch(ckey, match):
                continue
            secid = self.cache.get(ckey, flush=flush)
            if secid is None:
                continue
            secids.append((ckey, secid))
        return secids

    def list(self) -> set[str]:
        """
        List all cached leases.
        """
        return self.cache.list()

    def _lookup(
        self, secid: vleases.VaultSecretId, ckey: str, flush: bool
    ) -> vleases.VaultSecretId | None:
        """
        Lookup SecretID meta information.

        secid
            A SecretID to lookup.

        ckey
            Cache key where the object was stored (to update information, if changed).

        flush
            Flush the cache key if the SecretID does not exist.
        """
        try:
            _, mount, role_name, _ = ckey.split(".")
        except TypeError as err:
            raise VaultInvocationError(f"Invalid cache key `{ckey}`") from err
        try:
            meta = self.api.read_secret_id(role_name, accessor=secid.accessor, mount=mount)
        except VaultNotFoundError:
            if flush:
                self.cache.flush(ckey)
            return None
        secid_updated = secid.with_renewed(**meta)
        if secid_updated != secid:
            self.cache.store(ckey, secid)
        return secid_updated

    def destroy(self, name: str, secid: vleases.VaultSecretId, mount: str = "approle"):
        """
        Destroy a SecretID.

        name
            Name of the AppRole the SecretID belongs to.

        secid
            SecretID to revoke.
        """
        try:
            self.api.destroy_secret_id(name, accessor=secid.accessor, mount=mount)
        except VaultNotFoundError:
            pass

    def list_cached_info(self, match: str = "*") -> dict[str, dict[str, typing.Any]]:
        """
        List cached SecretIDs.

        match
            Only list cached SecretIDs whose ckey matches this glob pattern.
            Defaults to ``*``.
        """
        ret = {}
        for ckey, secid in self._list_cached_secids(match=match, flush=False):
            info = secid.to_dict()
            ttl_left = secid.ttl_left
            info["expires_in"] = ttl_left
            info["expired"] = ttl_left == 0
            # do not leak auth data
            info.pop("id")
            info.pop("lease_id")
            ret[ckey] = info
        return ret

    def destroy_cached(
        self,
        match: str = "*",
        flush_on_failure: bool = True,
    ):
        """
        Revoke cached leases.

        match
            Only revoke cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.

        flush_on_failure
            If a revocation fails, remove the lease from cache anyways.
            Defaults to true.
        """
        failed = []
        for ckey, secid in self._list_cached_secids(match=match, flush=True):
            _, mount, name, _ = ckey.split(".")
            try:
                self.destroy(name, secid, mount=mount)
            except VaultPermissionDeniedError:
                failed.append(ckey)
                if flush_on_failure:
                    # Forget the SecretID and let Vault's automatic revocation handle it
                    self.cache.flush(ckey)
            else:
                self.cache.flush(ckey)

        if failed:
            raise VaultException(f"Failed deleting some SecretIDs: {list(failed)}")

    def store(self, ckey: str, secid: vleases.VaultSecretId):
        """
        Cache a SecretID.

        ckey
            The cache key the lease should be saved in.

        secid
            A SecretID or wrapped SecretID to store.
        """
        self.cache.store(ckey, secid)
