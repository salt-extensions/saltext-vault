"""
Vault-specific cache classes
"""

import copy
import logging
import time
import typing
from abc import ABC
from abc import abstractmethod

import salt.cache

from saltext.vault.utils.vault import helpers
from saltext.vault.utils.vault import leases
from saltext.vault.utils.vault.exceptions import VaultAuthExpired
from saltext.vault.utils.vault.exceptions import VaultConfigExpired
from saltext.vault.utils.vault.exceptions import VaultLeaseExpired

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltLogger

log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore


def _get_config_cache(
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    cbank: str,
    ckey: str = "config",
) -> "VaultConfigCache":
    """
    Factory for VaultConfigCache to get around some
    chicken-and-egg problems
    """
    config = None
    if cbank in context and ckey in context[cbank]:
        config = context[cbank][ckey]
    else:
        cache = salt.cache.factory(opts)
        if cache.contains(cbank, ckey):
            # expiration check is done inside the class
            config = cache.fetch(cbank, ckey)
        elif opts.get("cache", "localfs") != "localfs":
            local_opts = copy.copy(opts)
            local_opts["cache"] = "localfs"
            cache = salt.cache.factory(local_opts)
            if cache.contains(cbank, ckey):
                # expiration check is done inside the class
                config = cache.fetch(cbank, ckey)

    return VaultConfigCache(
        context,
        cbank,
        ckey,
        opts,
        init_config=config,
        flush_exception=VaultConfigExpired,
    )


def _get_cache_backend(
    config: dict[str, typing.Any], opts: dict[str, typing.Any]
) -> "salt.cache.Cache | None":
    if config["cache"]["backend"] == "session":
        return None
    if config["cache"]["backend"] in ("localfs", "disk", "file"):
        # cache.Cache does not allow setting the type of cache by param
        local_opts = copy.copy(opts)
        local_opts["cache"] = "localfs"
        log.debug(
            "Using localfs cache backend (cachedir: %s)", local_opts.get("cachedir", "<not set>")
        )
        return salt.cache.factory(local_opts)
    # this should usually resolve to localfs as well on minions,
    # but can be overridden by setting cache in the minion config
    return salt.cache.factory(opts)


def _get_cache_bank(
    opts: dict[str, typing.Any],
    *,
    force_local: bool = False,
    connection: bool = True,
    session: bool = False,
) -> str:
    minion_id = None
    # force_local is necessary because pillar compilation would otherwise
    # leak tokens between master and minions
    if not force_local and helpers.get_salt_run_type(opts) in (
        helpers.SALT_RUNTYPE_MASTER_IMPERSONATING,
        helpers.SALT_RUNTYPE_MASTER_PEER_RUN,
    ):
        minion_id = opts["grains"]["id"]
    prefix = "vault" if minion_id is None else f"minions/{minion_id}/vault"
    if session:
        res = prefix + "/connection/session"
    elif connection:
        res = prefix + "/connection"
    else:
        res = prefix
    log.debug("Cache bank for %s (force_local: %s): %s", minion_id or "self", force_local, res)
    return res


class CommonCache(ABC):
    """
    Base class that unifies context and other cache backends.
    """

    def __init__(
        self,
        context: dict[typing.Any, typing.Any],
        cbank: str,
        cache_backend: "salt.cache.Cache | None" = None,
        ttl: int | str | None = None,
        flush_exception: type[VaultConfigExpired] | type[VaultAuthExpired] | None = None,
    ):
        self.context = context
        self.cbank = cbank
        self.cache = cache_backend
        self.ttl = ttl
        self.flush_exception = flush_exception

    @abstractmethod
    def flush(self):
        raise NotImplementedError()

    def _ckey_exists(self, ckey: str, flush: bool = True) -> bool:
        if self.cbank in self.context and ckey in self.context[self.cbank]:
            return True
        if self.cache is not None:
            if not self.cache.contains(self.cbank, ckey):
                return False
            if self.ttl is not None:
                updated = self.cache.updated(self.cbank, ckey)
                if int(time.time()) - updated >= self.ttl:
                    if flush:
                        log.debug(f"Cached data in {self.cbank}/{ckey} outdated, flushing.")
                        self.flush()
                    return False
            return True
        return False

    def _get_ckey(self, ckey: str, flush: bool = True) -> dict[str, typing.Any] | None:
        if not self._ckey_exists(ckey, flush=flush):
            return None
        if self.cbank in self.context and ckey in self.context[self.cbank]:
            return self.context[self.cbank][ckey]
        if self.cache is not None:
            return self.cache.fetch(self.cbank, ckey) or None  # account for race conditions
        raise RuntimeError("This code path should not have been hit.")  # pragma: no cover

    def _store_ckey(self, ckey: str, value: dict[str, typing.Any]):
        if self.cache is not None:
            self.cache.store(self.cbank, ckey, value)
        if self.cbank not in self.context:
            self.context[self.cbank] = {}
        self.context[self.cbank][ckey] = value

    def _flush(self, ckey: str | None = None):
        if not ckey and self.flush_exception is not None:
            # Flushing caches in Vault often requires an orchestrated effort
            # to ensure leases/sessions are terminated instead of left open.
            raise self.flush_exception()
        if self.cache is not None:
            self.cache.flush(self.cbank, ckey)
        if self.cbank in self.context:
            if ckey is None:
                self.context.pop(self.cbank)
            else:
                self.context[self.cbank].pop(ckey, None)
        # also remove sub-banks from context to mimic cache behavior
        if ckey is None:
            for bank in list(self.context):
                if bank.startswith(self.cbank + "/"):
                    self.context.pop(bank)

    def _list(self) -> set[str]:
        ckeys = []
        if self.cbank in self.context:
            ckeys += list(self.context[self.cbank])
        if self.cache is not None:
            ckeys += self.cache.list(self.cbank)
        return set(ckeys)


class VaultCache(CommonCache):
    """
    Encapsulates session and other cache backends for a single domain
    like secret path metadata. Uses a single cache key.
    """

    def __init__(
        self,
        context: dict[typing.Any, typing.Any],
        cbank: str,
        ckey: str,
        cache_backend: "salt.cache.Cache | None" = None,
        ttl: int | str | None = None,
        flush_exception: type[VaultConfigExpired] | type[VaultAuthExpired] | None = None,
    ):
        super().__init__(
            context,
            cbank,
            cache_backend=cache_backend,
            ttl=ttl,
            flush_exception=flush_exception,
        )
        self.ckey = ckey

    def exists(self, flush: bool = True) -> bool:
        """
        Check whether data for this domain exists
        """
        return self._ckey_exists(self.ckey, flush=flush)

    def get(self, flush: bool = True) -> dict[str, typing.Any] | None:
        """
        Return the cached data for this domain or None
        """
        return self._get_ckey(self.ckey, flush=flush)

    def flush(self, cbank: bool = False):
        """
        Flush the cache for this domain
        """
        return self._flush(self.ckey if not cbank else None)

    def store(self, value: dict[str, typing.Any]):
        """
        Store data for this domain
        """
        return self._store_ckey(self.ckey, value)


class VaultConfigCache(VaultCache):
    """
    Handles caching of received configuration
    """

    def __init__(
        self,
        context: dict[typing.Any, typing.Any],
        cbank: str,
        ckey: str,
        opts: dict[str, typing.Any],
        cache_backend_factory: "typing.Callable[[dict[str, typing.Any], dict[typing.Any, typing.Any]], salt.cache.Cache | None]" = _get_cache_backend,
        init_config: dict[str, typing.Any] | None = None,
        flush_exception: type[VaultConfigExpired] | type[VaultAuthExpired] | None = None,
    ):  # pylint: disable=super-init-not-called
        self.context = context
        self.cbank = cbank
        self.ckey = ckey
        self.opts = opts
        self.config = None
        self.cache = None
        self.ttl = None
        self.cache_backend_factory = cache_backend_factory
        self.flush_exception = flush_exception
        if init_config is not None:
            self._load(init_config)

    def exists(self, flush: bool = True) -> bool:
        """
        Check if a configuration has been loaded and cached
        """
        if self.config is None:
            return False
        return super().exists(flush=flush)

    def get(self, flush: bool = True) -> dict[str, typing.Any] | None:
        """
        Return the current cached configuration
        """
        if self.config is None:
            return None
        return super().get(flush=flush)

    def flush(self, cbank: bool = True):
        """
        Flush all connection-scoped data
        """
        if self.config is None:
            log.warning("Tried to flush uninitialized configuration cache. Skipping flush.")
            return
        # flush the whole connection-scoped cache by default
        super().flush(cbank=cbank)
        self.config = None
        self.cache = None
        self.ttl = None

    def _load(self, config: dict[str, typing.Any]):
        if self.config is not None:
            if (
                self.config["cache"]["backend"] != "session"
                and self.config["cache"]["backend"] != config["cache"]["backend"]
            ):
                self.flush()
        self.config = config
        self.cache = self.cache_backend_factory(self.config, self.opts)
        self.ttl = self.config["cache"]["config"]

    def store(self, value: dict[str, typing.Any]):
        """
        Reload cache configuration, then store the new Vault configuration,
        overwriting the existing one.
        """
        self._load(value)
        super().store(value)


LeaseType = typing.TypeVar("LeaseType", bound=leases.BaseLease)  # pylint: disable=invalid-name


class LeaseCacheMixin(typing.Generic[LeaseType]):
    """
    Mixin for auth and lease cache that checks validity
    and acts with hydrated objects
    """

    def __init__(
        self,
        *args,
        lease_cls: type[LeaseType],
        expire_events: typing.Callable[..., bool] | None = None,
        **kwargs,
    ):
        self.lease_cls = lease_cls
        self.expire_events = expire_events
        super().__init__(*args, **kwargs)

    def _check_validity(
        self, lease_data: dict[str, typing.Any], valid_for: int | str = 0
    ) -> LeaseType | None:
        lease = self.lease_cls(**lease_data)
        try:
            # is_valid on auth classes accounts for duration and uses
            if lease.is_valid(valid_for):  # type: ignore
                log.debug("Using cached lease.")
                return lease
        except AttributeError:
            if lease.is_valid_for(valid_for):
                log.debug("Using cached lease.")
                return lease
        if self.expire_events is not None:
            raise VaultLeaseExpired(lease)
        return None


class VaultLeaseCache(LeaseCacheMixin[LeaseType], CommonCache):
    """
    Handles caching of Vault leases. Supports multiple cache keys.
    Checks whether cached leases are still valid before returning.
    Does not enforce for per-lease ``min_ttl``.
    """

    def get(self, ckey: str, valid_for: int | str = 0, flush: bool = True) -> LeaseType | None:
        """
        Returns valid cached lease data or None.
        Flushes cache if invalid by default.
        """
        data = self._get_ckey(ckey, flush=flush)
        if data is None:
            return data
        try:
            ret = self._check_validity(data, valid_for=valid_for)
        except VaultLeaseExpired as err:
            if self.expire_events is not None:
                self.expire_events(
                    tag=f"vault/lease/{ckey}/expire",
                    data={
                        "valid_for_less": (
                            valid_for if valid_for is not None else err.lease.min_ttl or 0
                        ),
                        "ttl": err.lease.ttl_left,
                        "meta": getattr(err.lease, "meta", None),
                    },
                )
            ret = None
        if ret is None and flush:
            log.debug("Cached lease not valid anymore. Flushing cache.")
            self._flush(ckey)
        return ret

    def store(self, ckey: str, value: LeaseType | dict[str, typing.Any]):
        """
        Store a lease in cache
        """
        try:
            lease_data = value.to_dict()  # type: ignore
        except AttributeError:
            return self._store_ckey(ckey, typing.cast(dict[str, typing.Any], value))
        return self._store_ckey(ckey, lease_data)

    def exists(self, ckey: str, flush: bool = True) -> bool:
        """
        Check whether a named lease exists in cache. Does not filter invalid ones,
        so fetching a reported one might still return None.
        """
        return self._ckey_exists(ckey, flush=flush)

    def flush(self, ckey: str | None = None):
        """
        Flush the lease cache or a single lease from the lease cache
        """
        return self._flush(ckey)

    def list(self) -> set[str]:
        """
        List all cached leases. Does not filter invalid ones,
        so fetching a reported one might still return None.
        """
        return self._list()


AuthType = typing.TypeVar(  # pylint: disable=invalid-name
    "AuthType", leases.VaultSecretId, leases.VaultToken
)


class VaultAuthCache(LeaseCacheMixin[AuthType], CommonCache):
    """
    Implements authentication secret-specific caches. Checks whether
    the cached secrets are still valid before returning.
    """

    def __init__(
        self,
        context: dict[typing.Any, typing.Any],
        cbank: str,
        ckey: str,
        auth_cls: type[AuthType],
        cache_backend=None,
        ttl: int | str | None = None,
        flush_exception: type[VaultConfigExpired] | type[VaultAuthExpired] | None = None,
    ):
        super().__init__(
            context,
            cbank,
            lease_cls=auth_cls,
            cache_backend=cache_backend,
            ttl=ttl,
            flush_exception=flush_exception,
        )
        self.ckey = ckey
        self.flush_exception = flush_exception

    def exists(self, flush: bool = True) -> bool:
        """
        Check whether data for this domain exists
        """
        return self._ckey_exists(self.ckey, flush=flush)

    def get(self, valid_for: int | str = 0, flush: bool = True) -> AuthType | None:
        """
        Returns valid cached auth data or None.
        Flushes cache if invalid by default.
        """
        data = self._get_ckey(self.ckey, flush=flush)
        if data is None:
            return data
        ret = self._check_validity(data, valid_for=valid_for)
        if ret is None and flush:
            log.debug("Cached auth data not valid anymore. Flushing cache.")
            self.flush()
        return ret

    def store(self, value: AuthType | dict[str, typing.Any]):
        """
        Store an auth credential in cache. Overwrites possibly existing one.
        """
        try:
            new_value = value.to_dict()  # type: ignore
        except AttributeError:
            return self._store_ckey(self.ckey, typing.cast(dict[str, typing.Any], value))
        return self._store_ckey(self.ckey, new_value)

    def flush(self, cbank: str | None = None):
        """
        Flush the cached auth credentials. If this is a token cache,
        flushing it deletes the whole session-scoped cache bank.
        """
        if self.lease_cls is leases.VaultToken:
            # flush the whole cbank (session-scope) if this is a token cache
            ckey = None
        else:
            ckey = None if cbank else self.ckey
        return self._flush(ckey)
