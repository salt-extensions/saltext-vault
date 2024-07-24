"""
Models for Vault leases
"""

import copy
import fnmatch
import logging
import time

from saltext.vault.utils.vault.exceptions import VaultException
from saltext.vault.utils.vault.exceptions import VaultInvocationError
from saltext.vault.utils.vault.exceptions import VaultNotFoundError
from saltext.vault.utils.vault.exceptions import VaultPermissionDeniedError
from saltext.vault.utils.vault.helpers import iso_to_timestamp
from saltext.vault.utils.vault.helpers import timestring_map

log = logging.getLogger(__name__)


class DurationMixin:
    """
    Mixin that handles expiration with time.
    """

    def __init__(
        self,
        renewable=False,
        duration=0,
        creation_time=None,
        expire_time=None,
        **kwargs,
    ):
        if "lease_duration" in kwargs:
            duration = kwargs.pop("lease_duration")
        self.renewable = renewable
        self.duration = duration
        creation_time = creation_time if creation_time is not None else round(time.time())
        try:
            creation_time = int(creation_time)
        except ValueError:
            creation_time = iso_to_timestamp(creation_time)
        self.creation_time = creation_time

        expire_time = expire_time if expire_time is not None else round(time.time()) + duration
        try:
            expire_time = int(expire_time)
        except ValueError:
            expire_time = iso_to_timestamp(expire_time)
        self.expire_time = expire_time
        super().__init__(**kwargs)

    def is_renewable(self):
        """
        Checks whether the lease is renewable
        """
        return self.renewable

    def is_valid_for(self, valid_for=0, blur=0):
        """
        Checks whether the entity is valid

        valid_for
            Check whether the entity will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        blur
            Allow undercutting ``valid_for`` for this amount of seconds.
            Defaults to 0.
        """
        if not self.duration:
            return True
        delta = self.expire_time - time.time() - timestring_map(valid_for)
        if delta >= 0:
            return True
        return abs(delta) <= blur

    @property
    def ttl_left(self):
        """
        .. versionadded:: 1.1.0

        Return the time in seconds until the lease expires.
        """
        return max(self.expire_time - round(time.time()), 0)


class UseCountMixin:
    """
    Mixin that handles expiration with number of uses.
    """

    def __init__(self, num_uses=0, use_count=0, **kwargs):
        self.num_uses = num_uses
        self.use_count = use_count
        super().__init__(**kwargs)

    def used(self):
        """
        Increment the use counter by one.
        """
        self.use_count += 1

    def has_uses_left(self, uses=1):
        """
        Check whether this entity has uses left.
        """
        return self.num_uses == 0 or self.num_uses - (self.use_count + uses) >= 0


class DropInitKwargsMixin:
    """
    Mixin that breaks the chain of passing unhandled kwargs up the MRO.
    """

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        super().__init__(*args)


class AccessorMixin:
    """
    Mixin that manages accessor information relevant for tokens/SecretIDs.
    """

    def __init__(self, accessor=None, wrapping_accessor=None, **kwargs):
        # ensure the accessor always points to the actual entity
        if "wrapped_accessor" in kwargs:
            wrapping_accessor = accessor
            accessor = kwargs.pop("wrapped_accessor")
        self.accessor = accessor
        self.wrapping_accessor = wrapping_accessor
        super().__init__(**kwargs)

    def accessor_payload(self):
        if self.accessor is not None:
            return {"accessor": self.accessor}
        raise VaultInvocationError("No accessor information available")


class BaseLease(DurationMixin, DropInitKwargsMixin):
    """
    Base class for leases that expire with time.
    """

    def __init__(self, lease_id, **kwargs):
        self.id = self.lease_id = lease_id
        super().__init__(**kwargs)

    def __str__(self):
        return self.id

    def __repr__(self):
        return repr(self.to_dict())

    def __eq__(self, other):
        try:
            data = other.__dict__
        except AttributeError:
            data = other
        return data == self.__dict__

    def with_renewed(self, **kwargs):
        """
        Partially update the contained data after lease renewal.
        """
        attrs = copy.copy(self.__dict__)
        # ensure expire_time is reset properly
        attrs.pop("expire_time")
        attrs.update(kwargs)
        return type(self)(**attrs)

    def to_dict(self):
        """
        Return a dict of all contained attributes.
        """
        return copy.deepcopy(self.__dict__)


class VaultLease(BaseLease):
    """
    Data object representing a Vault lease.

    Optional parameters in addition to the required``lease_id`` and ``data``:

    min_ttl
        When requesting this lease from the LeaseStore, ensure it is
        valid for at least this amount of time, even if the
        passed ``valid_for`` parameter is less.

        .. versionadded:: 1.1.0

    renew_increment
        When renewing this lease, instead of the lease's default TTL,
        default to this increment.

        .. versionadded:: 1.1.0

    revoke_delay
        When revoking this lease, instead of the default value of 60,
        default to this amount of time before having the Vault server
        revoke it.

        .. versionadded:: 1.1.0

    meta
        Cache arbitrary metadata together with the lease. It will
        be included in expiry events.

        .. versionadded:: 1.1.0
    """

    def __init__(
        self,
        lease_id,
        data,
        min_ttl=None,
        renew_increment=None,
        revoke_delay=None,
        meta=None,
        **kwargs,
    ):
        # save lease-associated data
        self.data = data
        # lifecycle default parameters
        self.min_ttl = min_ttl
        self.renew_increment = renew_increment
        self.revoke_delay = revoke_delay
        # metadata that is included in expiry events
        self.meta = meta
        super().__init__(lease_id, **kwargs)

    def is_valid_for(self, valid_for=None, blur=0):
        """
        Checks whether the lease is valid.

        valid_for
            Check whether the entity will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to the minimum TTL that was set on the lease
            when creating it or 0.

        blur
            Allow undercutting ``valid_for`` for this amount of seconds.
            Defaults to 0.
        """
        return super().is_valid_for(
            valid_for=valid_for if valid_for is not None else (self.min_ttl or 0),
            blur=blur,
        )


class VaultToken(UseCountMixin, AccessorMixin, BaseLease):
    """
    Data object representing an authentication token
    """

    def __init__(self, **kwargs):
        if "client_token" in kwargs:
            # Ensure response data from Vault is accepted as well
            kwargs["lease_id"] = kwargs.pop("client_token")
        super().__init__(**kwargs)

    def is_valid(self, valid_for=0, uses=1):
        """
        Checks whether the token is valid for an amount of time and number of uses.

        valid_for
            Check whether the token will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        uses
            Check whether the token has at least this number of uses left. Defaults to 1.
        """
        return self.is_valid_for(valid_for) and self.has_uses_left(uses)

    def is_renewable(self):
        """
        Check whether the token is renewable, which requires it
        to be currently valid for at least two uses and renewable.
        """
        # Renewing a token deducts a use, hence it does not make sense to
        # renew a token on the last use
        return self.renewable and self.is_valid(uses=2)

    def payload(self):
        """
        Return the payload to use for POST requests using this token.
        """
        return {"token": str(self)}

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        return {
            "client_token": self.id,
            "renewable": self.renewable,
            "lease_duration": self.duration,
            "num_uses": self.num_uses,
            "creation_time": self.creation_time,
            "expire_time": self.expire_time,
        }


class VaultSecretId(UseCountMixin, AccessorMixin, BaseLease):
    """
    Data object representing an AppRole SecretID.
    """

    def __init__(self, **kwargs):
        if "secret_id" in kwargs:
            # Ensure response data from Vault is accepted as well
            kwargs["lease_id"] = kwargs.pop("secret_id")
            kwargs["lease_duration"] = kwargs.pop("secret_id_ttl")
            kwargs["num_uses"] = kwargs.pop("secret_id_num_uses", 0)
            kwargs["accessor"] = kwargs.pop("secret_id_accessor", None)
        if "expiration_time" in kwargs:
            kwargs["expire_time"] = kwargs.pop("expiration_time")
        super().__init__(**kwargs)

    def is_valid(self, valid_for=0, uses=1):
        """
        Checks whether the SecretID is valid for an amount of time and number of uses

        valid_for
            Check whether the SecretID will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        uses
            Check whether the SecretID has at least this number of uses left.
            Defaults to 1.
        """
        return self.is_valid_for(valid_for) and self.has_uses_left(uses)

    def payload(self):
        """
        Return the payload to use for POST requests using this SecretID.
        """
        return {"secret_id": str(self)}

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        return {
            "secret_id": self.id,
            "secret_id_ttl": self.duration,
            "secret_id_num_uses": self.num_uses,
            "creation_time": self.creation_time,
            "expire_time": self.expire_time,
        }


class VaultWrappedResponse(AccessorMixin, BaseLease):
    """
    Data object representing a wrapped response.
    """

    def __init__(
        self,
        creation_path,
        **kwargs,
    ):
        if "token" in kwargs:
            # Ensure response data from Vault is accepted as well
            kwargs["lease_id"] = kwargs.pop("token")
            kwargs["lease_duration"] = kwargs.pop("ttl")
        if "renewable" not in kwargs:
            # Not renewable might be incorrect, wrapped tokens are,
            # but we cannot know what was wrapped here.
            kwargs["renewable"] = False
        super().__init__(**kwargs)
        self.creation_path = creation_path

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        return {
            "wrap_info": {
                "token": self.id,
                "ttl": self.duration,
                "creation_time": self.creation_time,
                "creation_path": self.creation_path,
            },
        }


class LeaseStore:
    """
    Caches leases and handles lease operations
    """

    def __init__(self, client, cache, expire_events=None):
        self.client = client
        self.cache = cache
        self.expire_events = expire_events
        # to update cached leases after renewal/revocation, we need a mapping id => ckey
        self.lease_id_ckey_cache = {}

    def get(
        self,
        ckey,
        valid_for=None,
        renew=True,
        renew_increment=None,
        renew_blur=2,
        revoke=None,
        check_server=False,
    ):
        """
        Return cached lease or None.

        ckey
            Cache key the lease has been saved in.

        valid_for
            Ensure the returned lease is valid for at least this amount of time.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to the minimum TTL that was set on the lease when creating it or 0.

            .. note::

                This does not take into account token validity, which active leases
                are bound to as well.

        renew
            If the lease is still valid, but not valid for ``valid_for``, attempt to
            renew it. Defaults to true.

        renew_increment
            When renewing, request the lease to be valid for this amount of time from
            the current point of time onwards.
            If unset, will renew the lease by its default validity period and, if
            the renewed lease does not pass ``valid_for``, will try to renew it
            by ``valid_for``.

        renew_blur
            When checking validity after renewal, allow this amount of seconds in leeway
            to account for latency. Especially important when renew_increment is unset
            and the default validity period is less than ``valid_for``.
            Defaults to 2.

        revoke
            If the lease is not valid for ``valid_for`` and renewals
            are disabled or impossible, attempt to have Vault revoke the lease
            after this amount of time and flush the cache. Defaults to the
            revocation delay that was set on the lease when creating it or 60s.

        check_server
            Check on the Vault server whether the lease is still active and was not
            revoked early. Defaults to false.

            .. versionadded:: 1.1.0
        """
        if renew_increment is not None and timestring_map(valid_for) > timestring_map(
            renew_increment
        ):
            raise VaultInvocationError(
                "When renew_increment is set, it must be at least valid_for to make sense"
            )

        def check_revoke(lease, min_valid, validity_override=None):
            if self.expire_events is not None:
                event_data = {
                    "valid_for_less": round(min_valid),
                    "ttl": validity_override if validity_override is not None else lease.ttl_left,
                    "meta": lease.meta,
                }
                self.expire_events(tag=f"vault/lease/{ckey}/expire", data=event_data)
            if revoke is None or revoke:
                self.revoke(lease, delta=revoke)
            return None

        # Since we can renew leases, do not check for future validity in cache
        lease = self.cache.get(ckey, flush=bool(revoke))
        if lease is None:
            return lease
        self.lease_id_ckey_cache[str(lease)] = ckey
        # Leases can have an associated min_ttl, which should be taken into
        # account here. It is not done on the lease class to not break internal
        # expectations.
        effective_min_validity = max(
            timestring_map(valid_for) or 0, timestring_map(lease.min_ttl) or 0
        )
        if renew_increment is not None and effective_min_validity > timestring_map(renew_increment):
            log.warning(
                f"renew_increment is set to '{renew_increment}', which is lower than "
                f"the minimum TTL of '{lease.min_ttl}' on lease '{ckey}'. "
                f"Dropping requested renew_increment for lease '{ckey}'."
            )
            renew_increment = None
        if lease.is_valid_for(effective_min_validity):
            if check_server:
                try:
                    # TODO: Save the updated info?
                    self.lookup(lease)
                except VaultNotFoundError:
                    return check_revoke(lease, effective_min_validity, 0)
            return lease

        if not renew:
            return check_revoke(lease, effective_min_validity)
        try:
            lease = self.renew(lease, increment=renew_increment, raise_all_errors=False)
        except VaultNotFoundError:
            # The cached lease was already revoked
            return check_revoke(lease, effective_min_validity, 0)
        if not lease.is_valid_for(effective_min_validity, blur=renew_blur):
            if renew_increment is not None:
                # valid_for cannot possibly be respected
                return check_revoke(lease, effective_min_validity)
            # Maybe valid_for is greater than the default validity period, so check if
            # the lease can be renewed by valid_for
            try:
                lease = self.renew(lease, increment=effective_min_validity, raise_all_errors=False)
            except VaultNotFoundError:
                # The cached lease was already revoked
                return check_revoke(lease, effective_min_validity, 0)
            if not lease.is_valid_for(effective_min_validity, blur=renew_blur):
                return check_revoke(lease, effective_min_validity)
        return lease

    def list(self):
        """
        List all known cache keys of cached leases.
        """
        return self.cache.list()

    def _list_cached_leases(self, match="*", flush=False):
        """
        Helper for functions that operate on the cached leases.
        """
        leases = []
        for ckey in self.list():
            if not fnmatch.fnmatch(ckey, match):
                continue
            lease = self.cache.get(ckey, flush=flush)
            if lease is None:
                continue
            self.lease_id_ckey_cache[str(lease)] = ckey
            leases.append((ckey, lease))
        return leases

    def list_info(self, match="*"):
        """
        .. versionadded:: 1.1.0

        List cached leases.

        match
            Only list cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.
        """
        ret = {}
        for ckey, lease in self._list_cached_leases(match=match, flush=False):
            info = lease.to_dict()
            ttl_left = lease.ttl_left
            info["expires_in"] = ttl_left
            info["expired"] = ttl_left == 0
            # do not leak auth data
            info.pop("data", None)
            ret[ckey] = info
        return ret

    def lookup(self, lease):
        """
        Lookup lease meta information.

        lease
            A lease ID or VaultLease object to look up.
        """
        endpoint = "sys/leases/lookup"
        payload = {"lease_id": str(lease)}
        try:
            return self.client.post(endpoint, payload=payload)
        except VaultInvocationError as err:
            if "invalid lease" not in str(err):
                raise
            raise VaultNotFoundError(str(err)) from err

    def renew(self, lease, increment=None, raise_all_errors=True, _store=True):
        """
        Renew a lease.

        lease
            A lease ID or VaultLease object to renew.

        increment
            Request the lease to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.

        raise_all_errors
            When ``lease`` is a VaultLease and the renewal does not succeed,
            do not catch exceptions. If this is false, the lease will be returned
            unmodified if the exception does not indicate it is invalid (NotFound).
            Defaults to true.
        """
        endpoint = "sys/leases/renew"
        payload = {"lease_id": str(lease)}
        if not isinstance(lease, VaultLease) and lease in self.lease_id_ckey_cache:
            lease = self.cache.get(self.lease_id_ckey_cache[lease], flush=False)
            if lease is None:
                raise VaultNotFoundError("Lease is already expired")
        if increment is not None:
            payload["increment"] = int(timestring_map(increment))
        if isinstance(lease, VaultLease) and lease.renew_increment is not None:
            payload["increment"] = max(
                int(timestring_map(lease.renew_increment)), payload.get("increment", 0)
            )
        try:
            ret = self.client.post(endpoint, payload=payload)
        except VaultInvocationError as err:
            if "lease not found" not in str(err):
                raise
            raise VaultNotFoundError(str(err)) from err
        except VaultException:
            if raise_all_errors or not isinstance(lease, VaultLease):
                raise
            return lease

        if _store and isinstance(lease, VaultLease):
            # Do not overwrite data of renewed leases!
            ret.pop("data", None)
            new_lease = lease.with_renewed(**ret)
            if str(new_lease) in self.lease_id_ckey_cache:
                self.store(self.lease_id_ckey_cache[str(new_lease)], new_lease)
            return new_lease
        return ret

    def renew_cached(self, match="*", increment=None):
        """
        Renew cached leases.

        match
            Only renew cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.

        increment
            Request the leases to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.
            If unset, defaults to the renewal increment that was set when creating
            the lease.
        """
        failed = []
        for ckey, lease in self._list_cached_leases(match=match, flush=True):
            try:
                self.renew(lease, increment=increment)
            except (VaultPermissionDeniedError, VaultNotFoundError) as err:
                log.warning(f"Failed renewing cached lease: {type(err).__name__}")
                log.debug(f"Lease ID was: {lease}")
                failed.append(ckey)
        if failed:
            raise VaultException(f"Failed renewing some leases: {list(failed)}")
        return True

    def revoke(self, lease, delta=None):
        """
        Revoke a lease. Will also remove the cached lease,
        if it has been requested from this LeaseStore before.

        lease
            A lease ID or VaultLease object to revoke.

        delta
            Time after which the lease should be requested
            to be revoked by Vault.
            Defaults to the revocation delay that was set when creating
            the lease or 60s.
        """
        if delta is None:
            if isinstance(lease, VaultLease) and lease.revoke_delay is not None:
                delta = lease.revoke_delay
            else:
                delta = 60
        try:
            # 0 would attempt a complete renewal
            self.renew(lease, increment=delta or 1, _store=False)
        except VaultNotFoundError:
            pass

        if str(lease) in self.lease_id_ckey_cache:
            self.cache.flush(self.lease_id_ckey_cache.pop(str(lease)))
        return True

    def revoke_cached(
        self,
        match="*",
        delta=None,
        flush_on_failure=True,
    ):
        """
        Revoke cached leases.

        match
            Only revoke cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.

        delta
            Time after which the leases should be revoked by Vault.
            Defaults to the revocation delay that was set when creating
            the lease(s) or 60s.

        flush_on_failure
            If a revocation fails, remove the lease from cache anyways.
            Defaults to true.
        """
        failed = []
        for ckey, lease in self._list_cached_leases(match=match, flush=True):
            try:
                self.revoke(lease, delta=delta)
            except VaultPermissionDeniedError:
                failed.append(ckey)
                if flush_on_failure:
                    # Forget the lease and let Vault's automatic revocation handle it
                    self.cache.flush(self.lease_id_ckey_cache.pop(str(lease)))
        if failed:
            raise VaultException(f"Failed revoking some leases: {list(failed)}")
        return True

    def store(self, ckey, lease):
        """
        Cache a lease.

        ckey
            The cache key the lease should be saved in.

        lease
            A lease ID or VaultLease object to store.
        """
        self.cache.store(ckey, lease)
        self.lease_id_ckey_cache[str(lease)] = ckey
        return True
