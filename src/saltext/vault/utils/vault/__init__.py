"""
High-level utility functions for Vault (or OpenBao) interaction
"""

import logging
import re
import typing
from collections.abc import Mapping

from saltext.vault.utils.vault import client as vclient
from saltext.vault.utils.vault.auth import InvalidVaultSecretId
from saltext.vault.utils.vault.auth import InvalidVaultToken
from saltext.vault.utils.vault.auth import LocalVaultSecretId
from saltext.vault.utils.vault.auth import VaultAppRole
from saltext.vault.utils.vault.exceptions import VaultAuthExpired
from saltext.vault.utils.vault.exceptions import VaultConfigExpired
from saltext.vault.utils.vault.exceptions import VaultException
from saltext.vault.utils.vault.exceptions import VaultInvocationError
from saltext.vault.utils.vault.exceptions import VaultNotFoundError
from saltext.vault.utils.vault.exceptions import VaultPermissionDeniedError
from saltext.vault.utils.vault.exceptions import VaultPreconditionFailedError
from saltext.vault.utils.vault.exceptions import VaultRateLimitExceededError
from saltext.vault.utils.vault.exceptions import VaultServerError
from saltext.vault.utils.vault.exceptions import VaultUnavailableError
from saltext.vault.utils.vault.exceptions import VaultUnsupportedOperationError
from saltext.vault.utils.vault.exceptions import VaultUnwrapException
from saltext.vault.utils.vault.factory import clear_cache
from saltext.vault.utils.vault.factory import get_approle_api
from saltext.vault.utils.vault.factory import get_authd_client
from saltext.vault.utils.vault.factory import get_identity_api
from saltext.vault.utils.vault.factory import get_kv
from saltext.vault.utils.vault.factory import get_lease_store
from saltext.vault.utils.vault.factory import parse_config
from saltext.vault.utils.vault.factory import update_config
from saltext.vault.utils.vault.leases import VaultLease
from saltext.vault.utils.vault.leases import VaultSecretId
from saltext.vault.utils.vault.leases import VaultToken
from saltext.vault.utils.vault.leases import VaultWrappedResponse

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltLogger

log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore
logging.getLogger("requests").setLevel(logging.WARNING)

ACL_TEMPLATING_REGEX = re.compile(r"{{(.+?)}}")


def query(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    *,
    wrap=False,
    raise_error=True,
    safe_to_retry=None,
    is_unauthd=False,
    **kwargs,
):
    """
    Query the Vault API. Supplemental arguments to ``requests.request``
    can be passed as kwargs.

    method
        HTTP verb to use.

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send, if any.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        .. versionadded:: 1.4.0

        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    try:
        return client.request(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            safe_to_retry=safe_to_retry,
            is_unauthd=is_unauthd,
            **kwargs,
        )
    except VaultPermissionDeniedError:
        if not _check_clear(config, client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    client = get_authd_client(opts, context)
    return client.request(
        method,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        **kwargs,
    )


def query_raw(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    *,
    wrap=False,
    retry=True,
    is_unauthd=False,
    safe_to_retry=None,
    **kwargs,
):
    """
    Query the Vault API, returning the raw response object. Supplemental
    arguments to ``requests.request`` can be passed as kwargs.

    method
        HTTP verb to use.

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send, if any.

    retry
        Retry the query with cleared cache in case the permission
        was denied (to check for revoked cached credentials).
        Defaults to True.

        .. note::
            Affects handling of ``403 Forbidden`` responses by this function and
            is independent from client settings.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    safe_to_retry
        .. versionadded:: 1.4.0

        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    res = client.request_raw(
        method,
        endpoint,
        payload=payload,
        wrap=wrap,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        **kwargs,
    )

    if not retry:
        return res

    if res.status_code == 403:
        if not _check_clear(config, client):
            return res

        # in case policies have changed
        clear_cache(opts, context)
        client = get_authd_client(opts, context)
        res = client.request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            safe_to_retry=safe_to_retry,
            is_unauthd=is_unauthd,
            **kwargs,
        )
    return res


def is_v2(path, opts, context):
    """
    Determines if a given secret path is KV v1 or v2.
    """
    kv = get_kv(opts, context)
    return kv.is_v2(path)


def read_kv(path, opts, context, include_metadata=False, version=None):
    """
    Read secret at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.read(path, include_metadata=include_metadata, version=version)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.read(path, include_metadata=include_metadata, version=version)


def read_kv_meta(path, opts, context):
    """
    Read secret metadata and version info at <path>.
    Requires KV v2.

    .. versionadded:: 1.2.0
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.read_meta(path)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.read_meta(path)


def write_kv(path, data, opts, context):
    """
    Write secret <data> to <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.write(path, data)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.write(path, data)


def patch_kv(path, data, opts, context):
    """
    Patch secret <data> at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.patch(path, data)
    except VaultAuthExpired:
        # patching can consume several token uses when
        # 1) `patch` cap unvailable 2) KV v1 3) KV v2 w/ old Vault versions
        kv = get_kv(opts, context)
        return kv.patch(path, data)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.patch(path, data)


def delete_kv(path, opts, context, versions=None, all_versions=False):
    """
    Delete secret at <path>. For KV v2, versions can be specified,
    which is soft-deleted.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.delete(path, versions=versions, all_versions=all_versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.delete(path, versions=versions, all_versions=all_versions)


def restore_kv(path, opts, context, versions=None, all_versions=False):
    """
    Restore secret versions at <path>. Requires KV v2.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.restore(path, versions=versions, all_versions=all_versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.restore(path, versions=versions, all_versions=all_versions)


def destroy_kv(path, versions, opts, context, all_versions=False):
    """
    Destroy secret <versions> at <path>. Requires KV v2.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.destroy(path, versions, all_versions=all_versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.destroy(path, versions, all_versions=all_versions)


def wipe_kv(path, opts, context):
    """
    Completely remove all version history and data at <path>.
    Requires KV v2.

    .. versionadded:: 1.2.0
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.nuke(path)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.nuke(path)


def list_kv(path, opts, context):
    """
    List secrets at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.list(path)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.list(path)


class LazyIdentityContext(Mapping[str, typing.Any]):
    """
    Simulates an identity metadata dictionary. Requests data from Vault
    once an item is accessed.
    """

    def __init__(self, client: vclient.AuthenticatedVaultClient):
        self.client = client
        self._entity: dict[str, typing.Any] | None = None
        self._group_ids: list[str] | None = None
        self._groups = {"ids": {}, "names": {}}

    def _init_entity(self):
        entity = self.client.token_entity()
        if not entity:
            raise RuntimeError("Current token has no associated entity")
        self._entity = {
            "id": entity["id"],
            "name": entity["name"],
            "metadata": entity["metadata"] or {},
            "aliases": {
                alias["mount_accessor"]: {
                    "id": alias["id"],
                    "name": alias["name"],
                    "metadata": alias["metadata"] or {},
                    "custom_metadata": alias["custom_metadata"] or {},
                }
                for alias in (entity["aliases"] or [])
            },
        }
        self._group_ids = entity["group_ids"] or []

    @typing.overload
    def _init_group(self, *, gid: str) -> dict[str, typing.Any] | None: ...
    @typing.overload
    def _init_group(self, *, name: str) -> dict[str, typing.Any] | None: ...
    def _init_group(
        self, *, gid: str | None = None, name: str | None = None
    ) -> dict[str, typing.Any] | None:
        if name:
            group = self.client.token_entity_group(name=name)
        elif gid:
            group = self.client.token_entity_group(gid=gid)
        else:
            raise TypeError("Need name or gid")
        if not group:
            raise RuntimeError(
                f"Current token has no associated entity or is not part of group {gid or name}"
            )
        self._groups["ids"][group["id"]] = {
            "name": group["name"],
            "metadata": group["metadata"] or {},
        }
        self._groups["names"][group["name"]] = {
            "id": group["id"],
            "metadata": group["metadata"] or {},
        }

    def _init_all_groups(self):
        if self._group_ids is None:
            self._init_entity()

        for gid in self._group_ids or []:
            if gid not in self._groups["ids"]:
                self._init_group(gid=gid)

    def _lookup(self, steps, ptr, key):
        while steps:
            try:
                ptr = ptr[steps.pop(0)]
            except KeyError as err:
                raise KeyError(key) from err
        if isinstance(ptr, Mapping):
            raise KeyError(key)
        return ptr

    def _lookup_entity(self, parts, key):
        if self._entity is None:
            self._init_entity()
        return self._lookup(parts[2:], self._entity, key)

    def _lookup_groups(self, parts, key):
        if parts[2] == "ids":
            if parts[3] not in self._groups["ids"]:
                self._init_group(gid=parts[3])
            group = self._groups["ids"][parts[3]]
        elif parts[2] == "names":
            if parts[3] not in self._groups["names"]:
                self._init_group(name=parts[3])
            group = self._groups["names"][parts[3]]
        else:
            raise KeyError(key)
        return self._lookup(parts[4:], group, key)

    def __getitem__(self, key):
        try:
            parts = key.split(".")
        except AttributeError as err:
            raise KeyError(key) from err
        if parts[0] != "identity":
            raise KeyError(key)
        if parts[1] == "entity":
            return self._lookup_entity(parts, key)
        if parts[1] == "groups":
            return self._lookup_groups(parts, key)
        raise KeyError(key)

    def __iter__(self):
        def _it(ptr, prefix=None):
            prefix = prefix or []
            for k, v in ptr.items():
                if isinstance(v, Mapping):
                    yield from _it(v, prefix + [k])
                else:
                    yield ".".join(prefix + [k])

        if self._entity is None:
            self._init_entity()
        yield from _it(self._entity, ["identity", "entity"])
        self._init_all_groups()
        yield from _it(self._groups, ["identity", "groups"])

    def __len__(self):
        return len(dict(self))


def render_identity_template(tpl, opts, context):
    """
    Render an identity template based on the currently active token.
    Example: ``foo/{{identity.entity.metadata.bar}}``.

    tpl
        (Possible) template string.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
    """
    if not _has_identity_template(tpl):
        return tpl

    # Intentionally use the same client for all requests and crash if auth expires
    client = get_authd_client(opts, context)
    ctx = LazyIdentityContext(client)

    def _sub_id(match):
        tgt = match.group(1).strip()
        return str(ctx[tgt])

    try:
        return ACL_TEMPLATING_REGEX.sub(_sub_id, tpl)
    except (KeyError, RuntimeError):
        return None


def _has_identity_template(tpl):
    """
    Check whether a string contains an identity template.
    """
    return bool(ACL_TEMPLATING_REGEX.search(tpl))


def _check_clear(config, client):
    """
    Called when encountering a VaultPermissionDeniedError.
    Decides whether caches should be cleared to retry with
    possibly updated token policies.
    """
    if config["cache"]["clear_on_unauthorized"]:
        return True
    try:
        # verify the current token is still valid
        return not client.token_valid(remote=True)
    except VaultAuthExpired:
        return True
