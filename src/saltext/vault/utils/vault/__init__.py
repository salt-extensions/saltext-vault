"""
High-level utility functions for Vault (or OpenBao) interaction
"""

import logging
import re
import typing
from collections.abc import Callable
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
    method: str,
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool | None = None,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API. Supplemental arguments to ``requests.request``
    can be passed as kwargs.

    method
        HTTP verb to use.

        .. note::
            A literal ``LIST`` is passed through as-is and does not
            follow the :vconf:`client:list_as_get` option. Use
            :func:`api_list` for logical list operations that
            respect it.

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

    warn_handler
        .. versionadded:: 1.9.0

        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "request",
        opts,
        context,
        method,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def query_raw(
    method: str,
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    retry: bool = True,
    is_unauthd: bool = False,
    safe_to_retry: bool | None = None,
    **kwargs,
):
    """
    Query the Vault API, returning the raw response object. Supplemental
    arguments to ``requests.request`` can be passed as kwargs.

    method
        HTTP verb to use.

        .. note::
            A literal ``LIST`` is passed through as-is and does not
            follow the :vconf:`client:list_as_get` option.

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


def api_get(
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool | None = None,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API using a ``GET`` request. Supplemental arguments
    to ``requests.request`` can be passed as kwargs.

    .. versionadded:: 1.9.0

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of query parameters to send, if any.
        They are URL-encoded automatically.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.

    warn_handler
        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "get",
        opts,
        context,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def api_list(
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool | None = None,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API using a logical list operation. Supplemental
    arguments to ``requests.request`` can be passed as kwargs.

    By default, this uses the ``LIST`` HTTP method. When
    :vconf:`client:list_as_get` is enabled, it issues a ``GET`` request
    with the ``list=true`` query parameter instead.

    .. versionadded:: 1.9.0

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of query parameters to send, if any.
        They are URL-encoded automatically.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.

    warn_handler
        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "list",
        opts,
        context,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def api_post(
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool | None = None,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API using a ``POST`` request. Supplemental arguments
    to ``requests.request`` can be passed as kwargs.

    .. versionadded:: 1.9.0

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send as the JSON request body, if any.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.

    warn_handler
        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "post",
        opts,
        context,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def api_put(
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool = True,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API using a ``POST`` request that is marked as safe
    to retry by default (idempotent). Vault considers ``POST`` and ``PUT``
    to be synonymous, this is the only difference to :py:func:`api_post`.
    Supplemental arguments to ``requests.request`` can be passed as kwargs.

    .. versionadded:: 1.9.0

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send as the JSON request body, if any.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        A boolean indicating whether this request is safe to retry (idempotent) or not.
        Defaults to True.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.

    warn_handler
        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "put",
        opts,
        context,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def api_patch(
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any],
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool | None = None,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API using a ``PATCH`` request. Supplemental arguments
    to ``requests.request`` can be passed as kwargs.

    .. versionadded:: 1.9.0

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send as the JSON merge patch body.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.

    warn_handler
        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "patch",
        opts,
        context,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def api_delete(
    endpoint: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    payload: dict[typing.Any, typing.Any] | None = None,
    *,
    wrap: str | typing.Literal[False] = False,
    raise_error: bool = True,
    safe_to_retry: bool | None = None,
    is_unauthd: bool = False,
    warn_handler: bool | Callable[[list[str]], list[str] | None] = True,
    **kwargs,
):
    """
    Query the Vault API using a ``DELETE`` request. Supplemental arguments
    to ``requests.request`` can be passed as kwargs.

    .. versionadded:: 1.9.0

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of query parameters to send, if any.
        They are URL-encoded automatically.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    safe_to_retry
        A boolean indicating whether this request is safe to retry (idempotent) or not.
        If not provided, defaults to guessing based on the HTTP method.
        Unsafe requests are not retried, unless :vconf:`client:retry_post` is enabled.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.

    warn_handler
        Boolean or callable to handle Vault-emitted warnings.
        Defaults to ``true``, meaning all emitted warnings are logged.
        Set this to ``false`` to silence any warnings.
        Set this to a callable that takes a list of warnings and optionally
        returns a list of warnings to log.
    """
    return _query_client(
        "delete",
        opts,
        context,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        safe_to_retry=safe_to_retry,
        is_unauthd=is_unauthd,
        warn_handler=warn_handler,
        **kwargs,
    )


def is_v2(path: str, opts: dict[str, typing.Any], context: dict[typing.Any, typing.Any]):
    """
    Determines if a given secret path is KV v1 or v2.

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
    """
    kv = get_kv(opts, context)
    return kv.is_v2(path)


def read_kv(
    path: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    include_metadata: bool = False,
    version: int | str | None = None,
):
    """
    Read secret at <path>.

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    metadata
        If ``path`` is on a KV v2 backend, display full results, including metadata.
        Defaults to False.

    version
        Version to read. If unset, reads the latest one.
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


def read_kv_meta(path: str, opts: dict[str, typing.Any], context: dict[typing.Any, typing.Any]):
    """
    Read secret metadata and version info at <path>.
    Requires KV v2.

    .. versionadded:: 1.2.0

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
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


def write_kv(
    path: str,
    data: dict[str, typing.Any],
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
):
    """
    Write secret <data> to <path>.

    path
        Path to the secret, including mount.

    data
        Secret data to write to <path>. Has to be a mapping.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
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


def patch_kv(
    path: str,
    data: dict[str, typing.Any],
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
):
    """
    Patch secret <data> at <path>.

    path
        Path to the secret, including mount.

    data
        Secret data to patch into <path>. Has to be a mapping.
        Keys set to ``null`` (JSON/YAML)/``None`` (Python) are deleted.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
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


def delete_kv(
    path: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    versions: int | str | list[int | str] | None = None,
    all_versions: bool = False,
):
    """
    Delete secret at <path>. For KV v2, versions can be specified,
    which is soft-deleted.

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    versions
        List of versions to soft-delete. If no version is specified,
        deletes the most recent one.

    all_versions
        Delete all versions of the secret for KV v2. Defaults to false.
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


def restore_kv(
    path: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    versions: int | str | list[int | str] | None = None,
    all_versions: bool = False,
):
    """
    Restore secret versions at <path>. Requires KV v2.

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    versions
        List of versions to restore. If no version is specified,
        restores the most recent one.

    all_versions
        Restore all versions of the secret for KV v2. Defaults to false.
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


def destroy_kv(
    path: str,
    versions: int | str | list[int | str] | None,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    all_versions: bool = False,
):
    """
    Destroy secret <versions> at <path>. Requires KV v2.

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    all_versions
        Restore all versions of the secret for KV v2. Defaults to false.
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


def wipe_kv(path: str, opts: dict[str, typing.Any], context: dict[typing.Any, typing.Any]):
    """
    Completely remove all version history and data at <path>.
    Requires KV v2.

    .. versionadded:: 1.2.0

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
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


def list_kv(path: str, opts: dict[str, typing.Any], context: dict[typing.Any, typing.Any]):
    """
    List secrets at <path>.

    path
        Path to the secret, including mount.

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.
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


def render_identity_template(
    tpl: str, opts: dict[str, typing.Any], context: dict[typing.Any, typing.Any]
) -> str | None:
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


class LazyIdentityContext(Mapping[str, str]):
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

    def _lookup(self, steps: list[str], ptr: typing.Any, key: str) -> str:
        while steps:
            try:
                ptr = ptr[steps.pop(0)]
            except KeyError as err:
                raise KeyError(key) from err
        if isinstance(ptr, Mapping):
            raise KeyError(key)
        return ptr

    def _lookup_entity(self, parts: list[str], key: str) -> str:
        if self._entity is None:
            self._init_entity()
        return self._lookup(parts[2:], self._entity, key)

    def _lookup_groups(self, parts: list[str], key: str) -> str:
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

    def __getitem__(self, key: str) -> str:
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

    def __iter__(self) -> typing.Iterator[str]:
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

    def __len__(self) -> int:
        return sum(1 for _ in self)


def _has_identity_template(tpl: str) -> bool:
    """
    Check whether a string contains an identity template.
    """
    return bool(ACL_TEMPLATING_REGEX.search(tpl))


def _query_client(
    func: str,
    opts: dict[str, typing.Any],
    context: dict[typing.Any, typing.Any],
    *args: typing.Any,
    **kwargs: typing.Any,
):
    """
    Call a request method of the authenticated client, retrying with
    a new client after clearing the cache in case permission was denied
    and the cached authentication data might be outdated.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    try:
        return getattr(client, func)(*args, **kwargs)
    except VaultPermissionDeniedError:
        if not _check_clear(config, client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    client = get_authd_client(opts, context)
    return getattr(client, func)(*args, **kwargs)


def _check_clear(config: dict[str, typing.Any], client: vclient.AuthenticatedVaultClient) -> bool:
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
