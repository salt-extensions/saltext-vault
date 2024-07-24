"""
High-level utility functions for Vault interaction
"""

import logging

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

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


def query(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    wrap=False,
    raise_error=True,
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
        is_unauthd=is_unauthd,
        **kwargs,
    )


def query_raw(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    wrap=False,
    retry=True,
    is_unauthd=False,
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

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    res = client.request_raw(
        method, endpoint, payload=payload, wrap=wrap, is_unauthd=is_unauthd, **kwargs
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


def read_kv(path, opts, context, include_metadata=False):
    """
    Read secret at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.read(path, include_metadata=include_metadata)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.read(path, include_metadata=include_metadata)


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


def delete_kv(path, opts, context, versions=None):
    """
    Delete secret at <path>. For KV v2, versions can be specified,
    which will be soft-deleted.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.delete(path, versions=versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.delete(path, versions=versions)


def destroy_kv(path, versions, opts, context):
    """
    Destroy secret <versions> at <path>. Requires KV v2.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.destroy(path, versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.destroy(path, versions)


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
