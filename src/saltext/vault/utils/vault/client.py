"""
Vault (or OpenBao) API client implementation
"""

import logging
import random
import re
import typing
from collections.abc import Mapping
from collections.abc import Sequence
from itertools import takewhile

import requests
import requests.adapters
import salt.exceptions

from saltext.vault.utils.vault import auth as vauth
from saltext.vault.utils.vault import leases
from saltext.vault.utils.vault.exceptions import VaultAuthExpired
from saltext.vault.utils.vault.exceptions import VaultInvocationError
from saltext.vault.utils.vault.exceptions import VaultNotFoundError
from saltext.vault.utils.vault.exceptions import VaultPermissionDeniedError
from saltext.vault.utils.vault.exceptions import VaultPreconditionFailedError
from saltext.vault.utils.vault.exceptions import VaultRateLimitExceededError
from saltext.vault.utils.vault.exceptions import VaultServerError
from saltext.vault.utils.vault.exceptions import VaultUnavailableError
from saltext.vault.utils.vault.exceptions import VaultUnsupportedOperationError
from saltext.vault.utils.vault.exceptions import VaultUnwrapException

try:
    from urllib3.util import create_urllib3_context

    URLLIB3V1 = False
except ImportError:
    # urllib <2
    from urllib3.util.ssl_ import create_urllib3_context

    URLLIB3V1 = True

if typing.TYPE_CHECKING:
    from typing_extensions import Self
    from urllib3 import response as urllib3response

    from saltext.vault.utils._types import SaltLogger


log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore
logging.getLogger("requests").setLevel(logging.WARNING)

# This list is not complete at all, but contains
# the most important paths.
VAULT_UNAUTHD_PATHS: tuple[str, ...] = (
    "sys/wrapping/lookup",
    "sys/internal/ui/mounts",
    "sys/internal/ui/namespaces",
    "sys/seal-status",
    "sys/health",
)

HTTP_TOO_MANY_REQUESTS = 429

# Default timeout configuration
DEFAULT_CONNECT_TIMEOUT = 9.2
DEFAULT_READ_TIMEOUT = 30

# Default retry configuration
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_FACTOR = 0.1
DEFAULT_BACKOFF_MAX = 10.0
DEFAULT_BACKOFF_JITTER = 0.2
DEFAULT_RETRY_POST = False
DEFAULT_RESPECT_RETRY_AFTER = True
DEFAULT_RETRY_AFTER_MAX = 60
# https://developer.hashicorp.com/vault/api-docs#http-status-codes
# 412: eventually consistent data is still missing (Enterprise)
DEFAULT_RETRY_STATUS = (412, 500, 502, 503, 504)

# Caps for retry configuration
MAX_MAX_RETRIES = 10
MAX_BACKOFF_FACTOR = 3.0
MAX_BACKOFF_MAX = 60.0
MAX_BACKOFF_JITTER = 5.0


def _get_expected_creation_path(
    secret_type: typing.Literal["token"] | typing.Literal["secret_id"] | typing.Literal["role_id"],
    config: Mapping[str, typing.Any] | None = None,
) -> str:
    if secret_type == "token":
        return r"auth/token/create(/[^/]+)?"

    if secret_type == "secret_id":
        if config is not None:
            mount, approle = re.escape(config["auth"]["approle_mount"]), re.escape(
                config["auth"]["approle_name"]
            )
            return rf"auth/{mount}/role/{approle}/secret\-id"
        return r"auth/[^/]+/role/[^/]+/secret\-id"

    if secret_type == "role_id":
        if config is not None:
            mount, approle = re.escape(config["auth"]["approle_mount"]), re.escape(
                config["auth"]["approle_name"]
            )
            return rf"auth/{mount}/role/{approle}/role\-id"
        return r"auth/[^/]+/role/[^/]+/role\-id"

    raise salt.exceptions.SaltInvocationError(
        f"secret_type must be one of token, secret_id, role_id, got `{secret_type}`."
    )


class VaultClient:  # pylint: disable=too-many-instance-attributes
    """
    Unauthenticated client for the Vault API.
    Base class for authenticated client.
    """

    def __init__(
        self,
        url: str,
        namespace: str | None = None,
        verify: str | bool | None = None,
        *,
        session: requests.Session | None = None,
        connect_timeout: float | int = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float | int = DEFAULT_READ_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float | int = DEFAULT_BACKOFF_FACTOR,
        backoff_max: float | int = DEFAULT_BACKOFF_MAX,
        backoff_jitter: float | int = DEFAULT_BACKOFF_JITTER,
        retry_post: bool = DEFAULT_RETRY_POST,
        respect_retry_after: bool = DEFAULT_RESPECT_RETRY_AFTER,
        retry_status: Sequence[int] | None = DEFAULT_RETRY_STATUS,
        retry_after_max: int | None = DEFAULT_RETRY_AFTER_MAX,
        url_alts: Sequence[str] | None = None,
        # Drop unknown kwargs to ensure future additions to server/client config
        # don't break clients running older releases.
        **_,
    ):
        self.url = url
        self.namespace = namespace
        self.verify = verify

        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        # Cap the retry-backoff values somewhat
        self.max_retries = float(max(0, min(max_retries, MAX_MAX_RETRIES)))
        self.backoff_factor = float(max(0, min(backoff_factor, MAX_BACKOFF_FACTOR)))
        self.backoff_max = float(max(0, min(backoff_max, MAX_BACKOFF_MAX)))
        self.backoff_jitter = float(max(0, min(backoff_jitter, MAX_BACKOFF_JITTER)))
        self.retry_post = bool(retry_post)
        self.respect_retry_after = bool(respect_retry_after)
        # urllib3 2.6.3 introduced this parameter and set its default to 21600 (6h). Match that.
        self.retry_after_max = max(0, retry_after_max) if retry_after_max is not None else 21600

        self.retry_status = tuple(retry_status) if retry_status is not None else None
        self.url_alts = tuple(url_alts or (url,))

        retry = VaultRetry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            backoff_max=self.backoff_max,
            backoff_jitter=self.backoff_jitter,
            respect_retry_after_header=self.respect_retry_after,
            retry_after_max=self.retry_after_max,
            allowed_methods=None if retry_post else requests.adapters.Retry.DEFAULT_ALLOWED_METHODS,
            raise_on_status=False,
            status_forcelist=self.retry_status,
        )

        if session is None:
            session = requests.Session()
            adapter = VaultAPIAdapter(
                max_retries=retry,
                verify=verify,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
            )
            session.mount(url, adapter)
        else:
            # Sessions should only be inherited from other instances
            # of this class. A changed ``verify`` setting causes a fresh
            # client to be instantiated.
            # We want to keep the TCP connection alive, so we'll modify
            # the adapter in place.
            adapter = typing.cast(VaultAPIAdapter, session.get_adapter(url))
            adapter.max_retries = retry
            adapter.connect_timeout = self.connect_timeout
            adapter.read_timeout = self.read_timeout
        self.session = session
        self._vault_adapter = adapter

    @typing.overload
    def delete(
        self,
        endpoint: str,
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any: ...
    @typing.overload
    def delete(
        self,
        endpoint: str,
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> leases.VaultWrappedResponse: ...
    def delete(
        self,
        endpoint: str,
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any:
        """
        Wrapper for client.request("DELETE", ...)
        """
        return self.request(
            "DELETE",
            endpoint,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
        )

    @typing.overload
    def get(
        self,
        endpoint: str,
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any: ...
    @typing.overload
    def get(
        self,
        endpoint: str,
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> leases.VaultWrappedResponse: ...
    def get(
        self,
        endpoint: str,
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any:
        """
        Wrapper for client.request("GET", ...)
        """
        return self.request(
            "GET",
            endpoint,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
        )

    @typing.overload
    def list(
        self,
        endpoint: str,
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any: ...
    @typing.overload
    def list(
        self,
        endpoint: str,
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> leases.VaultWrappedResponse: ...
    def list(
        self,
        endpoint: str,
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any:
        """
        Wrapper for client.request("LIST", ...)
        TODO: configuration to enable GET requests with query parameters for LIST?
        """
        return self.request(
            "LIST",
            endpoint,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
        )

    @typing.overload
    def post(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any: ...
    @typing.overload
    def post(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> leases.VaultWrappedResponse: ...
    def post(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any:
        """
        Wrapper for client.request("POST", ...)
        """
        return self.request(
            "POST",
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
        )

    @typing.overload
    def put(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool = True,
    ) -> typing.Any: ...
    @typing.overload
    def put(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool = True,
    ) -> leases.VaultWrappedResponse: ...
    def put(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool = True,
    ) -> leases.VaultWrappedResponse | typing.Any:
        """
        Also a wrapper for client.request("POST", ...)
        Vault considers POST and PUT to be synonymous.
        The difference to ``post`` is that this request is marked as safe to retry by default (idempotent).
        """
        return self.request(
            "POST",
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
        )

    @typing.overload
    def patch(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any],
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any: ...
    @typing.overload
    def patch(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any],
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> leases.VaultWrappedResponse: ...
    def patch(
        self,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any],
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
    ) -> typing.Any:
        """
        Wrapper for client.request("PATCH", ...)
        """
        return self.request(
            "PATCH",
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
        )

    @typing.overload
    def request(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
        **kwargs,
    ) -> typing.Any: ...
    @typing.overload
    def request(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
        **kwargs,
    ) -> leases.VaultWrappedResponse: ...
    def request(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str | typing.Literal[False] = False,
        raise_error: bool = True,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
        **kwargs,
    ) -> typing.Any:
        """
        Issue a request against the Vault API.
        Returns boolean when no data was returned, otherwise the decoded json data
        or a VaultWrappedResponse object if wrapping was requested.
        """
        res = self.request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
            **kwargs,
        )
        if res.status_code == 204:
            return True
        data = res.json()
        if not res.ok:
            if raise_error:
                self._raise_status(res)
            return data
        if wrap:
            return leases.VaultWrappedResponse(**data["wrap_info"])
        return data

    def request_raw(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str | typing.Literal[False] = False,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
        **kwargs,
    ) -> requests.Response:
        """
        Issue a request against the Vault API. Returns the raw response object.
        """
        url = self._get_url(endpoint)
        headers = self._get_headers(wrap)
        if method.upper() == "PATCH":
            # PATCH always requires JSON patch content-type, so
            # just replace it.
            headers["Content-Type"] = "application/merge-patch+json"

        try:
            headers.update(add_headers or {})
        except TypeError:
            pass

        self._vault_adapter.max_retries.safe_to_retry = safe_to_retry

        try:
            res = self.session.request(
                method,
                url,
                headers=headers,
                json=payload,
                **kwargs,
            )
        finally:
            self._vault_adapter.max_retries.safe_to_retry = None

        return res

    def unwrap(
        self,
        wrapped: leases.VaultWrappedResponse | str,
        expected_creation_path: Sequence[str] | str | None = None,
    ) -> typing.Any:
        """
        Unwraps the data associated with a wrapping token.

        wrapped
            Wrapping token to unwrap

        expected_creation_path
            Regex expression or list of expressions that should fully match the
            wrapping token creation path. At least one match is required.
            Defaults to None, which skips the check.

            .. note::
                This check prevents tampering with wrapping tokens, which are
                valid for one request only. Usually, if an attacker sniffs a wrapping
                token, there are two unwrapping requests, causing an audit warning.
                If the attacker can issue a new wrapping token and insert it into the
                response instead, this warning would be silenced. Assuming they do not
                possess the permissions to issue a wrapping token from the correct
                endpoint, checking the creation path makes this kind of attack obvious.
        """
        if expected_creation_path:
            wrap_info = self.wrap_info(wrapped)
            if isinstance(expected_creation_path, str):
                expected_creation_path = [expected_creation_path]
            elif not isinstance(expected_creation_path, list):
                expected_creation_path = [str(path) for path in expected_creation_path]
            expected_creation_path = typing.cast(list[str], expected_creation_path)
            if not any(re.fullmatch(p, wrap_info["creation_path"]) for p in expected_creation_path):
                raise VaultUnwrapException(
                    actual=wrap_info["creation_path"],
                    expected=expected_creation_path,
                    url=self.url,
                    namespace=self.namespace,
                    verify=self.verify,
                )
        url = self._get_url("sys/wrapping/unwrap")
        headers = self._get_headers()
        payload = {}
        if "X-Vault-Token" not in headers:
            headers["X-Vault-Token"] = str(wrapped)
        else:
            payload["token"] = str(wrapped)
        res = self.session.request("POST", url, headers=headers, json=payload)
        if not res.ok:
            self._raise_status(res)
        return res.json()

    def wrap_info(self, wrapped: leases.VaultWrappedResponse | str) -> dict[str, typing.Any]:
        """
        Lookup wrapping token meta information.
        """
        endpoint = "sys/wrapping/lookup"
        add_headers = {"X-Vault-Token": str(wrapped)}
        return self.put(endpoint, wrap=False, add_headers=add_headers)["data"]

    @typing.overload
    def token_lookup(self, *, token: str, raw: typing.Literal[True]) -> requests.Response: ...
    @typing.overload
    def token_lookup(
        self, *, token: str, raw: typing.Literal[False] = False
    ) -> dict[str, typing.Any]: ...
    @typing.overload
    def token_lookup(self, *, accessor: str, raw: typing.Literal[True]) -> requests.Response: ...
    @typing.overload
    def token_lookup(
        self, *, accessor: str, raw: typing.Literal[False] = False
    ) -> dict[str, typing.Any]: ...
    def token_lookup(
        self, *, token: str | None = None, accessor: str | None = None, raw: bool = False
    ):
        """
        Lookup token meta information.

        token
            Token to look up or to use to look up the accessor.
            Required.

        accessor
            Accessor to use to query the token meta information.

        raw
            Return the raw response object instead of response data.
            Also disables status code checking.
        """
        endpoint = "auth/token/lookup-self"
        method = "GET"
        payload = {}
        if token is None:
            raise VaultInvocationError("Unauthenticated VaultClient needs a token to lookup.")
        add_headers = {"X-Vault-Token": token}

        if accessor is not None:
            method = "POST"
            endpoint = "auth/token/lookup-accessor"
            payload["accessor"] = accessor

        res = self.request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=False,
            add_headers=add_headers,
            safe_to_retry=True,
        )
        if raw:
            return res
        self._raise_status(res)
        return res.json()["data"]

    def token_valid(
        self, valid_for: int | str = 0, remote: bool = True  # pylint: disable=unused-argument
    ) -> bool:
        """
        This client does not have a token, hence it's always invalid.
        """
        return False

    def get_config(self) -> dict[str, typing.Any]:
        """
        Returns Vault server configuration used by this client.
        """
        return {
            "url": self.url,
            "url_alts": list(self.url_alts),
            "namespace": self.namespace,
            "verify": self.verify,
        }

    def _get_url(self, endpoint: str) -> str:
        endpoint = endpoint.strip("/")
        return f"{self.url}/v1/{endpoint}"

    def _get_headers(self, wrap: int | str | typing.Literal[False] = False) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "X-Vault-Request": "true"}
        if self.namespace is not None:
            headers["X-Vault-Namespace"] = self.namespace
        if wrap:
            headers["X-Vault-Wrap-TTL"] = str(wrap)
        return headers

    def _raise_status(self, res: requests.Response):
        errors = ", ".join(res.json().get("errors", []))
        if res.status_code == 400:
            raise VaultInvocationError(errors)
        if res.status_code == 403:
            raise VaultPermissionDeniedError(errors)
        if res.status_code == 404:
            raise VaultNotFoundError(errors)
        if res.status_code == 405:
            raise VaultUnsupportedOperationError(errors)
        if res.status_code == 412:
            raise VaultPreconditionFailedError(errors)
        if res.status_code == HTTP_TOO_MANY_REQUESTS:
            raise VaultRateLimitExceededError(errors)
        if res.status_code in (500, 502):
            raise VaultServerError(errors)
        if res.status_code == 503:
            raise VaultUnavailableError(errors)
        res.raise_for_status()


class AuthenticatedVaultClient(VaultClient):
    """
    Authenticated client for the Vault API.
    This should be used for most operations.
    """

    # Need to define some value here for Mock spec
    auth: vauth.VaultAppRoleAuth | vauth.VaultTokenAuth = None  # type: ignore

    def __init__(self, auth: vauth.VaultAppRoleAuth | vauth.VaultTokenAuth, url: str, **kwargs):
        self.auth = auth
        self._entity = None
        self._groups = {"name": {}, "id": {}}

        super().__init__(url, **kwargs)

    def token_valid(self, valid_for: int | str = 0, remote: bool = True) -> bool:
        """
        Check whether this client's authentication information is
        still valid.

        remote
            Check with the remote Vault server as well. This consumes
            a token use. Defaults to true.
        """
        if not self.auth.is_valid(valid_for):
            return False
        if not remote:
            return True
        try:
            res = self.token_lookup(raw=True)
            if res.status_code != 200:
                return False
            return True
        except Exception as err:  # pylint: disable=broad-except
            raise salt.exceptions.CommandExecutionError(
                "Error while looking up self token."
            ) from err

    @typing.overload
    def token_lookup(  # pylint: disable=arguments-differ
        self, *, raw: typing.Literal[True]
    ) -> requests.Response: ...
    @typing.overload
    def token_lookup(  # pylint: disable=arguments-differ
        self, *, raw: typing.Literal[False] = False
    ) -> dict[str, typing.Any]: ...
    @typing.overload
    def token_lookup(self, *, token: str, raw: typing.Literal[True]) -> requests.Response: ...
    @typing.overload
    def token_lookup(
        self, *, token: str, raw: typing.Literal[False] = False
    ) -> dict[str, typing.Any]: ...
    @typing.overload
    def token_lookup(  # pylint: disable=arguments-differ
        self, *, accessor: str, raw: typing.Literal[True]
    ) -> requests.Response: ...
    @typing.overload
    def token_lookup(  # pylint: disable=arguments-differ
        self, *, accessor: str, raw: typing.Literal[False] = False
    ) -> dict[str, typing.Any]: ...
    def token_lookup(  # pylint: disable=arguments-differ
        self, token: str | None = None, accessor: str | None = None, raw: bool = False
    ):
        """
        Lookup token meta information.

        token
            Token to look up. If neither token nor accessor
            are specified, looks up the current token in use by
            this client.

        accessor
            Accessor of the token to query the meta information for.

        raw
            Return the raw response object instead of response data.
            Also disables status code checking.
        """
        endpoint = "auth/token/lookup"
        method = "POST"
        payload = {}
        if token is not None:
            payload["token"] = token
        elif accessor is not None:
            endpoint += "-accessor"
            payload["accessor"] = accessor
        else:
            endpoint += "-self"
            method = "GET"
        if raw:
            return self.request_raw(
                method, endpoint, payload=payload, wrap=False, safe_to_retry=True
            )
        return self.request(method, endpoint, payload=payload, wrap=False, safe_to_retry=True)[
            "data"
        ]

    @typing.overload
    def token_renew(self, increment: int | str | None = None) -> dict[str, typing.Any]: ...
    @typing.overload
    def token_renew(
        self, increment: int | str | None = None, *, token: str
    ) -> dict[str, typing.Any]: ...
    @typing.overload
    def token_renew(
        self, increment: int | str | None = None, *, accessor: str
    ) -> dict[str, typing.Any]: ...
    def token_renew(self, increment=None, *, token=None, accessor=None):
        """
        Renew a token.

        increment
            Request the token to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.

        token
            Token that should be renewed. Optional.
            If token and accessor are unset, renews the token currently in use
            by this client.

        accessor
            Accessor of the token that should be renewed. Optional.
        """
        endpoint = "auth/token/renew"
        payload = {}

        if token is None and accessor is None:
            if not self.auth.is_renewable():
                return False
            endpoint += "-self"

        if increment is not None:
            payload["increment"] = increment
        if token is not None:
            payload["token"] = token
        elif accessor is not None:
            endpoint += "-accessor"
            payload["accessor"] = accessor

        res = self.post(endpoint, payload=payload)

        if token is None and accessor is None:
            self.auth.update_token(res["auth"])
        return res["auth"]

    @typing.overload
    def token_revoke(self, delta: int | str | None = None) -> typing.Literal[True]: ...
    @typing.overload
    def token_revoke(self, delta: int | str | None = None, *, token: str) -> bool: ...
    @typing.overload
    def token_revoke(self, delta: int | str | None = None, *, accessor: str) -> bool: ...
    def token_revoke(
        self, delta: int | str | None = 1, *, token: str | None = None, accessor: str | None = None
    ):
        """
        Revoke a token by setting its TTL to 1s.

        delta
            Time in seconds to request revocation after.
            Defaults to 1s.

        token
            Token that should be revoked. Optional.
            If token and accessor are unset, revokes the token currently in use
            by this client.

        accessor
            Accessor of the token that should be revoked. Optional.
        """
        try:
            if token:
                self.token_renew(increment=delta, token=token)
            elif accessor:
                self.token_renew(increment=delta, accessor=accessor)
            else:
                raise TypeError("Either token or accessor is required")
        except (VaultPermissionDeniedError, VaultNotFoundError, VaultAuthExpired):
            # if we're trying to revoke ourselves and this happens,
            # the token was already invalid
            if token or accessor:
                raise
            return False
        return True

    def token_entity_id(self) -> str | typing.Literal[False]:
        """
        Get the entity ID of the current token.
        """
        tok = self.auth.get_token()
        if tok.entity_id is not None:
            return tok.entity_id
        # This means it has never been set. It should be set during creation,
        # so this is a migration functionality that should be dropped in a future version.
        info = self.token_lookup()
        self.auth.update_token({"entity_id": info["entity_id"] or False})
        return typing.cast(str | typing.Literal[False], self.auth.get_token().entity_id)

    def token_entity(self) -> Mapping[str, typing.Any] | None:
        """
        Get the entity data of the token's current entity or None, if it does not have an entity.
        """
        if self._entity is None:
            entity_id = self.token_entity_id()
            if not entity_id:
                return None
            self._entity = self.get(f"identity/entity/id/{entity_id}")["data"]
        return self._entity

    @typing.overload
    def token_entity_group(self, *, gid: str) -> dict[str, typing.Any] | None: ...
    @typing.overload
    def token_entity_group(self, *, name: str) -> dict[str, typing.Any] | None: ...
    def token_entity_group(
        self, *, gid: str | None = None, name: str | None = None
    ) -> dict[str, typing.Any] | None:
        """
        Get the group data of a group the current token belongs to.

        gid
            Group ID to lookup. Preferred. Either this or name is required.

        name
            Group name to lookup. Fallback. Either this or gid is required.
        """
        entity = self.token_entity()
        if not entity:
            return None

        group_ids = entity["group_ids"] or []
        if gid:
            if gid not in group_ids:
                return None
            if gid not in self._groups["id"]:
                group = self.get(f"identity/group/id/{gid}")["data"]
                self._groups["id"][group["id"]] = group
                self._groups["name"][group["name"]] = group
            return self._groups["id"][gid]
        if name:
            if name not in self._groups["name"]:
                group = self.get(f"identity/group/name/{name}")["data"]
                if group["id"] not in group_ids:
                    return None
                self._groups["id"][group["id"]] = group
                self._groups["name"][group["name"]] = group
            return self._groups["name"][name]
        raise TypeError("Either `name` or `gid` is required")

    def request_raw(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[typing.Any, typing.Any] | None = None,
        *,
        wrap: int | str | typing.Literal[False] = False,
        add_headers: dict[str, str] | None = None,
        safe_to_retry: bool | None = None,
        is_unauthd: bool = False,
        **kwargs,
    ) -> requests.Response:  # pylint: disable=arguments-differ
        """
        Issue an authenticated request against the Vault API. Returns the raw response object.
        """
        ret = super().request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            add_headers=add_headers,
            safe_to_retry=safe_to_retry,
            **kwargs,
        )
        # tokens are used regardless of status code
        if not is_unauthd and not endpoint.startswith(VAULT_UNAUTHD_PATHS):
            self.auth.used()
        return ret

    def _get_headers(self, wrap: int | str | typing.Literal[False] = False) -> dict[str, str]:
        headers = super()._get_headers(wrap)
        headers["X-Vault-Token"] = str(self.auth.get_token())
        return headers


class VaultAPIAdapter(requests.adapters.HTTPAdapter):
    """
    An adapter that

        * allows to restrict requests CA chain validation to a single
          root certificate without writing it to disk.
        * sets default values for timeout settings without having to
          specify it in every request.
    """

    max_retries: "VaultRetry"

    def __init__(
        self,
        *args,
        verify: bool | str | None = None,
        connect_timeout: float | int | None = None,
        read_timeout: float | int | None = None,
        **kwargs,
    ):
        ca_cert_data: str | None = None
        try:
            if verify.strip().startswith("-----BEGIN CERTIFICATE"):  # type: ignore
                verify = typing.cast(str, verify)
                ca_cert_data = verify
                verify = None
        except AttributeError:
            pass
        self.ca_cert_data = ca_cert_data
        self.verify = verify
        self.connect_timeout = connect_timeout or DEFAULT_CONNECT_TIMEOUT
        self.read_timeout = read_timeout or DEFAULT_READ_TIMEOUT
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = requests.adapters.DEFAULT_POOLBLOCK,
        **pool_kwargs: typing.Any,
    ):
        if self.ca_cert_data is not None:
            ssl_context = create_urllib3_context()
            ssl_context.load_verify_locations(cadata=self.ca_cert_data)
            pool_kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: float | tuple[float | None, float | None] | None = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
        proxies: dict[str, str] | None = None,
    ):
        """
        Wrap sending the request to ensure ``verify`` and ``timeout`` is set
        as specified on every request. ``timeout`` can be overridden per request.
        """
        if self.verify is not None:
            verify = self.verify
        if timeout is None:
            timeout = (self.connect_timeout, self.read_timeout)
        return super().send(
            request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies
        )


class VaultRetry(requests.adapters.Retry):
    """
    The Vault API responds with HTTP 429 when rate limits have been hit.
    We want to always retry 429, regardless of the HTTP verb and the presence
    of the ``Retry-After`` header, thus we need to subclass the retry configuration class.
    For HTTP error responses, we do not want to retry immediately if the header was not set.

    We override the default exponential power-of-2 algorithm for calculating
    the backoff time with a Fibonacci one because we expect a relatively
    quick turnaround.
    """

    PHI: float = 1.618
    SQRT5: float = 2.236

    def __init__(
        self,
        *args,
        backoff_jitter: float | int = 0.0,
        backoff_max: float = requests.adapters.Retry.DEFAULT_BACKOFF_MAX,
        retry_after_max: int | None = DEFAULT_RETRY_AFTER_MAX,
        **kwargs: typing.Any,
    ):
        """
        For ``urllib3<2``, backport ``backoff_max`` and ``backoff_jitter``.
        Also, allow limiting the value returned by ``Retry-After`` by
        specifying ``retry_after_max``.
        """
        if URLLIB3V1:
            self.backoff_max = backoff_max
            self.backoff_jitter = backoff_jitter
        else:
            kwargs["backoff_max"] = backoff_max
            kwargs["backoff_jitter"] = backoff_jitter
        super().__init__(*args, **kwargs)
        # urllib3 2.6.3 introduced the same parameter. Avoid having to guess
        # whether the parameter is supported by setting it ourselves.
        self.retry_after_max = retry_after_max
        self.safe_to_retry = None

    def _is_method_retryable(self, method: str) -> bool:
        """
        Some API calls can be safely retried, even if their HTTP method is not
        considered idempotent usually (e.g. POST for lookups).
        Other HTTP methods are generally considered idempotent, but are not
        for specific API calls (like DELETE on KVv2).

        Therefore, we allow to override the inbuilt HTTP method-only logic
        on a per-request basis.
        """
        if self.safe_to_retry is not None:
            return self.safe_to_retry
        return super()._is_method_retryable(method)

    def is_retry(self, method: str, status_code: int, has_retry_after: bool = False) -> bool:
        """
        HTTP 429 is always retryable (even for POST/PATCH), otherwise fall back
        to the configuration.
        """
        if status_code == HTTP_TOO_MANY_REQUESTS:
            return True
        return super().is_retry(method, status_code, has_retry_after=has_retry_after)

    def get_backoff_time(self) -> float:
        """
        When we're retrying HTTP error responses, ensure we don't execute the
        first retry immediately.
        Also overrides the default 2**n algorithm with one based on the Fibonacci sequence.
        On ``urllib3<2``, this also backports ``backoff_jitter`` and ``backoff_max``.
        """
        # We want to consider only the last consecutive errors sequence (Ignore redirects).
        consecutive_errors = list(
            takewhile(lambda x: x.redirect_location is None, reversed(self.history))
        )
        consecutive_errors_len = len(consecutive_errors)
        if consecutive_errors_len and consecutive_errors[0].status is not None:
            # Ensure we only immediately retry for local (connection/read) errors,
            # not when we got an HTTP response.
            consecutive_errors_len += 1
        if consecutive_errors_len <= 1:
            return 0
        # Approximate the nth Fibonacci number.
        # We want to begin with the 4th one (2).
        backoff_value = round(
            self.backoff_factor * round(self.PHI ** (consecutive_errors_len + 1) / self.SQRT5),
            1,
        )
        if self.backoff_jitter != 0.0:
            backoff_value += random.random() * self.backoff_jitter
        return float(max(0, min(self.backoff_max, backoff_value)))

    def get_retry_after(self, response: "urllib3response.BaseHTTPResponse") -> float | None:
        """
        The default implementation sleeps for as long as requested
        by the ``Retry-After`` header. We want to limit that somewhat
        to avoid sleeping until the end of the universe.
        """
        retry_after = response.headers.get("Retry-After")

        if retry_after is None:
            return None

        res = self.parse_retry_after(retry_after)
        if self.retry_after_max is None:
            return res
        return min(res, self.retry_after_max)

    def new(self, **kw: typing.Any) -> "Self":
        """
        Since we backport some params and introduce a new one,
        ensure all requests use the defined parameters, not the default ones.
        """
        ret = super().new(**kw)
        if URLLIB3V1:
            ret.backoff_jitter = self.backoff_jitter
            ret.backoff_max = self.backoff_max
        ret.retry_after_max = self.retry_after_max
        ret.safe_to_retry = self.safe_to_retry
        return ret
