"""
Vault API client implementation
"""

import logging
import random
import re
from itertools import takewhile

import requests
import salt.exceptions
from requests.adapters import HTTPAdapter
from requests.adapters import Retry

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


log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)

# This list is not complete at all, but contains
# the most important paths.
VAULT_UNAUTHD_PATHS = (
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


def _get_expected_creation_path(secret_type, config=None):
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


class VaultClient:
    """
    Unauthenticated client for the Vault API.
    Base class for authenticated client.
    """

    def __init__(
        self,
        url,
        namespace=None,
        verify=None,
        session=None,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        read_timeout=DEFAULT_READ_TIMEOUT,
        max_retries=DEFAULT_MAX_RETRIES,
        backoff_factor=DEFAULT_BACKOFF_FACTOR,
        backoff_max=DEFAULT_BACKOFF_MAX,
        backoff_jitter=DEFAULT_BACKOFF_JITTER,
        retry_post=DEFAULT_RETRY_POST,
        respect_retry_after=DEFAULT_RESPECT_RETRY_AFTER,
        retry_status=DEFAULT_RETRY_STATUS,
        retry_after_max=DEFAULT_RETRY_AFTER_MAX,
    ):
        self.url = url
        self.namespace = namespace
        self.verify = verify

        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        # Cap the retry-backoff values somewhat
        self.max_retries = max(0, min(max_retries, MAX_MAX_RETRIES))
        self.backoff_factor = max(0, min(backoff_factor, MAX_BACKOFF_FACTOR))
        self.backoff_max = max(0, min(backoff_max, MAX_BACKOFF_MAX))
        self.backoff_jitter = max(0, min(backoff_jitter, MAX_BACKOFF_JITTER))
        self.retry_post = bool(retry_post)
        self.respect_retry_after = bool(respect_retry_after)
        self.retry_after_max = max(0, retry_after_max) if retry_after_max is not None else None
        self.retry_status = tuple(retry_status) if retry_status is not None else None

        retry = VaultRetry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            backoff_max=self.backoff_max,
            backoff_jitter=self.backoff_jitter,
            respect_retry_after_header=self.respect_retry_after,
            retry_after_max=self.retry_after_max,
            allowed_methods=None if retry_post else Retry.DEFAULT_ALLOWED_METHODS,
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
            adapter = session.get_adapter(url)
            adapter.max_retries = retry
            adapter.connect_timeout = self.connect_timeout
            adapter.read_timeout = self.read_timeout
        self.session = session

    def delete(self, endpoint, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("DELETE", ...)
        """
        return self.request(
            "DELETE",
            endpoint,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
        )

    def get(self, endpoint, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("GET", ...)
        """
        return self.request(
            "GET", endpoint, wrap=wrap, raise_error=raise_error, add_headers=add_headers
        )

    def list(self, endpoint, wrap=False, raise_error=True, add_headers=None):
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
        )

    def post(self, endpoint, payload=None, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("POST", ...)
        Vault considers POST and PUT to be synonymous.
        """
        return self.request(
            "POST",
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
        )

    def patch(self, endpoint, payload, wrap=False, raise_error=True, add_headers=None):
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
        )

    def request(
        self,
        method,
        endpoint,
        payload=None,
        wrap=False,
        raise_error=True,
        add_headers=None,
        **kwargs,
    ):
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

    def request_raw(self, method, endpoint, payload=None, wrap=False, add_headers=None, **kwargs):
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
            headers.update(add_headers)
        except TypeError:
            pass
        res = self.session.request(
            method,
            url,
            headers=headers,
            json=payload,
            **kwargs,
        )
        return res

    def unwrap(self, wrapped, expected_creation_path=None):
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
                token, there will be two unwrapping requests, causing an audit warning.
                If the attacker can issue a new wrapping token and insert it into the
                response instead, this warning would be silenced. Assuming they do not
                possess the permissions to issue a wrapping token from the correct
                endpoint, checking the creation path makes this kind of attack obvious.
        """
        if expected_creation_path:
            wrap_info = self.wrap_info(wrapped)
            if not isinstance(expected_creation_path, list):
                expected_creation_path = [expected_creation_path]
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

    def wrap_info(self, wrapped):
        """
        Lookup wrapping token meta information.
        """
        endpoint = "sys/wrapping/lookup"
        add_headers = {"X-Vault-Token": str(wrapped)}
        return self.post(endpoint, wrap=False, add_headers=add_headers)["data"]

    def token_lookup(self, token=None, accessor=None, raw=False):
        """
        Lookup token meta information.

        token
            The token to look up or to use to look up the accessor.
            Required.

        accessor
            The accessor to use to query the token meta information.

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
            endpoint = "auth/token/lookup-accessor"
            payload["accessor"] = accessor

        res = self.request_raw(
            method, endpoint, payload=payload, wrap=False, add_headers=add_headers
        )
        if raw:
            return res
        self._raise_status(res)
        return res.json()["data"]

    def token_valid(self, valid_for=0, remote=True):  # pylint: disable=unused-argument
        """
        This client does not have a token, hence it's always invalid.
        """
        return False

    def get_config(self):
        """
        Returns Vault server configuration used by this client.
        """
        return {
            "url": self.url,
            "namespace": self.namespace,
            "verify": self.verify,
        }

    def _get_url(self, endpoint):
        endpoint = endpoint.strip("/")
        return f"{self.url}/v1/{endpoint}"

    def _get_headers(self, wrap=False):
        headers = {"Content-Type": "application/json", "X-Vault-Request": "true"}
        if self.namespace is not None:
            headers["X-Vault-Namespace"] = self.namespace
        if wrap:
            headers["X-Vault-Wrap-TTL"] = str(wrap)
        return headers

    def _raise_status(self, res):
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

    auth = None

    def __init__(self, auth, url, **kwargs):
        self.auth = auth
        super().__init__(url, **kwargs)

    def token_valid(self, valid_for=0, remote=True):
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

    def token_lookup(self, token=None, accessor=None, raw=False):
        """
        Lookup token meta information.

        token
            The token to look up. If neither token nor accessor
            are specified, looks up the current token in use by
            this client.

        accessor
            The accessor of the token to query the meta information for.

        raw
            Return the raw response object instead of response data.
            Also disables status code checking.
        """
        endpoint = "auth/token/lookup"
        method = "POST"
        payload = {}
        if token is None and accessor is None:
            endpoint += "-self"
            method = "GET"
        if token is not None:
            payload["token"] = token
        elif accessor is not None:
            endpoint += "-accessor"
            payload["accessor"] = accessor
        if raw:
            return self.request_raw(method, endpoint, payload=payload, wrap=False)
        return self.request(method, endpoint, payload=payload, wrap=False)["data"]

    def token_renew(self, increment=None, token=None, accessor=None):
        """
        Renew a token.

        increment
            Request the token to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.

        token
            The token that should be renewed. Optional.
            If token and accessor are unset, renews the token currently in use
            by this client.

        accessor
            The accessor of the token that should be renewed. Optional.
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

    def token_revoke(self, delta=1, token=None, accessor=None):
        """
        Revoke a token by setting its TTL to 1s.

        delta
            The time in seconds to request revocation after.
            Defaults to 1s.

        token
            The token that should be revoked. Optional.
            If token and accessor are unset, revokes the token currently in use
            by this client.

        accessor
            The accessor of the token that should be revoked. Optional.
        """
        try:
            self.token_renew(increment=delta, token=token, accessor=accessor)
        except (VaultPermissionDeniedError, VaultNotFoundError, VaultAuthExpired):
            # if we're trying to revoke ourselves and this happens,
            # the token was already invalid
            if token or accessor:
                raise
            return False
        return True

    def request_raw(
        self,
        method,
        endpoint,
        payload=None,
        wrap=False,
        add_headers=None,
        is_unauthd=False,
        **kwargs,
    ):  # pylint: disable=arguments-differ
        """
        Issue an authenticated request against the Vault API. Returns the raw response object.
        """
        ret = super().request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            add_headers=add_headers,
            **kwargs,
        )
        # tokens are used regardless of status code
        if not is_unauthd and not endpoint.startswith(VAULT_UNAUTHD_PATHS):
            self.auth.used()
        return ret

    def _get_headers(self, wrap=False):
        headers = super()._get_headers(wrap)
        headers["X-Vault-Token"] = str(self.auth.get_token())
        return headers


class VaultAPIAdapter(HTTPAdapter):
    """
    An adapter that

        * allows to restrict requests CA chain validation to a single
          root certificate without writing it to disk.
        * sets default values for timeout settings without having to
          specify it in every request.
    """

    def __init__(self, *args, verify=None, connect_timeout=None, read_timeout=None, **kwargs):
        ca_cert_data = None
        try:
            if verify.strip().startswith("-----BEGIN CERTIFICATE"):
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
        connections,
        maxsize,
        block=requests.adapters.DEFAULT_POOLBLOCK,
        **pool_kwargs,
    ):
        if self.ca_cert_data is not None:
            ssl_context = create_urllib3_context()
            ssl_context.load_verify_locations(cadata=self.ca_cert_data)
            pool_kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
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


class VaultRetry(Retry):
    """
    The Vault API responds with HTTP 429 when rate limits have been hit.
    We want to always retry 429, regardless of the HTTP verb and the presence
    of the ``Retry-After`` header, thus we need to subclass the retry configuration class.
    For HTTP error responses, we do not want to retry immediately if the header was not set.

    We override the default exponential power-of-2 algorithm for calculating
    the backoff time with a Fibonacci one because we expect a relatively
    quick turnaround.
    """

    PHI = 1.618
    SQRT5 = 2.236

    def __init__(
        self,
        *args,
        backoff_jitter=0.0,
        backoff_max=Retry.DEFAULT_BACKOFF_MAX,
        retry_after_max=DEFAULT_RETRY_AFTER_MAX,
        **kwargs,
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
        self.retry_after_max = retry_after_max
        super().__init__(*args, **kwargs)

    def is_retry(self, method, status_code, has_retry_after=False):
        """
        HTTP 429 is always retryable (even for POST/PATCH), otherwise fall back
        to the configuration.
        """
        if status_code == HTTP_TOO_MANY_REQUESTS:
            return True
        return super().is_retry(method, status_code, has_retry_after=has_retry_after)

    def get_backoff_time(self):
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

    def get_retry_after(self, response):
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

    def new(self, **kw):
        """
        Since we backport some params and introduce a new one,
        ensure all requests use the defined parameters, not the default ones.
        """
        ret = super().new(**kw)
        if URLLIB3V1:
            ret.backoff_jitter = self.backoff_jitter
            ret.backoff_max = self.backoff_max
        ret.retry_after_max = self.retry_after_max
        return ret
