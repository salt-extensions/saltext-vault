import contextlib
from unittest.mock import ANY
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import call
from unittest.mock import patch

import pytest
import requests
import salt.exceptions
import urllib3.exceptions

from saltext.vault.utils import vault
from saltext.vault.utils.vault import client as vclient
from tests.unit.utils.vault.conftest import _mock_json_response  # pylint: disable=import-error


@pytest.mark.parametrize(
    "endpoint",
    [
        "secret/some/path",
        "/secret/some/path",
        "secret/some/path/",
        "/secret/some/path/",
    ],
)
def test_vault_client_request_raw_url(endpoint, client, req):
    """
    Test that requests are sent to the correct endpoint, regardless of leading or trailing slashes
    """
    expected_url = f"{client.url}/v1/secret/some/path"
    client.request_raw("GET", endpoint)
    req.assert_called_with(
        "GET",
        expected_url,
        headers=ANY,
        json=None,
    )


def test_vault_client_request_raw_kwargs_passthrough(client, req):
    """
    Test that kwargs for requests.request are passed through
    """
    client.request_raw(
        "GET", "secret/some/path", allow_redirects=False, cert="/etc/certs/client.pem"
    )
    req.assert_called_with(
        "GET",
        ANY,
        headers=ANY,
        json=ANY,
        allow_redirects=False,
        cert="/etc/certs/client.pem",
    )


@pytest.mark.parametrize("namespace", [None, "test-namespace"])
@pytest.mark.parametrize("client", [None], indirect=True)
def test_vault_client_request_raw_headers_namespace(namespace, client, req):
    """
    Test that namespace is present in the HTTP headers only if it was specified
    """
    if namespace is not None:
        client.namespace = namespace

    namespace_header = "X-Vault-Namespace"
    client.request_raw("GET", "secret/some/path")
    headers = req.call_args.kwargs.get("headers", {})
    if namespace is None:
        assert namespace_header not in headers
    else:
        assert headers.get(namespace_header) == namespace


@pytest.mark.parametrize("wrap", [False, 30, "1h"])
def test_vault_client_request_raw_headers_wrap(wrap, client, req):
    """
    Test that the wrap header is present only if it was specified and supports time strings
    """
    wrap_header = "X-Vault-Wrap-TTL"
    client.request_raw("GET", "secret/some/path", wrap=wrap)
    headers = req.call_args.kwargs.get("headers", {})
    if not wrap:
        assert wrap_header not in headers
    else:
        assert headers.get(wrap_header) == str(wrap)


@pytest.mark.parametrize("header", ["X-Custom-Header", "X-Existing-Header"])
def test_vault_client_request_raw_headers_additional(header, client, req):
    """
    Test that additional headers are passed correctly and override default ones
    """
    with patch.object(
        client, "_get_headers", Mock(return_value={"X-Existing-Header": "unchanged"})
    ):
        client.request_raw("GET", "secret/some/path", add_headers={header: "changed"})
        actual_header = req.call_args.kwargs.get("headers", {}).get(header)
        assert actual_header == "changed"


@pytest.mark.usefixtures("req_failed")
@pytest.mark.parametrize(
    "req_failed",
    [400, 403, 404, 502, 401],
    indirect=True,
)
@pytest.mark.parametrize(
    "client",
    [None],
    indirect=True,
)
def test_vault_client_request_raw_does_not_raise_http_exception(client):
    """
    request_raw should return the raw response object regardless of HTTP status code
    """
    res = client.request_raw("GET", "secret/some/path")
    with pytest.raises(requests.exceptions.HTTPError):
        res.raise_for_status()


@pytest.mark.parametrize(
    "req_failed,expected",
    [
        (400, vault.VaultInvocationError),
        (403, vault.VaultPermissionDeniedError),
        (404, vault.VaultNotFoundError),
        (405, vault.VaultUnsupportedOperationError),
        (412, vault.VaultPreconditionFailedError),
        (429, vault.VaultRateLimitExceededError),
        (500, vault.VaultServerError),
        (502, vault.VaultServerError),
        (503, vault.VaultUnavailableError),
        (401, requests.exceptions.HTTPError),
    ],
    indirect=["req_failed"],
)
@pytest.mark.parametrize("raise_error", [True, False])
def test_vault_client_request_respects_raise_error(
    raise_error, req_failed, expected, client
):  # pylint: disable=unused-argument
    """
    request should inspect the response object and raise appropriate errors
    or fall back to raise_for_status if raise_error is true
    """
    if raise_error:
        with pytest.raises(expected):
            client.request("GET", "secret/some/path", raise_error=raise_error)
    else:
        res = client.request("GET", "secret/some/path", raise_error=raise_error)
        assert "errors" in res


def test_vault_client_request_returns_whole_response_data(role_id_response, req, client):
    """
    request should return the whole returned payload, not auth/data etc only
    """
    req.return_value = _mock_json_response(role_id_response)
    res = client.request("GET", "auth/approle/role/test-minion/role-id")
    assert res == role_id_response


def test_vault_client_request_hydrates_wrapped_response(wrapped_role_id_response, req, client):
    """
    request should detect wrapped responses and return an instance of VaultWrappedResponse
    instead of raw data
    """
    req.return_value = _mock_json_response(wrapped_role_id_response)
    res = client.request("GET", "auth/approle/role/test-minion/role-id", wrap="180s")
    assert isinstance(res, vault.VaultWrappedResponse)


@pytest.mark.usefixtures("req_success")
def test_vault_client_request_returns_true_when_no_data_is_reported(client):
    """
    HTTP 204 indicates success with no data returned
    """
    res = client.request("GET", "secret/some/path")
    assert res is True


def test_vault_client_get_config(server_config, client):
    """
    The returned configuration should match the one used to create an instance of VaultClient
    """
    assert client.get_config() == server_config


@pytest.mark.parametrize("client", [None], indirect=["client"])
def test_vault_client_token_valid_false(client):
    """
    The unauthenticated client should always report the token as being invalid
    """
    assert client.token_valid() is False


@pytest.mark.parametrize("client", ["valid_token", "invalid_token"], indirect=True)
@pytest.mark.parametrize("req_any", [200, 403], indirect=True)
@pytest.mark.parametrize("remote", [False, True])
def test_vault_client_token_valid(client, remote, req_any):
    valid = client.token_valid(remote=remote)
    if not remote or not client.auth.is_valid():
        req_any.assert_not_called()
    else:
        req_any.assert_called_once()
    should_be_valid = client.auth.is_valid() and (
        not remote or req_any("POST", "abc").status_code == 200
    )
    assert valid is should_be_valid


@pytest.mark.parametrize("func", ["get", "delete", "post", "list"])
def test_vault_client_wrapper_should_not_require_payload(func, client, req):
    """
    Check that wrappers for get/delete/post/list do not require a payload
    """
    req.return_value = _mock_json_response({}, status_code=200)
    tgt = getattr(client, func)
    res = tgt("auth/approle/role/test-role/secret-id")
    assert res == {}


@pytest.mark.parametrize("func", ["patch"])
def test_vault_client_wrapper_should_require_payload(func, client, req):
    """
    Check that patch wrapper does require a payload
    """
    req.return_value = _mock_json_response({}, status_code=200)
    tgt = getattr(client, func)
    with pytest.raises(TypeError):
        tgt("auth/approle/role/test-role/secret-id")


def test_vault_client_wrap_info_only_data(wrapped_role_id_lookup_response, client, req):
    """
    wrap_info should only return the data portion of the returned wrapping information
    """
    req.return_value = _mock_json_response(wrapped_role_id_lookup_response)
    res = client.wrap_info("test-wrapping-token")
    assert res == wrapped_role_id_lookup_response["data"]


@pytest.mark.parametrize(
    "req_failed,expected", [(502, vault.VaultServerError)], indirect=["req_failed"]
)
def test_vault_client_wrap_info_should_fail_with_sensible_response(
    expected, req_failed, client
):  # pylint: disable=unused-argument
    """
    wrap_info should return sensible Exceptions, not KeyError etc
    """
    with pytest.raises(expected):
        client.wrap_info("test-wrapping-token")


def test_vault_client_unwrap_returns_whole_response(role_id_response, client, req):
    """
    The unwrapped response should be returned as a whole, not auth/data etc only
    """
    req.return_value = _mock_json_response(role_id_response)
    res = client.unwrap("test-wrapping-token")
    assert res == role_id_response


def test_vault_client_unwrap_should_default_to_token_header_before_payload(
    role_id_response, client, req
):
    """
    When unwrapping a wrapping token, it can be used as the authentication token header.
    If the client has a valid token, it should be used in the header instead and the
    unwrapping token should be passed in the payload
    """
    token = "test-wrapping-token"
    req.return_value = _mock_json_response(role_id_response)
    client.unwrap(token)
    if client.token_valid(remote=False):
        payload = req.call_args.kwargs.get("json", {})
        assert payload.get("token") == token
    else:
        headers = req.call_args.kwargs.get("headers", {})
        assert headers.get("X-Vault-Token") == token


@pytest.mark.parametrize("func", ["unwrap", "token_lookup"])
@pytest.mark.parametrize(
    "req_failed,expected",
    [
        (400, vault.VaultInvocationError),
        (403, vault.VaultPermissionDeniedError),
        (404, vault.VaultNotFoundError),
        (502, vault.VaultServerError),
        (401, requests.exceptions.HTTPError),
    ],
    indirect=["req_failed"],
)
def test_vault_client_unwrap_should_raise_appropriate_errors(
    func, req_failed, expected, client
):  # pylint: disable=unused-argument
    """
    unwrap/token_lookup should raise exceptions the same way request does
    """
    with pytest.raises(expected):
        tgt = getattr(client, func)
        tgt("test-wrapping-token")


@pytest.mark.usefixtures("req_unwrapping")
@pytest.mark.parametrize(
    "path",
    [
        "auth/approle/role/test-minion/role-id",
        "auth/approle/role/[^/]+/role-id",
        ["incorrect/path", "[^a]+", "auth/approle/role/[^/]+/role-id"],
    ],
)
def test_vault_client_unwrap_should_match_check_expected_creation_path(
    path, role_id_response, client
):
    """
    Expected creation paths should be accepted as strings and list of strings,
    where the strings can be regex patterns
    """
    res = client.unwrap("test-wrapping-token", expected_creation_path=path)
    assert res == role_id_response


@pytest.mark.usefixtures("req_unwrapping")
@pytest.mark.parametrize(
    "path",
    [
        "auth/other_mount/role/test-minion/role-id",
        "auth/approle/role/[^tes/]+/role-id",
        ["incorrect/path", "[^a]+", "auth/approle/role/[^/]/role-id"],
    ],
)
def test_vault_client_unwrap_should_fail_on_unexpected_creation_path(path, client):
    """
    When none of the patterns match, a (serious) exception should be raised
    """
    with pytest.raises(vault.VaultUnwrapException):
        client.unwrap("test-wrapping-token", expected_creation_path=path)


def test_vault_client_token_lookup_returns_data_only(token_lookup_self_response, req, client):
    """
    token_lookup should return "data" only, not the whole response payload
    """
    req.return_value = _mock_json_response(token_lookup_self_response)
    res = client.token_lookup("test-token")
    assert res == token_lookup_self_response["data"]


@pytest.mark.parametrize("raw", [False, True])
def test_vault_client_token_lookup_respects_raw(raw, req, client):
    """
    when raw is True, token_lookup should return the raw response
    """
    response_data = {"foo": "bar"}
    req.return_value = _mock_json_response({"data": response_data})
    res = client.token_lookup("test-token", raw=raw)
    if raw:
        assert res.json() == {"data": response_data}
    else:
        assert res == response_data


def test_vault_client_token_lookup_uses_accessor(client, req_any):
    """
    Ensure a client can lookup tokens with provided accessor
    """
    token = "test-token"
    if client.token_valid():
        token = None
    client.token_lookup(token=token, accessor="test-token-accessor")
    payload = req_any.call_args.kwargs.get("json", {})
    _, url = req_any.call_args[0]
    assert payload.get("accessor") == "test-token-accessor"
    assert url.endswith("lookup-accessor")


# VaultClient only


@pytest.mark.usefixtures("req")
@pytest.mark.parametrize("client", [None], indirect=["client"])
def test_vault_client_token_lookup_requires_token_for_unauthenticated_client(client):
    with pytest.raises(vault.VaultInvocationError):
        client.token_lookup()


# AuthenticatedVaultClient only


@pytest.mark.usefixtures("req_any")
@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
@pytest.mark.parametrize(
    "endpoint,use",
    [
        ("secret/data/some/path", True),
        ("auth/approle/role/test-minion", True),
        ("sys/internal/ui/mounts", False),
        ("sys/internal/ui/mounts/secret", False),
        ("sys/wrapping/lookup", False),
        ("sys/internal/ui/namespaces", False),
        ("sys/health", False),
        ("sys/seal-status", False),
    ],
)
def test_vault_client_request_raw_increases_use_count_when_necessary_depending_on_path(
    endpoint, use, client
):
    """
    When a request is issued to an endpoint that consumes a use, ensure it is passed
    along to the token.
    https://github.com/hashicorp/vault/blob/d467681e15898041b6dd5f2bf7789bd7c236fb16/vault/logical_system.go#L119-L155
    """
    client.request_raw("GET", endpoint)
    assert client.auth.used.called is use


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
@pytest.mark.parametrize(
    "req_failed",
    [400, 403, 404, 405, 412, 500, 502, 503, 401],
    indirect=True,
)
def test_vault_client_request_raw_increases_use_count_when_necessary_depending_on_response(
    client, req_failed  # pylint: disable=unused-argument
):
    """
    When a request is issued to an endpoint that consumes a use, make sure that
    this is registered regardless of status code:
    https://github.com/hashicorp/vault/blob/c1cf97adac5c53301727623a74b828a5f12592cf/vault/request_handling.go#L864-L866
    ref: PR #62552
    """
    client.request_raw("GET", "secret/data/some/path")
    assert client.auth.used.called is True


@pytest.mark.usefixtures("req_any")
@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
def test_vault_client_request_raw_does_not_increase_use_count_with_unauthd_endpoint(
    client,
):
    """
    Unauthenticated endpoints do not consume a token use. Since some cannot be detected
    easily because of customizable mount points for secret engines and auth methods,
    this can be specified in the request. Make sure it is honored.
    """
    client.request("GET", "pki/cert/ca", is_unauthd=True)
    client.auth.used.assert_not_called()


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
def test_vault_client_token_lookup_self_possible(client, req_any):
    """
    Ensure an authenticated client can lookup its own token
    """
    client.token_lookup()
    headers = req_any.call_args.kwargs.get("headers", {})
    _, url = req_any.call_args[0]
    assert headers.get("X-Vault-Token") == str(client.auth.get_token())
    assert url.endswith("lookup-self")


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
def test_vault_client_token_lookup_supports_token_arg(client, req_any):
    """
    Ensure an authenticated client can lookup other tokens
    """
    token = "other-test-token"
    client.token_lookup(token=token)
    headers = req_any.call_args.kwargs.get("headers", {})
    payload = req_any.call_args.kwargs.get("json", {})
    _, url = req_any.call_args[0]
    assert payload.get("token") == token
    assert headers.get("X-Vault-Token") == str(client.auth.get_token())
    assert url.endswith("lookup")


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
@pytest.mark.parametrize("renewable", [True, False])
def test_vault_client_token_renew_self_possible(token_renew_self_response, client, req, renewable):
    """
    Ensure an authenticated client can renew its own token only when
    it is renewable and that the renewed data is passed along to the
    token store
    """
    req.return_value = _mock_json_response(token_renew_self_response)
    client.auth.is_renewable.return_value = renewable
    res = client.token_renew()
    if renewable:
        headers = req.call_args.kwargs.get("headers", {})
        _, url = req.call_args[0]
        assert headers.get("X-Vault-Token") == str(client.auth.get_token())
        assert url.endswith("renew-self")
        req.assert_called_once()
        client.auth.update_token.assert_called_once_with(token_renew_self_response["auth"])
        assert res == token_renew_self_response["auth"]
    else:
        assert res is False


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
def test_vault_client_token_renew_supports_token_arg(token_renew_other_response, client, req):
    """
    Ensure an authenticated client can renew other tokens
    """
    req.return_value = _mock_json_response(token_renew_other_response)
    token = "other-test-token"
    client.token_renew(token=token)
    headers = req.call_args.kwargs.get("headers", {})
    payload = req.call_args.kwargs.get("json", {})
    _, url = req.call_args[0]
    assert payload.get("token") == token
    assert headers.get("X-Vault-Token") == str(client.auth.get_token())
    assert url.endswith("renew")


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
def test_vault_client_token_renew_uses_accessor(token_renew_accessor_response, client, req):
    """
    Ensure a client can renew tokens with provided accessor
    """
    req.return_value = _mock_json_response(token_renew_accessor_response)
    client.token_renew(accessor="test-token-accessor")
    payload = req.call_args.kwargs.get("json", {})
    _, url = req.call_args[0]
    assert payload.get("accessor") == "test-token-accessor"
    assert url.endswith("renew-accessor")


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
@pytest.mark.parametrize("token", [None, "other-test-token"])
def test_vault_client_token_renew_self_updates_token(token_renew_self_response, client, token, req):
    """
    Ensure the current client token is updated when it is renewed, but not
    when another token is renewed
    """
    req.return_value = _mock_json_response(token_renew_self_response)
    client.token_renew(token=token)
    if token is None:
        assert client.auth.update_token.called
    else:
        assert not client.auth.update_token.called


@pytest.mark.parametrize("client", ["valid_token"], indirect=True)
@pytest.mark.parametrize(
    "token,accessor",
    [(None, None), ("other-test-token", None), (None, "test-accessor")],
)
def test_vault_client_token_renew_increment_is_honored(
    token, accessor, client, token_renew_self_response, req
):
    """
    Ensure the renew increment is passed to vault if provided
    """
    req.return_value = _mock_json_response(token_renew_self_response)
    client.token_renew(token=token, accessor=accessor, increment=3600)
    payload = req.call_args.kwargs.get("json", {})
    assert payload.get("increment") == 3600


@pytest.mark.parametrize(
    "secret,config,expected",
    [
        ("token", None, r"auth/token/create(/[^/]+)?"),
        ("secret_id", None, r"auth/[^/]+/role/[^/]+/secret\-id"),
        ("role_id", None, r"auth/[^/]+/role/[^/]+/role\-id"),
        (
            "secret_id",
            {"auth": {"approle_mount": "test_mount", "approle_name": "test_minion"}},
            r"auth/test_mount/role/test_minion/secret\-id",
        ),
        (
            "role_id",
            {"auth": {"approle_mount": "test_mount", "approle_name": "test_minion"}},
            r"auth/test_mount/role/test_minion/role\-id",
        ),
        (
            "secret_id",
            {"auth": {"approle_mount": "te$t-mount", "approle_name": "te$t-minion"}},
            r"auth/te\$t\-mount/role/te\$t\-minion/secret\-id",
        ),
        (
            "role_id",
            {"auth": {"approle_mount": "te$t-mount", "approle_name": "te$t-minion"}},
            r"auth/te\$t\-mount/role/te\$t\-minion/role\-id",
        ),
    ],
)
def test_get_expected_creation_path(secret, config, expected):
    """
    Ensure expected creation paths are resolved as expected
    """
    assert (
        vclient._get_expected_creation_path(secret, config)  # pylint: disable=protected-access
        == expected
    )


def test_get_expected_creation_path_fails_for_unknown_type():
    """
    Ensure unknown source types result in an exception
    """
    with pytest.raises(salt.exceptions.SaltInvocationError):
        vclient._get_expected_creation_path("nonexistent")  # pylint: disable=protected-access


@pytest.fixture
def _send_mock():
    with patch("saltext.vault.utils.vault.client.HTTPAdapter.send", autospec=True) as send:
        send.return_value.is_redirect = False
        yield send


@pytest.mark.parametrize(
    "server_config",
    [
        {
            "url": "https://127.0.0.1:8200",
            "verify": "-----BEGIN CERTIFICATE-----testcert",
        }
    ],
    indirect=True,
)
def test_vault_api_adapter_pem(server_config, _send_mock):
    """
    Test that the ``verify`` parameter to the client can contain a PEM-encoded certificate
    which will be used as the sole trust anchor for the Vault URL.
    The ``verify`` parameter to ``HTTPAdapter.send`` should be the default (True)
    in that case since it requires a local file path.
    """
    with patch("saltext.vault.utils.vault.client.create_urllib3_context", autospec=True) as tls:
        client = vclient.VaultClient(**server_config, connect_timeout=42, read_timeout=1337)
        tls.return_value.load_verify_locations.assert_called_once_with(
            cadata=server_config["verify"]
        )
        client.request_raw("GET", "test")
    _send_mock.assert_called_once_with(
        ANY, ANY, stream=ANY, timeout=ANY, verify=True, cert=None, proxies=ANY
    )


def test_vault_api_adapter_timeout_default(server_config, _send_mock):
    """
    Ensure the timeout defaults are set by the adapter.
    """
    client = vclient.VaultClient(**server_config, connect_timeout=42, read_timeout=1337)
    client.request_raw("GET", "test")
    _send_mock.assert_called_once_with(
        ANY, ANY, stream=ANY, timeout=(42, 1337), verify=ANY, cert=ANY, proxies=ANY
    )


def test_vault_api_adapter_timeout_override(server_config, _send_mock):
    """
    Ensure the timeout defaults can be overridden.
    """
    client = vclient.VaultClient(**server_config, connect_timeout=42, read_timeout=1337)
    client.request_raw("GET", "test", timeout=1234)
    _send_mock.assert_called_once_with(
        ANY, ANY, stream=ANY, timeout=1234, verify=ANY, cert=ANY, proxies=ANY
    )


@pytest.mark.parametrize(
    "server_config",
    [
        {
            "url": "https://127.0.0.1:8200",
            "verify": False,
        },
        {
            "url": "https://127.0.0.1:8200",
            "verify": "/some/path",
        },
    ],
    indirect=True,
)
def test_vault_api_adapter_verify_set(server_config, _send_mock):
    """
    Ensure the ``verify`` parameter is always set as specified.
    """
    with patch("saltext.vault.utils.vault.client.create_urllib3_context", autospec=True) as tls:
        client = vclient.VaultClient(**server_config)
        client.request_raw("GET", "test")
        _send_mock.assert_called_once_with(
            ANY,
            ANY,
            stream=ANY,
            timeout=ANY,
            verify=server_config["verify"],
            cert=ANY,
            proxies=ANY,
        )
        tls.assert_not_called()


@pytest.fixture
def sleep_mock():
    with patch("time.sleep") as sleep:
        yield sleep


@pytest.fixture(params=({},))
def req_mock(request):
    headers = {}
    msg_mock = MagicMock()
    msg_mock.values.side_effect = headers.values
    msg_mock.keys.side_effect = headers.keys
    msg_mock.items.side_effect = headers.items
    msg_mock.get.side_effect = headers.get
    msg_mock.get_all.return_value = {}
    params = getattr(request, "param", {})
    status = params.get("status", 500)
    retry_after = params.get("retry_after")
    error = params.get("err")
    if error is not None:
        conn_ctx = patch(
            "urllib3.connectionpool.HTTPConnectionPool._new_conn", autospec=True, side_effect=error
        )
        exp_ctx = pytest.raises(requests.exceptions.ConnectionError)
    else:
        conn_ctx = patch("urllib3.connectionpool.HTTPConnectionPool._make_request", autospec=True)
        exp_ctx = contextlib.nullcontext()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    with conn_ctx as req:
        if error is not None:
            req.side_effect = error
        else:
            req.return_value.get_redirect_location.return_value = None
            req.return_value.cookies = None
            req.return_value.msg = msg_mock  # urllib <2
            req.return_value.headers = headers  # urllib >=2
            req.return_value.status = status
        yield req, exp_ctx


@pytest.mark.parametrize(
    "req_mock,cnt,slept,respect_retry_after",
    (
        ({"status": 200}, 1, 0, True),
        ({"status": 204}, 1, 0, True),
        ({"status": 412}, 6, 5, True),
        ({"status": 429}, 6, 5, True),
        ({"status": 500}, 6, 5, True),
        ({"status": 502}, 6, 5, True),
        ({"status": 503}, 6, 5, True),
        ({"status": 504}, 6, 5, True),
        ({"err": urllib3.exceptions.ConnectTimeoutError}, 6, 4, True),
        ({"err": urllib3.exceptions.ProtocolError}, 6, 4, True),
        (
            {
                "err": urllib3.exceptions.ReadTimeoutError(
                    MagicMock(), "http://127.0.0.1/v1/test", "foo"
                )
            },
            6,
            4,
            True,
        ),
        ({"status": 200, "retry_after": "1234"}, 1, 0, True),
        ({"status": 204, "retry_after": "1234"}, 1, 0, True),
        ({"status": 412, "retry_after": "1234"}, 6, 5, False),
        ({"status": 429, "retry_after": "1234"}, 6, 5, False),
        ({"status": 500, "retry_after": "1234"}, 6, 5, False),
        ({"status": 502, "retry_after": "1234"}, 6, 5, False),
        ({"status": 503, "retry_after": "1234"}, 6, 5, False),
        ({"status": 504, "retry_after": "1234"}, 6, 5, False),
        ({"err": urllib3.exceptions.ConnectTimeoutError}, 6, 4, False),
        ({"err": urllib3.exceptions.ProtocolError}, 6, 4, False),
        (
            {
                "err": urllib3.exceptions.ReadTimeoutError(
                    MagicMock(), "http://127.0.0.1/v1/test", "foo"
                )
            },
            6,
            4,
            False,
        ),
    ),
    indirect=("req_mock",),
)
def test_vault_retry(server_config, cnt, slept, respect_retry_after, req_mock, sleep_mock):
    """
    Ensure the client retries specific response codes only.
    HTTP error responses should not retry immediately, only connection/read errors.
    """
    client = vclient.VaultClient(
        **server_config, respect_retry_after=respect_retry_after, backoff_jitter=0.0
    )
    with req_mock[1]:
        client.request_raw("GET", "test")
    assert req_mock[0].call_count == cnt
    default_sleep = [0.2, 0.3, 0.5, 0.8, 1.3, 2.1, 3.4]
    calls = [call(default_sleep[x]) for x in range(slept)]
    assert sleep_mock.call_args_list == calls


@pytest.mark.parametrize(
    "req_mock",
    (
        {"status": 412, "retry_after": "42"},
        {"status": 429, "retry_after": "42"},
        {"status": 500, "retry_after": "42"},
        {"status": 502, "retry_after": "42"},
        {"status": 503, "retry_after": "42"},
        {"status": 504, "retry_after": "42"},
    ),
    indirect=True,
)
def test_vault_retry_retry_after(server_config, req_mock, sleep_mock):
    """
    Ensure the Retry-After header is respected by default and overrides
    the backoff algorithm.
    """
    client = vclient.VaultClient(**server_config, backoff_jitter=0.0)
    client.request_raw("GET", "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1
    calls = [call(42) for x in range(5)]
    assert sleep_mock.call_args_list == calls


@pytest.mark.parametrize(
    "req_mock",
    (
        {"status": 412, "retry_after": "9999999999"},
        {"status": 429, "retry_after": "9999999999"},
        {"status": 500, "retry_after": "9999999999"},
        {"status": 502, "retry_after": "9999999999"},
        {"status": 503, "retry_after": "9999999999"},
        {"status": 504, "retry_after": "9999999999"},
    ),
    indirect=True,
)
@pytest.mark.parametrize("disabled", (False, True))
def test_vault_retry_retry_after_max(server_config, disabled, req_mock, sleep_mock):
    """
    Ensure the Retry-After header is respected by default and overrides
    the backoff algorithm.
    """
    kwargs = {}
    if disabled:
        kwargs["retry_after_max"] = None
    client = vclient.VaultClient(**server_config, backoff_jitter=0.0, **kwargs)
    client.request_raw("GET", "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1
    calls = [call(60 if not disabled else 9999999999) for x in range(5)]
    assert sleep_mock.call_args_list == calls


@pytest.mark.parametrize(
    "req_mock,slept",
    (
        ({"err": urllib3.exceptions.ConnectTimeoutError}, 4),
        ({"err": urllib3.exceptions.ProtocolError}, 4),
        (
            {
                "err": urllib3.exceptions.ReadTimeoutError(
                    MagicMock(), "http://127.0.0.1/v1/test", "foo"
                )
            },
            4,
        ),
        ({"status": 412}, 5),
        ({"status": 429}, 5),
        ({"status": 500}, 5),
        ({"status": 502}, 5),
        ({"status": 503}, 5),
        ({"status": 504}, 5),
    ),
    indirect=("req_mock",),
)
def test_vault_retry_backoff_factor(server_config, slept, req_mock, sleep_mock):
    """
    Ensure the backoff_factor has an effect.
    """
    client = vclient.VaultClient(**server_config, backoff_factor=0.2, backoff_jitter=0.0)
    with req_mock[1]:
        client.request_raw("GET", "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1
    default_sleep = [0.4, 0.6, 1.0, 1.6, 2.6, 4.2, 6.8]
    calls = [call(default_sleep[x]) for x in range(slept)]
    assert sleep_mock.call_args_list == calls


@pytest.mark.parametrize(
    "req_mock,slept",
    (
        ({"err": urllib3.exceptions.ConnectTimeoutError}, 4),
        ({"err": urllib3.exceptions.ProtocolError}, 4),
        (
            {
                "err": urllib3.exceptions.ReadTimeoutError(
                    MagicMock(), "http://127.0.0.1/v1/test", "foo"
                )
            },
            4,
        ),
        ({"status": 412}, 5),
        ({"status": 429}, 5),
        ({"status": 500}, 5),
        ({"status": 502}, 5),
        ({"status": 503}, 5),
        ({"status": 504}, 5),
    ),
    indirect=("req_mock",),
)
def test_vault_retry_backoff_max(server_config, slept, req_mock, sleep_mock):
    """
    Ensure backoff_max has an effect.
    """
    client = vclient.VaultClient(
        **server_config, backoff_factor=3, backoff_max=10, backoff_jitter=0.0
    )
    with req_mock[1]:
        client.request_raw("GET", "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1
    default_sleep = [6.0, 9.0, 10.0, 10.0, 10.0, 10.0, 10.0]
    calls = [call(default_sleep[x]) for x in range(slept)]
    assert sleep_mock.call_args_list == calls


@pytest.mark.parametrize("max_retries", (0, 8))
@pytest.mark.parametrize(
    "req_mock,slept",
    (
        ({"err": urllib3.exceptions.ConnectTimeoutError}, -1),
        ({"err": urllib3.exceptions.ProtocolError}, -1),
        (
            {
                "err": urllib3.exceptions.ReadTimeoutError(
                    MagicMock(), "http://127.0.0.1/v1/test", "foo"
                )
            },
            -1,
        ),
        ({"status": 412}, 0),
        ({"status": 429}, 0),
        ({"status": 500}, 0),
        ({"status": 502}, 0),
        ({"status": 503}, 0),
        ({"status": 504}, 0),
    ),
    indirect=("req_mock",),
)
def test_vault_retry_max_retries(server_config, max_retries, slept, req_mock, sleep_mock):
    """
    Ensure max_retries has an effect.
    """
    client = vclient.VaultClient(**server_config, max_retries=max_retries, backoff_jitter=0.0)
    with req_mock[1]:
        client.request_raw("GET", "test")
    assert req_mock[0].call_count == max_retries + 1
    default_sleep = [0.2, 0.3, 0.5, 0.8, 1.3, 2.1, 3.4, 5.5]
    calls = [call(default_sleep[x]) for x in range(max_retries + slept)]
    assert sleep_mock.call_args_list == calls


@pytest.mark.usefixtures("sleep_mock")
@pytest.mark.parametrize("method", ("POST", "PATCH"))
def test_vault_retry_post_not_default(server_config, method, req_mock):
    """
    Ensure that by default, we don't retry potentially non-idempotent actions.
    """
    client = vclient.VaultClient(**server_config)
    client.request_raw(method, "test")
    assert req_mock[0].call_count == 1


@pytest.mark.usefixtures("sleep_mock")
@pytest.mark.parametrize("req_mock", ({"status": 429},), indirect=True)
@pytest.mark.parametrize("method", ("POST", "PATCH"))
def test_vault_retry_post_with_too_many_requests(server_config, method, req_mock):
    """
    Ensure 429 is always retried, even with POST/PATCH.
    """
    client = vclient.VaultClient(**server_config)
    client.request_raw(method, "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1


@pytest.mark.usefixtures("sleep_mock")
@pytest.mark.parametrize("method", ("POST", "PATCH"))
def test_vault_retry_post_enabled(server_config, method, req_mock):
    """
    Ensure POST/PATCH requests are retried if enabled.
    """
    client = vclient.VaultClient(**server_config, retry_post=True)
    client.request_raw(method, "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1


@pytest.mark.usefixtures("sleep_mock")
@pytest.mark.parametrize("statuses", ((412,), None))
def test_vault_retry_status(server_config, statuses, req_mock):
    """
    Ensure retry_status can be set and HTTP 429 is retried
    regardless.
    """
    client = vclient.VaultClient(**server_config, retry_status=statuses)
    client.request_raw("GET", "test")
    assert req_mock[0].call_count == 1
    req_mock[0].return_value.status = 429
    client.request_raw("GET", "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 2


def test_vault_retry_backoff_jitter(server_config, req_mock, sleep_mock):
    """
    Ensure that by default, we introduce some jitter to retry intervals.
    """
    client = vclient.VaultClient(**server_config, backoff_factor=1, backoff_max=100)
    client.request_raw("GET", "test")
    assert req_mock[0].call_count == vclient.DEFAULT_MAX_RETRIES + 1
    default_sleep = [2.0, 3.0, 5.0, 8.0, 13.0, 21.0, 43.0]
    assert len(sleep_mock.call_args_list) == vclient.DEFAULT_MAX_RETRIES
    for exp, cll in zip(default_sleep, sleep_mock.call_args_list):
        # random.random returning 0 exactly should be very seldom,
        # so let's accept a tiny bit of flakiness
        assert exp + vclient.DEFAULT_BACKOFF_JITTER >= cll.args[0] > exp
