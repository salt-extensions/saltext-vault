import threading
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

import pytest
import requests

from tests.common import gen_master_opts
from tests.common.containers import genmarks
from tests.support.vault import vault_delete
from tests.support.vault import vault_write

pytestmark = genmarks(mounts="ssh", policies=True)


@pytest.fixture(scope="module")
def intercepting_proxy(vault_port):
    """
    A reverse proxy in front of the Vault API that records all request lines
    and rejects the non-standard ``LIST`` method, mimicking HTTP
    intermediaries like AWS CloudFront.
    """
    request_log = []
    vault_url = f"http://127.0.0.1:{vault_port}"

    class ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _proxy(self):
            request_log.append((self.command, self.path))
            if self.command == "LIST":
                self.send_error(405, "Method Not Allowed")
                return
            body = None
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                body = self.rfile.read(length)
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("host", "content-length", "connection", "accept-encoding")
            }
            res = requests.request(
                self.command, vault_url + self.path, headers=headers, data=body, timeout=30
            )
            self.send_response(res.status_code)
            content_type = res.headers.get("Content-Type")
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(res.content)))
            self.end_headers()
            self.wfile.write(res.content)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_LIST = _proxy

        def log_message(self, *args):  # ty: ignore[invalid-method-override]
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", request_log
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()


@pytest.fixture(scope="module")
def master_config_overrides(intercepting_proxy):
    proxy_url, _ = intercepting_proxy
    return gen_master_opts(
        {"vault": {"client": {"list_as_get": True}}}, policies="ssh_admin", url=proxy_url
    )


@pytest.fixture(scope="module")
def ssh_role(secret_mounts):  # pylint: disable=unused-argument
    role = "list_as_get_test"
    vault_write(f"ssh/roles/{role}", key_type="otp", default_user="foo", cidr_list="10.0.0.0/8")
    try:
        yield role
    finally:
        vault_delete(f"ssh/roles/{role}")


def test_list_operation_with_master_configured_list_as_get(
    salt_call_cli, ssh_role, intercepting_proxy
):
    """
    Ensure the master-configured ``client:list_as_get`` option is propagated
    to minions with issued credentials and that their list operations issue
    ``GET`` requests with the ``list=true`` query parameter, which pass
    through intermediaries that reject the non-standard ``LIST`` method.
    """
    _, request_log = intercepting_proxy
    ret = salt_call_cli.run("vault_ssh.list_roles")
    assert ret.returncode == 0
    assert list(ret.data) == [ssh_role]
    assert ("GET", "/v1/ssh/roles?list=true") in request_log
    assert not any(method == "LIST" for method, _ in request_log)


def test_query_list_with_master_configured_list_as_get(salt_call_cli, ssh_role, intercepting_proxy):
    """
    Ensure ``LIST`` queries via the ``vault.query`` execution module function
    are dispatched as logical list operations, hence follow
    ``client:list_as_get`` as well.
    """
    _, request_log = intercepting_proxy
    ret = salt_call_cli.run("vault.query", "LIST", "ssh/roles")
    assert ret.returncode == 0
    assert ret.data["data"]["keys"] == [ssh_role]
    assert ("GET", "/v1/ssh/roles?list=true") in request_log
    assert not any(method == "LIST" for method, _ in request_log)
