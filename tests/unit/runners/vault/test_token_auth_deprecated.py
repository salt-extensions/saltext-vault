"""
Unit tests for the Vault runner

This module only tests a deprecated function, see
tests/unit/runners/test_vault.py for the current tests.
"""

import logging
from unittest.mock import ANY
from unittest.mock import Mock
from unittest.mock import patch

import pytest

import saltext.vault.utils.vault as vaultutil
from saltext.vault.runners import vault
from saltext.vault.utils.vault import client as vclient

pytestmark = [
    pytest.mark.usefixtures("validate_sig", "policies"),
]

log = logging.getLogger(__name__)


@pytest.fixture
def configure_loader_modules():
    return {
        vault: {
            "__opts__": {
                "vault": {
                    "url": "http://127.0.0.1",
                    "auth": {
                        "token": "test",
                        "method": "token",
                        "allow_minion_override": True,
                    },
                }
            }
        }
    }


@pytest.fixture
def auth():
    return {
        "auth": {
            "client_token": "test",
            "renewable": False,
            "lease_duration": 0,
        }
    }


@pytest.fixture
def client(auth):
    client_mock = Mock(vclient.AuthenticatedVaultClient)
    client_mock.post.return_value = auth
    with patch("saltext.vault.runners.vault._get_master_client", Mock(return_value=client_mock)):
        yield client_mock


@pytest.fixture
def validate_sig():
    with patch("saltext.vault.runners.vault._validate_signature", autospec=True, return_value=None):
        yield


@pytest.fixture
def policies():
    with patch("saltext.vault.runners.vault._get_policies_cached", autospec=True) as policies:
        policies.return_value = ["saltstack/minion/test-minion", "saltstack/minions"]
        yield policies


# Basic tests for test_generate_token: all exits


def test_generate_token(client):
    result = vault.generate_token("test-minion", "signature")
    log.debug("generate_token result: %s", result)
    assert isinstance(result, dict)
    assert "error" not in result
    assert "token" in result
    assert result["token"] == "test"
    client.post.assert_called_with("auth/token/create", payload=ANY, wrap=False)


def test_generate_token_uses(client):
    # Test uses
    num_uses = 6
    result = vault.generate_token("test-minion", "signature", uses=num_uses)
    assert "uses" in result
    assert result["uses"] == num_uses
    json_request = {
        "policies": ["saltstack/minion/test-minion", "saltstack/minions"],
        "num_uses": num_uses,
        "meta": {
            "saltstack-jid": "<no jid set>",
            "saltstack-minion": "test-minion",
            "saltstack-user": "<no user set>",
        },
    }
    client.post.assert_called_with("auth/token/create", payload=json_request, wrap=False)


def test_generate_token_ttl(client):
    # Test ttl
    expected_ttl = "6h"
    result = vault.generate_token("test-minion", "signature", ttl=expected_ttl)
    assert result["uses"] == 1
    json_request = {
        "policies": ["saltstack/minion/test-minion", "saltstack/minions"],
        "num_uses": 1,
        "explicit_max_ttl": expected_ttl,
        "meta": {
            "saltstack-jid": "<no jid set>",
            "saltstack-minion": "test-minion",
            "saltstack-user": "<no user set>",
        },
    }
    client.post.assert_called_with("auth/token/create", payload=json_request, wrap=False)


def test_generate_token_permission_denied(client):
    client.post.side_effect = vaultutil.VaultPermissionDeniedError("no reason")
    result = vault.generate_token("test-minion", "signature")
    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "VaultPermissionDeniedError: no reason"


def test_generate_token_exception(client):
    client.post.side_effect = Exception("Test Exception Reason")
    result = vault.generate_token("test-minion", "signature")
    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "Exception: Test Exception Reason"


def test_generate_token_no_matching_policies(policies):
    policies.return_value = []
    result = vault.generate_token("test-minion", "signature")
    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "SaltRunnerError: No policies matched minion."
