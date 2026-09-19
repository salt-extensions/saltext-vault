"""
Shared fixtures for the unit test suites.
"""

from unittest.mock import patch

import pytest

from saltext.vault.utils import vault as vaultutil


@pytest.fixture
def data():
    return {"foo": "bar"}


@pytest.fixture
def read_kv(data):
    with patch("saltext.vault.utils.vault.read_kv", autospec=True) as read:
        read.return_value = data
        yield read


@pytest.fixture
def write_kv():
    with patch("saltext.vault.utils.vault.write_kv", autospec=True) as write:
        yield write


@pytest.fixture
def write_kv_err(write_kv):
    write_kv.side_effect = vaultutil.VaultPermissionDeniedError("damn")
    yield write_kv


@pytest.fixture
def patch_kv():
    with patch("saltext.vault.utils.vault.patch_kv", autospec=True) as patch_kv:
        yield patch_kv


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", return_value=True, autospec=True) as _query:
        yield _query


@pytest.fixture
def secret_id_response():
    return {
        "request_id": "0e8c388e-2cb6-bcb2-83b7-625127d568bb",
        "lease_id": "",
        "lease_duration": 0,
        "renewable": False,
        "data": {
            "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
            "secret_id": "841771dc-11c9-bbc7-bcac-6a3945a69cd9",
            "secret_id_ttl": 60,
        },
    }


@pytest.fixture
def secret_id_serialized(secret_id_response):
    return {
        "secret_id": secret_id_response["data"]["secret_id"],
        "secret_id_ttl": secret_id_response["data"]["secret_id_ttl"],
        "secret_id_num_uses": 1,
        # + creation_time
        # + expire_time
    }


@pytest.fixture
def wrapped_response():
    return {
        "request_id": "",
        "lease_id": "",
        "lease_duration": 0,
        "renewable": False,
        "data": None,
        "warnings": None,
        "wrap_info": {
            "token": "test-wrapping-token",
            "accessor": "test-wrapping-token-accessor",
            "ttl": 180,
            "creation_time": "2022-09-10T13:37:12.123456789+00:00",
            "creation_path": "whatever/not/checked/here",
            "wrapped_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
        },
    }
