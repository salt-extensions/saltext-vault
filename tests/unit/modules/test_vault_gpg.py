import base64
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.modules import vault_gpg
from saltext.vault.utils import vault


@pytest.fixture
def configure_loader_modules():
    return {
        vault_gpg: {
            "__grains__": {"id": "test-minion"},
        }
    }


@pytest.fixture
def query():
    with patch("saltext.vault.utils.vault.query", return_value=True, autospec=True) as _query:
        yield _query


@pytest.mark.parametrize(
    "func,kwargs",
    (
        ("create_key", {"name": "foo"}),
        ("import_key", {"name": "foo", "text": "dGVzdA=="}),
        ("list_keys", {}),
        ("read_key", {"name": "foo"}),
        ("delete_key", {"name": "foo"}),
        ("export_private_key", {"name": "foo"}),
        ("export_public_key", {"name": "foo"}),
        ("sign", {"name": "foo", "message": "hello"}),
        ("verify", {"name": "foo", "message": "hello", "sig": "sig"}),
        ("decrypt", {"name": "foo", "message": "hello"}),
        ("show_session_key", {"name": "foo", "message": "hello"}),
    ),
)
def test_func_converts_errors(func, kwargs, query):
    query.side_effect = vault.VaultException("booh")
    with pytest.raises(CommandExecutionError, match="booh"):
        getattr(vault_gpg, func)(**kwargs)


def test_sign_algorithm_endpoint_fallback_converts_errors(query):
    """
    When signing is denied, possibly because the policy only allows the
    algorithm-specific endpoint, the request is retried against it.
    Ensure errors of this backup query are converted as well.
    """
    query.side_effect = (
        vault.VaultPermissionDeniedError("nope"),
        vault.VaultException("booh"),
    )
    with pytest.raises(CommandExecutionError, match="booh"):
        vault_gpg.sign("foo", message="hello", algorithm="sha2-512")
    assert query.call_count == 2
    assert query.call_args[0][1] == "gpg/sign/foo/sha2-512"
    assert "algorithm" not in query.call_args[1]["payload"]


@pytest.mark.parametrize(
    "func,query_return",
    (
        ("export_private_key", {"data": {"key": "secret"}}),
        ("export_public_key", {"data": {"public_key": "public"}}),
    ),
)
def test_export_key_gnupg_import_failure(func, query_return, query):
    query.return_value = query_return
    gpg_import = MagicMock(return_value={"res": False, "message": "booh"})
    with patch.dict(vault_gpg.__salt__, {"gpg.import_key": gpg_import}):
        with pytest.raises(CommandExecutionError, match="booh"):
            getattr(vault_gpg, func)("foo", gnupg=True)
    assert gpg_import.call_args.kwargs["text"] == next(iter(query_return["data"].values()))


BLOCKTYPE = "PGP PUBLIC KEY BLOCK"
RAW_B64 = base64.b64encode(b"x" * 72).decode()  # 96 chars, forces line reflowing


@pytest.mark.parametrize(
    "key,expected",
    (
        # Properly ASCII-armored keys are passed through unmodified
        (
            f"-----BEGIN {BLOCKTYPE}-----\n\n{RAW_B64}\n-----END {BLOCKTYPE}-----",
            f"-----BEGIN {BLOCKTYPE}-----\n\n{RAW_B64}\n-----END {BLOCKTYPE}-----",
        ),
        # Raw base64 keys are reflowed to 64 columns and armored
        (
            RAW_B64,
            "\n".join(
                (
                    f"-----BEGIN {BLOCKTYPE}-----",
                    "",
                    "",
                    RAW_B64[:64],
                    RAW_B64[64:],
                    f"-----END {BLOCKTYPE}-----",
                )
            ),
        ),
        # Everything else is refused
        (
            "!!! not base64 !!!",
            None,
        ),
    ),
)
def test_fix_key(key, expected):
    if expected is None:
        with pytest.raises(CommandExecutionError, match="got neither"):
            vault_gpg._fix_key(key.encode(), BLOCKTYPE)
    else:
        assert vault_gpg._fix_key(key.encode(), BLOCKTYPE) == expected


def test_get_file_or_data_invalid_base64():
    with pytest.raises(SaltInvocationError, match="not Base64-encoded"):
        vault_gpg._get_file_or_data(None, None, b64="!!! not base64 !!!")
