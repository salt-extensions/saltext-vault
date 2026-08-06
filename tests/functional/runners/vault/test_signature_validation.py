import base64
from pathlib import Path

import pytest
import salt.crypt
import salt.exceptions

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
]

PEER_RUN_FUNCS = (
    "get_config",
    "get_role_id",
    "generate_secret_id",
    "generate_token",
    "generate_new_token",
)


@pytest.fixture(scope="module")
def minion_id():
    return "signature-test-minion"


@pytest.fixture(scope="module")
def minion_keys(tmp_path_factory):
    keydir = tmp_path_factory.mktemp("minion_keys")
    try:
        # Salt >= 3007 returns the generated keypair directly
        priv, pub = salt.crypt.gen_keys(2048)
    except (TypeError, ValueError):
        # Salt 3006 writes it to files in the specified directory
        salt.crypt.gen_keys(str(keydir), "minion", 2048)
    else:
        (keydir / "minion.pem").write_text(priv)
        (keydir / "minion.pub").write_text(pub)
    return keydir


@pytest.fixture(scope="module")
def _accepted_key(master_opts, minion_keys, minion_id):
    minions_dir = Path(master_opts["pki_dir"]) / "minions"
    minions_dir.mkdir(parents=True, exist_ok=True)
    (minions_dir / minion_id).write_bytes((minion_keys / "minion.pub").read_bytes())


@pytest.fixture(scope="module")
def valid_signature(minion_keys, minion_id):
    return base64.b64encode(salt.crypt.sign_message(str(minion_keys / "minion.pem"), minion_id))


@pytest.fixture(scope="module")
def invalid_signature(minion_keys):
    # This signs the wrong message, thus must not validate for minion_id
    return base64.b64encode(
        salt.crypt.sign_message(str(minion_keys / "minion.pem"), "rogue-minion")
    )


@pytest.mark.usefixtures("_accepted_key")
@pytest.mark.parametrize("func", PEER_RUN_FUNCS)
def test_peer_run_functions_deny_invalid_signatures(runners, func, minion_id, invalid_signature):
    with pytest.raises(
        salt.exceptions.AuthenticationError, match="Could not validate token request"
    ):
        getattr(runners.vault, func)(minion_id, invalid_signature)


@pytest.mark.usefixtures("_accepted_key")
@pytest.mark.parametrize("func", PEER_RUN_FUNCS)
def test_peer_run_functions_accept_valid_signatures(runners, func, minion_id, valid_signature):
    res = getattr(runners.vault, func)(minion_id, valid_signature)
    assert isinstance(res, dict)
    # Some functions return expected errors with the default configuration
    # (e.g. the master does not issue AppRoles), but the signature validation
    # must have passed.
    assert "Could not validate" not in str(res.get("error", ""))
