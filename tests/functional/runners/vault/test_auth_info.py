import pytest

from tests.conftest import CONTAINER_TARGETS

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
    pytest.mark.parametrize(
        "container", (CONTAINER_TARGETS[0],), indirect=True
    ),  # We only want to check the internal logic, not the API access
    pytest.mark.parametrize(
        "approle",
        ({"bind_secret_id": False, "token_bound_cidrs": ["0.0.0.0/1", "128.0.0.0/1"]},),
        indirect=True,
    ),
]


@pytest.fixture(scope="module", params=("token", "approle"))
def auth_method(request):
    return request.param


@pytest.fixture(scope="module")
def master_config_overrides(auth_method, approle):
    if auth_method == "token":
        return {}
    return {
        "vault": {
            "auth": {
                "method": "approle",
                "approle_mount": approle["mount"],
                "approle_name": "test-role",
                "role_id": approle["role_id"],
            },
        },
    }


@pytest.mark.usefixtures("master_config_overrides")
def test_auth_info(runners, auth_method):
    """
    Ensure ``auth_info`` reports token information for all authentication
    methods and does not fail when an AppRole does not require a SecretID.
    """
    info = runners.vault.auth_info()
    assert info["token"]
    if auth_method == "approle":
        # AppRole authentication with bind_secret_id: false
        assert info["secret_id"] is None
    else:
        # Token authentication does not involve a SecretID
        assert "secret_id" not in info
