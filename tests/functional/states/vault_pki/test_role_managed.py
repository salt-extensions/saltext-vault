"""
Tests for the role_managed/role_absent states.
"""

import pytest

from tests.common.containers import genmarks
from tests.support.vault import vault_list
from tests.support.vault import vault_read

pytestmark = genmarks(mounts="pki")


@pytest.mark.usefixtures("issuer_setup")
def test_role_managed(vault_pki, testmode):
    ret = vault_pki.role_managed("dummy", test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "created" in ret.changes
    assert ("dummy" in vault_list("pki/roles")) is not testmode

    if not testmode:
        ret = vault_pki.role_managed("dummy", test=testmode)
        assert ret.result
        assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "issuer_setup_additional")
@pytest.mark.parametrize("issuer_ref", ["additional", "root"])
def test_role_managed_correct_issuer(vault_pki, issuer_ref, testmode):
    ret = vault_pki.role_managed("dummy", issuer_ref=issuer_ref, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    if testmode:
        assert "dummy" not in vault_list("pki/roles")
        return

    role_info = vault_read("pki/roles/dummy")["data"]
    assert role_info["issuer_ref"] == issuer_ref


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "allow_localhost": False,
                "allow_bare_domains": True,
                "allowed_domains": ["www.example.com", "www.acme.com"],
                "allow_subdomains": True,
                "allow_glob_domains": True,
            },
            id="domain_restrictions",
        ),
        pytest.param(
            {"server_flag": False, "client_flag": False, "no_store": True},
            id="usage_flags",
        ),
        pytest.param(
            {
                "organization": ["Salt"],
                "country": ["US"],
                "locality": ["Seattle"],
                "require_cn": False,
            },
            id="subject_attrs",
        ),
    ],
)
def test_role_managed_payload(vault_pki, params, testmode):
    ret = vault_pki.role_managed("testrole", **params, test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode

    role_info = vault_read("pki/roles/testrole")["data"]

    for k, v in params.items():
        assert ret.changes[k]["new"] == v
        assert (role_info[k] == v) is not testmode


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
def test_role_managed_normalized_params_no_changes(vault_pki, testmode):
    """
    Ensure scalar values for list-type parameters and duration strings
    are compared correctly against the normalized values reported by
    Vault instead of causing a rewrite on every run.
    """
    params = {
        "allowed_domains": "www.example.com",
        "ttl": "1h",
        "max_ttl": "30d",
        "not_before_duration": "2m",
    }
    ret = vault_pki.role_managed("testrole", **params)
    assert ret.result is True
    assert ret.changes

    ret = vault_pki.role_managed("testrole", **params, test=testmode)
    assert ret.result is True
    assert not ret.changes


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "ttl,expected", [(60, 60), ("10m", 600), ("1h", 3600), ("1d", 86400), ("30d", 2592000)]
)
def test_role_managed_ttl(vault_pki, ttl, expected, testmode):
    ret = vault_pki.role_managed("testrole", ttl=ttl, max_ttl="365d", test=testmode)
    assert ret.result is not False

    role_info = vault_read("pki/roles/testrole")["data"]
    if testmode:
        # the role's initial ttl as set up by the testrole fixture
        assert role_info["ttl"] == 3600
    else:
        assert role_info["ttl"] == expected


@pytest.mark.usefixtures("issuer_setup", "roles_setup")
@pytest.mark.parametrize(
    "max_ttl,expected", [(60, 60), ("10m", 600), ("1h", 3600), ("1d", 86400), ("30d", 2592000)]
)
def test_role_managed_max_ttl(vault_pki, max_ttl, expected, testmode):
    ret = vault_pki.role_managed("testrole", ttl=1, max_ttl=max_ttl, test=testmode)
    assert ret.result is not False

    role_info = vault_read("pki/roles/testrole")["data"]
    if testmode:
        # the role's initial max_ttl as set up by the testrole fixture
        assert role_info["max_ttl"] == 86400
    else:
        assert role_info["max_ttl"] == expected


@pytest.mark.usefixtures("roles_setup")
def test_role_absent(vault_pki, testmode):
    assert "testrole" in vault_list("pki/roles")
    ret = vault_pki.role_absent("testrole", test=testmode)
    assert ret.result is not False
    assert (ret.result is None) is testmode
    assert "deleted" in ret.changes
    assert ("testrole" in vault_list("pki/roles")) is testmode


def test_role_absent_already_absent(vault_pki, testmode):
    ret = vault_pki.role_absent("missing", test=testmode)
    assert ret.result is True
    assert not ret.changes
    assert "already absent" in ret.comment
