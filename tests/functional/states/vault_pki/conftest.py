"""
Suite-specific fixtures for the vault_pki state tests.
"""

import pytest
from salt.utils.x509 import load_cert

# pylint: disable=unused-import
from tests.common.fixtures.vault_pki import aia_urls
from tests.common.fixtures.vault_pki import ca2_cert
from tests.common.fixtures.vault_pki import ca2_key
from tests.common.fixtures.vault_pki import ca_cert
from tests.common.fixtures.vault_pki import ca_cert_no_pathlen
from tests.common.fixtures.vault_pki import ca_key
from tests.common.fixtures.vault_pki import ca_key_no_pathlen
from tests.common.fixtures.vault_pki import ca_sub_cert
from tests.common.fixtures.vault_pki import ca_sub_key
from tests.common.fixtures.vault_pki import clean_pki_mount
from tests.common.fixtures.vault_pki import cluster_config
from tests.common.fixtures.vault_pki import fresh_pki_mount
from tests.common.fixtures.vault_pki import issuer_setup
from tests.common.fixtures.vault_pki import issuer_setup_additional
from tests.common.fixtures.vault_pki import issuer_setup_no_pathlen
from tests.common.fixtures.vault_pki import issuer_setup_sub
from tests.common.fixtures.vault_pki import private_key
from tests.common.fixtures.vault_pki import role_read_denied
from tests.common.fixtures.vault_pki import roles_setup
from tests.common.fixtures.vault_pki import url_config_read_denied

# pylint: enable=unused-import
from tests.common.helpers.vault_pki import _default_issuer
from tests.common.helpers.vault_pki import pregen_csr
from tests.support.vault import vault_delete


@pytest.fixture(scope="module")
def minion_config_overrides(salt_version):
    if salt_version[0] < 3008:
        # Need to enable x509_v2 explicitly on Salt <3008
        return {"features": {"x509_v2": True}}
    return {}


@pytest.fixture
def vault_pki(states):
    try:
        yield states.vault_pki
    finally:
        vault_delete("pki/roles/dummy")


@pytest.fixture
def testrole(request):
    defaults = {
        "ttl": 3600,
        "max_ttl": 86400,
        "allow_any_name": True,
        "enforce_hostnames": False,
        "allowed_other_sans": ["*"],
        "allowed_uri_sans": ["*"],
        "allowed_user_ids": ["*"],
        "allowed_serial_numbers": ["*"],
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


@pytest.fixture
def cert_args(tmp_path, private_key):
    return {
        "name": f"{tmp_path}/cert",
        "common_name": "saltproject.io",
        "role_name": "testrole",
        "private_key": private_key,
        "ttl": "30m",
        "ttl_remaining": 0,
    }


@pytest.fixture
def ca_cert_args(tmp_path, private_key):
    return {
        "name": f"{tmp_path}/cert",
        "common_name": "saltproject.io",
        "private_key": private_key,
        "ttl": "30m",
        "ttl_remaining": 0,
    }


@pytest.fixture(params=("regular", "intermediate"))
def cert_typ(request, vault_pki):
    if request.param == "intermediate":
        return vault_pki.ca_certificate_managed, request.getfixturevalue("ca_cert_args")
    return vault_pki.certificate_managed, request.getfixturevalue("cert_args")


@pytest.fixture
def existing_cert(
    issuer_setup, roles_setup, aia_urls, request, modules, vault_pki
):  # pylint: disable=unused-argument
    if "cert_typ" in request.fixturenames:
        cert_managed, cert_args = request.getfixturevalue("cert_typ")
    elif "ca_certificate_managed" in request.function.__name__:
        cert_managed, cert_args = vault_pki.ca_certificate_managed, request.getfixturevalue(
            "ca_cert_args"
        )
    else:
        cert_managed, cert_args = vault_pki.certificate_managed, request.getfixturevalue(
            "cert_args"
        )
    overrides = getattr(request, "param", {})
    generate_csr = overrides.pop("generate_csr", False)
    cert_args.update(overrides)
    if generate_csr:
        pregen_csr(cert_args)
    ret = cert_managed(**cert_args)
    assert ret.result is True
    assert "created" in ret.changes
    return load_cert(cert_args["name"]).serial_number


@pytest.fixture(params=("salt_ca", "vault_ca"))
def int_ca_args(
    ca_cert, ca_key, request, fresh_pki_mount, issuer_setup
):  # pylint: disable=unused-argument
    params = {
        "name": "Test Intermediate CA",
        "days_valid": 90,
        "key_algo": "ec",  # faster than rsa
        "mount": fresh_pki_mount,
    }
    if request.param == "salt_ca":
        params.update(
            {
                "signing_private_key": ca_key,
                "signing_cert": ca_cert,
            }
        )
    elif request.param == "vault_ca":
        params["issuer_ref"] = "root"
        params["issuer_mount"] = "pki"
    else:  # pragma: no cover
        raise TypeError(f"Unknown fixture param: {request.param}")
    return params


@pytest.fixture
def existing_intermediate(
    vault_pki, int_ca_args, clean_pki_mount, request, aia_urls, container
):  # pylint: disable=unused-argument
    int_ca_args.update(getattr(request, "param", {}))
    if int_ca_args.get("issuer_ref"):
        if not container.is_vault_latest():
            if "excluded_alt_names" in int_ca_args or any(
                not val.lower().startswith("dns")
                for val in int_ca_args.get("permitted_alt_names", [])
            ):
                int_ca_args.pop("excluded_alt_names", None)
                if "permitted_alt_names" in int_ca_args:
                    int_ca_args["permitted_alt_names"] = [
                        val
                        for val in int_ca_args["permitted_alt_names"]
                        if val.lower().startswith("dns")
                    ]
        if not container.is_openbao() and not container.is_latest():
            int_ca_args.pop("key_usage", None)
    if (
        "delta_crl_endpoints" in int_ca_args
        and not container.is_openbao()
        and not container.is_latest()
    ):
        int_ca_args.pop("delta_crl_endpoints")
    ret = vault_pki.intermediate_issuer_managed(**int_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    return _default_issuer(int_ca_args["mount"])


@pytest.fixture
def root_ca_args():
    return {
        "name": "test.root.ca",
        "ou": ["an org unit", "Org Unit 1", "Another Org Unit 2"],
        "organization": "Test Org",
        "country": "US",
        "locality": "Springfield",
        "province": "Utah",
        "street_address": "Test Rd 123",
        "postal_code": "1337",
        "serial_number": "42",
        "key_algo": "ec",  # faster than rsa
    }


@pytest.fixture
def existing_root(
    vault_pki, root_ca_args, clean_pki_mount, request, aia_urls, container
):  # pylint: disable=unused-argument
    root_ca_args.update(getattr(request, "param", {}))
    if "excluded_alt_names" in root_ca_args or any(
        not val.lower().startswith("dns") for val in root_ca_args.get("permitted_alt_names", [])
    ):
        if not container.is_vault_latest():
            root_ca_args.pop("excluded_alt_names", None)
            if "permitted_alt_names" in root_ca_args:
                root_ca_args["permitted_alt_names"] = [
                    val
                    for val in root_ca_args["permitted_alt_names"]
                    if val.lower().startswith("dns")
                ]
    if (
        "delta_crl_endpoints" in root_ca_args
        or "key_usage" in root_ca_args
        and (not container.is_openbao() and not container.is_latest())
    ):
        root_ca_args.pop("delta_crl_endpoints", None)
        root_ca_args.pop("key_usage", None)
    ret = vault_pki.root_issuer_managed(**root_ca_args)
    assert ret.result is True
    assert "created" in ret.changes
    return _default_issuer()
