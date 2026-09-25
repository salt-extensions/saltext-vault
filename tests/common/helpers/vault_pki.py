"""
Shared helpers and constants for the vault_pki test suites.
"""

from contextlib import contextmanager
from datetime import timezone
from unittest.mock import patch

from cryptography import x509 as cx509
from salt.modules.x509_v2 import create_csr
from salt.utils.immutabletypes import freeze
from salt.utils.x509 import NAME_ATTRS_OID

from saltext.vault.states.vault_pki import URL_EXTS_UNVERIFIED_NOTE
from saltext.vault.utils import vault as vaultutil
from saltext.vault.utils.vault import pki
from tests.support.vault import vault_delete
from tests.support.vault import vault_read
from tests.support.vault import vault_write

# Can't reset these to empty, so define reliable defaults instead
DEFAULT_CLUSTER_PATH = "https://cluster1.vault.local/v1/pki"
DEFAULT_CLUSTER_AIA_PATH = "http://foo.bar.baz/aia/"


def _wipe_issuers(mount="pki"):
    vault_delete(f"{mount}/root")


def _import_configured_issuer(certs, key, issuer_config, mount="pki"):
    if not isinstance(certs, list):
        certs = [certs]
    res = vault_write(f"/{mount}/config/ca", pem_bundle="\n".join(certs + [key]))["data"]
    issuer_id = res["imported_issuers"][0]
    vault_write(f"/{mount}/issuer/{issuer_id}", **issuer_config)
    return issuer_id


def pregen_csr(cert_args):
    csr_args, _ = pki.split_csr_kwargs(cert_args)
    for csr_arg in csr_args:
        cert_args.pop(csr_arg)
    private_key = cert_args.pop("private_key")
    private_key_passphrase = cert_args.pop("private_key_passphrase", None)
    digest = cert_args.pop("digest", "sha256")
    csr = create_csr(
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
        digest=digest,
        **csr_args,
    )
    cert_args["csr"] = csr
    return cert_args


@contextmanager
def _read_denied(*endpoints):
    """
    Simulate a policy denying read access to specific endpoint prefixes
    by patching the shared query helper.
    """
    real_query = vaultutil.query

    def query(method, endpoint, *args, **kwargs):
        if method == "GET" and endpoint.startswith(endpoints):
            raise vaultutil.VaultPermissionDeniedError("permission denied")
        return real_query(method, endpoint, *args, **kwargs)

    with patch("saltext.vault.utils.vault.query", query):
        yield


MOUNT_URL_CONFIG = freeze(
    {
        "issuing_certificates": ["https://ca.example.com/ca.der"],
        "crl_distribution_points": ["https://crl.example.com/crl.pem"],
        # Only supported by OpenBao/recent Vault, ignored by older versions during writes.
        "delta_crl_distribution_points": ["https://deltacrl.example.com/delta.pem"],
        "ocsp_servers": ["https://ocsp.example.com"],
    }
)

AIA_UNVERIFIED_NOTE = URL_EXTS_UNVERIFIED_NOTE.format(mount="pki")


def _assert_embedded_aia(cert, urls):
    aia = cert.extensions.get_extension_for_class(cx509.AuthorityInformationAccess)
    assert urls["issuing_certificates"][0] in {
        str(access.access_location.value) for access in aia.value
    }


def _default_issuer(mount="pki"):
    return vault_read(f"{mount}/issuer/default")["data"]


def _subject(cert, attr="CN"):
    return cert.subject.get_attributes_for_oid(NAME_ATTRS_OID[attr])[0].value


def _not_valid_after(cert):
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover
        return cert.not_valid_after.replace(tzinfo=timezone.utc)
