"""
SSH wrapper for the :py:mod:`vault_pki <saltext.vault.modules.vault_pki>` execution module.

See there for documentation.

Setup notes
-----------
In addition to the regular :ref:`Vault setup <vault-setup>`, using
:py:func:`sign_certificate <saltext.vault.modules.vault_pki.sign_certificate>` and
:py:func:`revoke_certificate <saltext.vault.modules.vault_pki.revoke_certificate>`
requires the :py:mod:`x509_v2 <salt.modules.x509_v2>` module to be active on the target.

This means:

1. The global Python installation on the target needs to have the
   ``cryptography`` library installed.

2. On Salt releases below 3008, you need to include the following in your
   master configuration:

   .. code-block:: yaml

        # e.g. /etc/salt/master.d/salt_ssh.conf

        ssh_minion_opts:
          features:
            x509_v2: true
"""

import typing

from salt.exceptions import CommandExecutionError

from saltext.vault.modules.vault_pki import _find_signing_issuer
from saltext.vault.modules.vault_pki import _split_csr_kwargs
from saltext.vault.modules.vault_pki import _x509v2
from saltext.vault.modules.vault_pki import delete_issuer
from saltext.vault.modules.vault_pki import delete_key
from saltext.vault.modules.vault_pki import delete_role
from saltext.vault.modules.vault_pki import generate_intermediate
from saltext.vault.modules.vault_pki import generate_intermediate_csr
from saltext.vault.modules.vault_pki import generate_key
from saltext.vault.modules.vault_pki import generate_root
from saltext.vault.modules.vault_pki import get_default_issuer
from saltext.vault.modules.vault_pki import get_key_id
from saltext.vault.modules.vault_pki import import_issuer as _import_issuer
from saltext.vault.modules.vault_pki import (
    import_issuer_intermediate as _import_issuer_intermediate,
)
from saltext.vault.modules.vault_pki import issue_certificate
from saltext.vault.modules.vault_pki import list_certificates
from saltext.vault.modules.vault_pki import list_issuers
from saltext.vault.modules.vault_pki import list_keys
from saltext.vault.modules.vault_pki import list_revoked_certificates
from saltext.vault.modules.vault_pki import list_roles
from saltext.vault.modules.vault_pki import read_certificate
from saltext.vault.modules.vault_pki import read_certificate_full
from saltext.vault.modules.vault_pki import read_issuer
from saltext.vault.modules.vault_pki import read_issuer_certificate
from saltext.vault.modules.vault_pki import read_issuer_crl
from saltext.vault.modules.vault_pki import read_role
from saltext.vault.modules.vault_pki import read_urls
from saltext.vault.modules.vault_pki import revoke_certificate
from saltext.vault.modules.vault_pki import set_default_issuer
from saltext.vault.modules.vault_pki import sign_certificate
from saltext.vault.modules.vault_pki import update_issuer
from saltext.vault.modules.vault_pki import write_role
from saltext.vault.modules.vault_pki import write_urls
from saltext.vault.utils.functools import namespaced_function

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltGrains
    from saltext.vault.utils._types import SaltOpts

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __grains__: SaltGrains

# generate_intermediate left out for now

globals_dict = globals()

_find_signing_issuer = namespaced_function(_find_signing_issuer, globals_dict)
_split_csr_kwargs = namespaced_function(_split_csr_kwargs, globals_dict)
_x509v2 = namespaced_function(_x509v2, globals_dict)
_import_issuer = namespaced_function(_import_issuer, globals_dict)
_import_issuer_intermediate = namespaced_function(_import_issuer_intermediate, globals_dict)
delete_issuer = namespaced_function(delete_issuer, globals_dict)
delete_key = namespaced_function(delete_key, globals_dict)
delete_role = namespaced_function(delete_role, globals_dict)
generate_intermediate = namespaced_function(generate_intermediate, globals_dict)
generate_intermediate_csr = namespaced_function(generate_intermediate_csr, globals_dict)
generate_key = namespaced_function(generate_key, globals_dict)
generate_root = namespaced_function(generate_root, globals_dict)
get_default_issuer = namespaced_function(get_default_issuer, globals_dict)
get_key_id = namespaced_function(get_key_id, globals_dict)
issue_certificate = namespaced_function(issue_certificate, globals_dict)
list_certificates = namespaced_function(list_certificates, globals_dict)
list_issuers = namespaced_function(list_issuers, globals_dict)
list_keys = namespaced_function(list_keys, globals_dict)
list_revoked_certificates = namespaced_function(list_revoked_certificates, globals_dict)
list_roles = namespaced_function(list_roles, globals_dict)
read_certificate = namespaced_function(read_certificate, globals_dict)
read_certificate_full = namespaced_function(read_certificate_full, globals_dict)
read_issuer = namespaced_function(read_issuer, globals_dict)
read_issuer_certificate = namespaced_function(read_issuer_certificate, globals_dict)
read_issuer_crl = namespaced_function(read_issuer_crl, globals_dict)
read_role = namespaced_function(read_role, globals_dict)
read_urls = namespaced_function(read_urls, globals_dict)
revoke_certificate = namespaced_function(revoke_certificate, globals_dict)
set_default_issuer = namespaced_function(set_default_issuer, globals_dict)
sign_certificate = namespaced_function(sign_certificate, globals_dict)
update_issuer = namespaced_function(update_issuer, globals_dict)
write_role = namespaced_function(write_role, globals_dict)
write_urls = namespaced_function(write_urls, globals_dict)


def import_issuer_intermediate(cert, chain=None, mount="pki"):
    """
    .. versionadded:: 1.9.0

    Import a CA certificate issued for an existing key on this mount.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#import-ca-certificates-and-keys>`__.

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/intermediate/set-signed" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.import_issuer_intermediate /etc/tls/my_intermediate_cert.pem

    cert
        Certificate to import. Any input accepted by the :py:mod:`x509_v2 modules <salt.modules.x509_v2>` is accepted.
        Included CA chain is respected when ``chain`` is not specified.

    chain
        CA chain for the certificate. Defaults to the chain in ``cert``, if present.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    # We need to dereference minion paths
    loaded_cert = _fetch_cert_raw(cert)

    loaded_chain = None
    if chain:
        loaded_chain = []
        if not isinstance(chain, list):
            chain = [chain]
        for chain_cert in chain:
            loaded_chain.append(__salt__["x509.encode_certificate"](chain_cert))

    return _import_issuer_intermediate(  # pylint: disable=not-callable
        loaded_cert, chain=loaded_chain, mount=mount
    )


def import_issuer(cert, chain=None, private_key=None, private_key_passphrase=None, mount="pki"):
    """
    .. versionadded:: 1.9.0

    Import a CA certificate and (optionally) corresponding private key.

    `API method docs <https://developer.hashicorp.com/vault/api-docs/secret/pki#import-ca-certificates-and-keys>`__.

    Required policy:

    .. code-block:: vaultpolicy

        # without private_key
        path "<mount>/issuer/import/cert" {
            capabilities = ["create", "update"]
        }

        # with private_key
        path "<mount>/issuer/import/bundle" {
            capabilities = ["create", "update"]
        }

    CLI Example:

    .. code-block:: bash

        salt '*' vault_pki.import_issuer /etc/tls/my_intermediate_cert.pem
        salt '*' vault_pki.import_issuer /etc/tls/my_intermediate_cert.pem private_key=/etc/tls/my_intermediate.key

    cert
        Certificate to import. Any input accepted by the :py:mod:`x509_v2 modules <salt.modules.x509_v2>` is accepted.

    chain
        CA chain for the certificate. Defaults to the chain in ``cert``, if present.

    private_key
        Import corresponding private key for ``cert``. Optional.

        .. important::

            Specifying this parameter means the private key leaves the remote minion.

    private_key_passphrase
        When ``private_key`` is specified and encrypted, the passphrase to decrypt it.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    # We need to dereference minion paths
    loaded_cert = _fetch_cert_raw(cert)

    loaded_chain = None
    if chain:
        loaded_chain = []
        if not isinstance(chain, list):
            chain = [chain]
        for chain_cert in chain:
            loaded_chain.append(__salt__["x509.encode_certificate"](chain_cert))

    if private_key is not None:
        private_key = __salt__["x509.encode_private_key"](
            private_key, private_key_passphrase=private_key_passphrase
        )

    return _import_issuer(  # pylint: disable=not-callable
        loaded_cert, chain=loaded_chain, private_key=private_key, mount=mount
    )


def _fetch_cert_raw(cert):
    # Ensure we get the certificate from the minion, if a path is specified
    try:
        # Can't use encode_certificate because it currently drops the chain
        loaded_cert = __salt__["hashutil.base64_encodefile"](cert)
    except CommandExecutionError:
        # Ignore errors, e.g. missing file or not a path.
        # This requires Salt 3007+, otherwise `cert`
        loaded_cert = cert
    else:
        if isinstance(loaded_cert, dict):
            # Salt <3007 returns an error return dict instead of raising exceptions
            loaded_cert = cert
        else:
            # Ensure the cert is loaded as intended
            loaded_cert = "b64:" + loaded_cert
    return loaded_cert
