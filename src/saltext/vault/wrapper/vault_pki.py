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

from salt.utils.functools import namespaced_function

from saltext.vault.modules.vault_pki import _split_csr_kwargs
from saltext.vault.modules.vault_pki import _split_sans
from saltext.vault.modules.vault_pki import delete_issuer
from saltext.vault.modules.vault_pki import delete_key
from saltext.vault.modules.vault_pki import delete_role
from saltext.vault.modules.vault_pki import generate_root
from saltext.vault.modules.vault_pki import get_default_issuer
from saltext.vault.modules.vault_pki import issue_certificate
from saltext.vault.modules.vault_pki import list_certificates
from saltext.vault.modules.vault_pki import list_issuers
from saltext.vault.modules.vault_pki import list_revoked_certificates
from saltext.vault.modules.vault_pki import list_roles
from saltext.vault.modules.vault_pki import read_certificate
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

_split_csr_kwargs = namespaced_function(_split_csr_kwargs, globals())
_split_sans = namespaced_function(_split_sans, globals())
delete_issuer = namespaced_function(delete_issuer, globals())
delete_key = namespaced_function(delete_key, globals())
delete_role = namespaced_function(delete_role, globals())
generate_root = namespaced_function(generate_root, globals())
get_default_issuer = namespaced_function(get_default_issuer, globals())
issue_certificate = namespaced_function(issue_certificate, globals())
list_certificates = namespaced_function(list_certificates, globals())
list_issuers = namespaced_function(list_issuers, globals())
list_revoked_certificates = namespaced_function(list_revoked_certificates, globals())
list_roles = namespaced_function(list_roles, globals())
read_certificate = namespaced_function(read_certificate, globals())
read_issuer = namespaced_function(read_issuer, globals())
read_issuer_certificate = namespaced_function(read_issuer_certificate, globals())
read_issuer_crl = namespaced_function(read_issuer_crl, globals())
read_role = namespaced_function(read_role, globals())
read_urls = namespaced_function(read_urls, globals())
revoke_certificate = namespaced_function(revoke_certificate, globals())
set_default_issuer = namespaced_function(set_default_issuer, globals())
sign_certificate = namespaced_function(sign_certificate, globals())
update_issuer = namespaced_function(update_issuer, globals())
write_role = namespaced_function(write_role, globals())
