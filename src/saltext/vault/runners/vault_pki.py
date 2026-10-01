"""
Runner module equivalent to the :py:mod:`vault_pki <saltext.vault.modules.vault_pki>` execution module.

Uses the actual master token to authenticate, not the master-minion one like :py:func:`salt.cmd <salt.runners.salt.cmd>` would use.

.. versionadded:: 1.9.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.

Setup notes
-----------
Some functionality requires the :py:mod:`x509_v2 <salt.modules.x509_v2>` execution module
to be loadable on the master itself. File path arguments to this functionality
refer to files local to the master.

This means:

1. The Python installation running the Salt master needs to have the
   ``cryptography`` library installed.

2. On Salt releases below 3008, you need to include the following in your
   master configuration:

   .. code-block:: yaml

        features:
          x509_v2: true
"""

import copy
import typing

import salt.loader
from salt.exceptions import CommandExecutionError

from saltext.vault.modules.vault_pki import _find_signing_issuer
from saltext.vault.modules.vault_pki import delete_issuer
from saltext.vault.modules.vault_pki import delete_key
from saltext.vault.modules.vault_pki import delete_role
from saltext.vault.modules.vault_pki import generate_intermediate
from saltext.vault.modules.vault_pki import generate_intermediate_csr
from saltext.vault.modules.vault_pki import generate_key
from saltext.vault.modules.vault_pki import generate_root
from saltext.vault.modules.vault_pki import get_default_issuer
from saltext.vault.modules.vault_pki import get_issuer_id
from saltext.vault.modules.vault_pki import get_key_id
from saltext.vault.modules.vault_pki import import_issuer
from saltext.vault.modules.vault_pki import import_issuer_intermediate
from saltext.vault.modules.vault_pki import issue_certificate
from saltext.vault.modules.vault_pki import list_certificates
from saltext.vault.modules.vault_pki import list_issuers
from saltext.vault.modules.vault_pki import list_keys
from saltext.vault.modules.vault_pki import list_revoked_certificates
from saltext.vault.modules.vault_pki import list_roles
from saltext.vault.modules.vault_pki import read_certificate
from saltext.vault.modules.vault_pki import read_certificate_full
from saltext.vault.modules.vault_pki import read_cluster_config
from saltext.vault.modules.vault_pki import read_issuer
from saltext.vault.modules.vault_pki import read_issuer_certificate
from saltext.vault.modules.vault_pki import read_issuer_crl
from saltext.vault.modules.vault_pki import read_role
from saltext.vault.modules.vault_pki import read_urls
from saltext.vault.modules.vault_pki import revoke_certificate
from saltext.vault.modules.vault_pki import set_default_issuer
from saltext.vault.modules.vault_pki import sign_certificate
from saltext.vault.modules.vault_pki import sign_intermediate
from saltext.vault.modules.vault_pki import update_issuer
from saltext.vault.modules.vault_pki import write_cluster_config
from saltext.vault.modules.vault_pki import write_role
from saltext.vault.modules.vault_pki import write_urls
from saltext.vault.utils.functools import namespaced_function

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltOpts

    __opts__: SaltOpts
    __context__: SaltContext

globals_dict = globals()

_find_signing_issuer = namespaced_function(_find_signing_issuer, globals_dict)
delete_issuer = namespaced_function(delete_issuer, globals_dict)
delete_key = namespaced_function(delete_key, globals_dict)
delete_role = namespaced_function(delete_role, globals_dict)
generate_intermediate = namespaced_function(generate_intermediate, globals_dict)
generate_intermediate_csr = namespaced_function(generate_intermediate_csr, globals_dict)
generate_key = namespaced_function(generate_key, globals_dict)
generate_root = namespaced_function(generate_root, globals_dict)
get_default_issuer = namespaced_function(get_default_issuer, globals_dict)
get_issuer_id = namespaced_function(get_issuer_id, globals_dict)
get_key_id = namespaced_function(get_key_id, globals_dict)
import_issuer = namespaced_function(import_issuer, globals_dict)
import_issuer_intermediate = namespaced_function(import_issuer_intermediate, globals_dict)
issue_certificate = namespaced_function(issue_certificate, globals_dict)
list_certificates = namespaced_function(list_certificates, globals_dict)
list_issuers = namespaced_function(list_issuers, globals_dict)
list_keys = namespaced_function(list_keys, globals_dict)
list_revoked_certificates = namespaced_function(list_revoked_certificates, globals_dict)
list_roles = namespaced_function(list_roles, globals_dict)
read_certificate = namespaced_function(read_certificate, globals_dict)
read_certificate_full = namespaced_function(
    read_certificate_full, globals_dict, versionadded="1.9.0"
)
read_cluster_config = namespaced_function(read_cluster_config, globals_dict)
read_issuer = namespaced_function(read_issuer, globals_dict)
read_issuer_certificate = namespaced_function(read_issuer_certificate, globals_dict)
read_issuer_crl = namespaced_function(read_issuer_crl, globals_dict)
read_role = namespaced_function(read_role, globals_dict)
read_urls = namespaced_function(read_urls, globals_dict)
revoke_certificate = namespaced_function(revoke_certificate, globals_dict)
set_default_issuer = namespaced_function(set_default_issuer, globals_dict)
sign_certificate = namespaced_function(sign_certificate, globals_dict)
sign_intermediate = namespaced_function(sign_intermediate, globals_dict)
update_issuer = namespaced_function(update_issuer, globals_dict)
write_cluster_config = namespaced_function(write_cluster_config, globals_dict)
write_role = namespaced_function(write_role, globals_dict)
write_urls = namespaced_function(write_urls, globals_dict)


def _x509v2(fun, *args, **kwargs):
    """
    Replaces the execution module helper of the same name.
    A runner's ``__salt__`` only provides runner functions, so load the
    execution modules on the master itself, the same way ``salt.cmd`` does.
    This means file path arguments refer to files local to the master.
    """
    try:
        funcs = __context__["saltext_vault_runner_exemods"]
    except KeyError:
        opts = copy.deepcopy(__opts__)
        opts["grains"] = salt.loader.grains(opts)
        opts["pillar"] = {}
        funcs = __context__["saltext_vault_runner_exemods"] = salt.loader.minion_mods(
            opts, utils=salt.loader.utils(opts), context=__context__
        )
    try:
        func = funcs[f"x509.{fun}"]
    except KeyError as err:
        raise CommandExecutionError(
            f"Missing `x509.{fun}`, provided by the builtin `x509_v2` execution module. "
            "On Salt releases below 3008, it needs to be enabled explicitly in the "
            "master configuration. See the runner module docs for details."
        ) from err
    return func(*args, **kwargs)
