"""
Runner module equivalent to the :py:mod:`vault_ssh <saltext.vault.modules.vault_ssh>` execution module.

Uses the actual master token to authenticate, not the master-minion one like :py:func:`salt.cmd <salt.runners.salt.cmd>` would use.

.. versionadded:: 1.9.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

from pathlib import Path

from saltext.vault.modules.vault_ssh import _write_role
from saltext.vault.modules.vault_ssh import create_ca
from saltext.vault.modules.vault_ssh import delete_role
from saltext.vault.modules.vault_ssh import delete_zeroaddr_roles
from saltext.vault.modules.vault_ssh import destroy_ca
from saltext.vault.modules.vault_ssh import generate_key_cert
from saltext.vault.modules.vault_ssh import get_creds
from saltext.vault.modules.vault_ssh import list_roles
from saltext.vault.modules.vault_ssh import list_roles_ip
from saltext.vault.modules.vault_ssh import list_roles_zeroaddr
from saltext.vault.modules.vault_ssh import read_ca
from saltext.vault.modules.vault_ssh import read_role
from saltext.vault.modules.vault_ssh import sign_key
from saltext.vault.modules.vault_ssh import write_role_ca
from saltext.vault.modules.vault_ssh import write_role_otp
from saltext.vault.modules.vault_ssh import write_zeroaddr_roles
from saltext.vault.utils.functools import namespaced_function

globals_dict = globals()

_write_role = namespaced_function(_write_role, globals_dict)
create_ca = namespaced_function(create_ca, globals_dict)
delete_role = namespaced_function(delete_role, globals_dict)
delete_zeroaddr_roles = namespaced_function(delete_zeroaddr_roles, globals_dict)
destroy_ca = namespaced_function(destroy_ca, globals_dict)
generate_key_cert = namespaced_function(generate_key_cert, globals_dict)
get_creds = namespaced_function(get_creds, globals_dict)
list_roles = namespaced_function(list_roles, globals_dict)
list_roles_ip = namespaced_function(list_roles_ip, globals_dict)
list_roles_zeroaddr = namespaced_function(list_roles_zeroaddr, globals_dict)
read_ca = namespaced_function(read_ca, globals_dict)
read_role = namespaced_function(read_role, globals_dict)
sign_key = namespaced_function(sign_key, globals_dict)
write_role_ca = namespaced_function(write_role_ca, globals_dict)
write_role_otp = namespaced_function(write_role_otp, globals_dict)
write_zeroaddr_roles = namespaced_function(write_zeroaddr_roles, globals_dict)


def _get_file_or_data(data):
    """
    Try to load a string as a file, otherwise return the string
    """
    try:
        # Check if the data can be interpreted as a Path at all
        path = Path(data).expanduser()
    except TypeError:
        return data
    try:
        if path.is_file():
            return path.read_text("utf8")
    except (OSError, TypeError, ValueError):
        pass
    return data
