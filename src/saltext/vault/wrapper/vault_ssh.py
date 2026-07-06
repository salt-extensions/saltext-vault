"""
SSH wrapper for the :py:mod:`vault_ssh <saltext.vault.modules.vault_ssh>` execution module.

See there for documentation.
"""

from salt.utils.functools import namespaced_function

from saltext.vault.modules.vault_ssh import _get_file_or_data
from saltext.vault.modules.vault_ssh import _write_role
from saltext.vault.modules.vault_ssh import create_ca
from saltext.vault.modules.vault_ssh import create_certificate
from saltext.vault.modules.vault_ssh import delete_role
from saltext.vault.modules.vault_ssh import delete_zeroaddr_roles
from saltext.vault.modules.vault_ssh import destroy_ca
from saltext.vault.modules.vault_ssh import generate_key_cert
from saltext.vault.modules.vault_ssh import get_creds
from saltext.vault.modules.vault_ssh import get_signing_policy
from saltext.vault.modules.vault_ssh import list_roles
from saltext.vault.modules.vault_ssh import list_roles_ip
from saltext.vault.modules.vault_ssh import list_roles_zeroaddr
from saltext.vault.modules.vault_ssh import read_ca
from saltext.vault.modules.vault_ssh import read_role
from saltext.vault.modules.vault_ssh import sign_key
from saltext.vault.modules.vault_ssh import write_role_ca
from saltext.vault.modules.vault_ssh import write_role_otp
from saltext.vault.modules.vault_ssh import write_zeroaddr_roles

globals_dict = globals()

_get_file_or_data = namespaced_function(_get_file_or_data, globals_dict)
_write_role = namespaced_function(_write_role, globals_dict)
create_ca = namespaced_function(create_ca, globals_dict)
create_certificate = namespaced_function(create_certificate, globals_dict)
delete_role = namespaced_function(delete_role, globals_dict)
delete_zeroaddr_roles = namespaced_function(delete_zeroaddr_roles, globals_dict)
destroy_ca = namespaced_function(destroy_ca, globals_dict)
generate_key_cert = namespaced_function(generate_key_cert, globals_dict)
get_creds = namespaced_function(get_creds, globals_dict)
get_signing_policy = namespaced_function(get_signing_policy, globals_dict)
list_roles = namespaced_function(list_roles, globals_dict)
list_roles_ip = namespaced_function(list_roles_ip, globals_dict)
list_roles_zeroaddr = namespaced_function(list_roles_zeroaddr, globals_dict)
read_ca = namespaced_function(read_ca, globals_dict)
read_role = namespaced_function(read_role, globals_dict)
sign_key = namespaced_function(sign_key, globals_dict)
write_role_ca = namespaced_function(write_role_ca, globals_dict)
write_role_otp = namespaced_function(write_role_otp, globals_dict)
write_zeroaddr_roles = namespaced_function(write_zeroaddr_roles, globals_dict)
