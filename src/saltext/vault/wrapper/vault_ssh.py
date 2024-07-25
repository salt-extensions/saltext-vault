"""
SSH wrapper for the :py:mod:`vault_ssh <saltext.vault.modules.vault_ssh>` execution module.

See there for documentation.
"""

from salt.utils.functools import namespaced_function

from saltext.vault.modules.vault_ssh import _get_file_or_data
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

_get_file_or_data = namespaced_function(_get_file_or_data, globals())
_write_role = namespaced_function(_write_role, globals())
create_ca = namespaced_function(create_ca, globals())
delete_role = namespaced_function(delete_role, globals())
delete_zeroaddr_roles = namespaced_function(delete_zeroaddr_roles, globals())
destroy_ca = namespaced_function(destroy_ca, globals())
generate_key_cert = namespaced_function(generate_key_cert, globals())
get_creds = namespaced_function(get_creds, globals())
list_roles = namespaced_function(list_roles, globals())
list_roles_ip = namespaced_function(list_roles_ip, globals())
list_roles_zeroaddr = namespaced_function(list_roles_zeroaddr, globals())
read_ca = namespaced_function(read_ca, globals())
read_role = namespaced_function(read_role, globals())
sign_key = namespaced_function(sign_key, globals())
write_role_ca = namespaced_function(write_role_ca, globals())
write_role_otp = namespaced_function(write_role_otp, globals())
write_zeroaddr_roles = namespaced_function(write_zeroaddr_roles, globals())
