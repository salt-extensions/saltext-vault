"""
SSH wrapper for the :py:mod:`vault_db <saltext.vault.modules.vault_db>` execution module.

See there for documentation.
"""

from saltext.vault.modules.vault_db import _write_role
from saltext.vault.modules.vault_db import clear_cached
from saltext.vault.modules.vault_db import delete_connection
from saltext.vault.modules.vault_db import delete_role
from saltext.vault.modules.vault_db import fetch_connection
from saltext.vault.modules.vault_db import fetch_role
from saltext.vault.modules.vault_db import get_creds
from saltext.vault.modules.vault_db import list_cached
from saltext.vault.modules.vault_db import list_connections
from saltext.vault.modules.vault_db import list_roles
from saltext.vault.modules.vault_db import renew_cached
from saltext.vault.modules.vault_db import reset_connection
from saltext.vault.modules.vault_db import rotate_root
from saltext.vault.modules.vault_db import rotate_static_role
from saltext.vault.modules.vault_db import write_connection
from saltext.vault.modules.vault_db import write_role
from saltext.vault.modules.vault_db import write_static_role
from saltext.vault.utils.functools import namespaced_function

globals_dict = globals()

_write_role = namespaced_function(_write_role, globals_dict)
clear_cached = namespaced_function(clear_cached, globals_dict)
delete_connection = namespaced_function(delete_connection, globals_dict)
delete_role = namespaced_function(delete_role, globals_dict)
fetch_connection = namespaced_function(fetch_connection, globals_dict)
fetch_role = namespaced_function(fetch_role, globals_dict)
get_creds = namespaced_function(get_creds, globals_dict)
list_cached = namespaced_function(list_cached, globals_dict)
list_connections = namespaced_function(list_connections, globals_dict)
list_roles = namespaced_function(list_roles, globals_dict)
renew_cached = namespaced_function(renew_cached, globals_dict)
reset_connection = namespaced_function(reset_connection, globals_dict)
rotate_root = namespaced_function(rotate_root, globals_dict)
rotate_static_role = namespaced_function(rotate_static_role, globals_dict)
write_connection = namespaced_function(write_connection, globals_dict)
write_role = namespaced_function(write_role, globals_dict)
write_static_role = namespaced_function(write_static_role, globals_dict)
