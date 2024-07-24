"""
SSH wrapper for the :py:mod:`vault_db <saltext.vault.modules.vault_db>` execution module.

See there for documentation.
"""

from salt.utils.functools import namespaced_function

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

_write_role = namespaced_function(_write_role, globals())
clear_cached = namespaced_function(clear_cached, globals())
delete_connection = namespaced_function(delete_connection, globals())
delete_role = namespaced_function(delete_role, globals())
fetch_connection = namespaced_function(fetch_connection, globals())
fetch_role = namespaced_function(fetch_role, globals())
get_creds = namespaced_function(get_creds, globals())
list_cached = namespaced_function(list_cached, globals())
list_connections = namespaced_function(list_connections, globals())
list_roles = namespaced_function(list_roles, globals())
renew_cached = namespaced_function(renew_cached, globals())
reset_connection = namespaced_function(reset_connection, globals())
rotate_root = namespaced_function(rotate_root, globals())
rotate_static_role = namespaced_function(rotate_static_role, globals())
write_connection = namespaced_function(write_connection, globals())
write_role = namespaced_function(write_role, globals())
write_static_role = namespaced_function(write_static_role, globals())
