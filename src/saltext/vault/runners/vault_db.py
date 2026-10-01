"""
Runner module equivalent to the :py:mod:`vault_db <saltext.vault.modules.vault_db>` execution module.

Uses the actual master token to authenticate, not the master-minion one like :py:func:`salt.cmd <salt.runners.salt.cmd>` would use.

.. versionadded:: 1.9.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.

Lease renewal
-------------
Leases requested with ``cache`` enabled are stored in the master's own lease store,
which :py:func:`list_cached <saltext.vault.runners.vault_db.list_cached>`,
:py:func:`renew_cached <saltext.vault.runners.vault_db.renew_cached>` and
:py:func:`clear_cached <saltext.vault.runners.vault_db.clear_cached>` operate on.

Unlike on minions, where the :py:mod:`vault_lease <saltext.vault.beacons.vault_lease>`
beacon module can renew cached leases automatically, there is no beacon support
on the master. Expired cached leases are discarded and replaced with newly issued
credentials transparently during :py:func:`get_creds <saltext.vault.runners.vault_db.get_creds>`
calls, so renewal is only necessary when the issued credentials themselves need
to stay valid, e.g. because they have been passed to Vault-unaware software.

In this case, you can employ the master scheduler, which executes runner functions:

.. code-block:: yaml

    # in the master configuration
    schedule:
      vault_db_lease_renewal:
        function: vault_db.renew_cached
        minutes: 10

Note that in contrast to the beacon module, this does not send expiry events for
leases that cannot be renewed further.
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
