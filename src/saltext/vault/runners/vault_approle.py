"""
Runner module equivalent to the :py:mod:`vault_approle <saltext.vault.modules.vault_approle>` execution module.

Uses the actual master token to authenticate, not the master-minion one like :py:func:`salt.cmd <salt.runners.salt.cmd>` would use.

.. versionadded:: 1.9.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

from saltext.vault.modules.vault_approle import clear_cached
from saltext.vault.modules.vault_approle import delete
from saltext.vault.modules.vault_approle import destroy_secret_id
from saltext.vault.modules.vault_approle import get_role_id
from saltext.vault.modules.vault_approle import get_secret_id
from saltext.vault.modules.vault_approle import list_
from saltext.vault.modules.vault_approle import list_cached
from saltext.vault.modules.vault_approle import lookup_secret_id
from saltext.vault.modules.vault_approle import read
from saltext.vault.modules.vault_approle import write
from saltext.vault.utils.functools import namespaced_function

__func_alias__ = {"list_": "list"}

globals_dict = globals()

clear_cached = namespaced_function(clear_cached, globals_dict)
delete = namespaced_function(delete, globals_dict)
destroy_secret_id = namespaced_function(destroy_secret_id, globals_dict)
get_role_id = namespaced_function(get_role_id, globals_dict)
get_secret_id = namespaced_function(get_secret_id, globals_dict)
list_ = namespaced_function(list_, globals_dict)
list_cached = namespaced_function(list_cached, globals_dict)
lookup_secret_id = namespaced_function(lookup_secret_id, globals_dict)
read = namespaced_function(read, globals_dict)
write = namespaced_function(write, globals_dict)
