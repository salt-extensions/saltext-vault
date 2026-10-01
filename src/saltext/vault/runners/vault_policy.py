"""
Runner module equivalent to the :py:mod:`vault_policy <saltext.vault.modules.vault_policy>` execution module.

Uses the actual master token to authenticate, not the master-minion one like :py:func:`salt.cmd <salt.runners.salt.cmd>` would use.

.. versionadded:: 1.9.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

from saltext.vault.modules.vault_policy import __func_alias__  # pylint: disable=unused-import
from saltext.vault.modules.vault_policy import delete
from saltext.vault.modules.vault_policy import fetch
from saltext.vault.modules.vault_policy import list_
from saltext.vault.modules.vault_policy import write
from saltext.vault.utils.functools import namespaced_function

globals_dict = globals()

list_ = namespaced_function(list_, globals_dict)
delete = namespaced_function(delete, globals_dict)
fetch = namespaced_function(fetch, globals_dict)
write = namespaced_function(write, globals_dict)
