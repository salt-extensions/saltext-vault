"""
Runner module equivalent to the :py:mod:`vault_secret <saltext.vault.modules.vault_secret>` execution module.

Uses the actual master token to authenticate, not the master-minion one like :py:func:`salt.cmd <salt.runners.salt.cmd>` would use.

.. versionadded:: 1.9.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

from saltext.vault.modules.vault_secret import __func_alias__  # pylint: disable=unused-import
from saltext.vault.modules.vault_secret import delete
from saltext.vault.modules.vault_secret import destroy
from saltext.vault.modules.vault_secret import list_
from saltext.vault.modules.vault_secret import patch
from saltext.vault.modules.vault_secret import patch_raw
from saltext.vault.modules.vault_secret import read
from saltext.vault.modules.vault_secret import read_meta
from saltext.vault.modules.vault_secret import restore
from saltext.vault.modules.vault_secret import wipe
from saltext.vault.modules.vault_secret import write
from saltext.vault.modules.vault_secret import write_raw
from saltext.vault.utils.functools import namespaced_function

globals_dict = globals()

delete = namespaced_function(delete, globals_dict)
destroy = namespaced_function(destroy, globals_dict)
list_ = namespaced_function(list_, globals_dict)
patch_raw = namespaced_function(patch_raw, globals_dict)
patch = namespaced_function(patch, globals_dict)
read = namespaced_function(read, globals_dict)
read_meta = namespaced_function(read_meta, globals_dict)
restore = namespaced_function(restore, globals_dict)
wipe = namespaced_function(wipe, globals_dict)
write_raw = namespaced_function(write_raw, globals_dict)
write = namespaced_function(write, globals_dict)
