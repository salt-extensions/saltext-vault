"""
SSH wrapper for the :py:mod:`vault_policy <saltext.vault.modules.vault_policy>` execution module.

See there for documentation.

.. versionadded:: 1.9.0
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
