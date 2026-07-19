"""
SSH wrapper for the :py:mod:`vault_plugin <saltext.vault.modules.vault_plugin>` execution module.

See there for documentation.
"""

from saltext.vault.modules.vault_plugin import _check_type
from saltext.vault.modules.vault_plugin import _list_all_filtered
from saltext.vault.modules.vault_plugin import _list_pins_filtered
from saltext.vault.modules.vault_plugin import deregister
from saltext.vault.modules.vault_plugin import get_config
from saltext.vault.modules.vault_plugin import list_
from saltext.vault.modules.vault_plugin import list_detailed
from saltext.vault.modules.vault_plugin import list_pins
from saltext.vault.modules.vault_plugin import list_versions
from saltext.vault.modules.vault_plugin import pin
from saltext.vault.modules.vault_plugin import pinned_version
from saltext.vault.modules.vault_plugin import register
from saltext.vault.modules.vault_plugin import reload
from saltext.vault.modules.vault_plugin import reload_mounts
from saltext.vault.modules.vault_plugin import reload_named
from saltext.vault.modules.vault_plugin import unpin
from saltext.vault.utils.functools import namespaced_function

globals_dict = globals()

_check_type = namespaced_function(_check_type, globals_dict)
_list_all_filtered = namespaced_function(_list_all_filtered, globals_dict)
_list_pins_filtered = namespaced_function(_list_pins_filtered, globals_dict)
deregister = namespaced_function(deregister, globals_dict)
get_config = namespaced_function(get_config, globals_dict)
list_ = namespaced_function(list_, globals_dict)
list_detailed = namespaced_function(list_detailed, globals_dict)
list_pins = namespaced_function(list_pins, globals_dict)
list_versions = namespaced_function(list_versions, globals_dict)
pin = namespaced_function(pin, globals_dict)
pinned_version = namespaced_function(pinned_version, globals_dict)
register = namespaced_function(register, globals_dict)
reload = namespaced_function(reload, globals_dict)
reload_mounts = namespaced_function(reload_mounts, globals_dict)
reload_named = namespaced_function(reload_named, globals_dict)
unpin = namespaced_function(unpin, globals_dict)
