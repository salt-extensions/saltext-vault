"""
SSH wrapper for the :py:mod:`vault <saltext.vault.modules.vault>` execution module.

See there for documentation.
"""

from saltext.vault.modules.vault import clear_cache
from saltext.vault.modules.vault import clear_token_cache
from saltext.vault.modules.vault import delete_secret
from saltext.vault.modules.vault import destroy_secret
from saltext.vault.modules.vault import get_server_config
from saltext.vault.modules.vault import list_secrets
from saltext.vault.modules.vault import patch_secret
from saltext.vault.modules.vault import policies_list
from saltext.vault.modules.vault import policy_delete
from saltext.vault.modules.vault import policy_fetch
from saltext.vault.modules.vault import policy_write
from saltext.vault.modules.vault import query
from saltext.vault.modules.vault import read_secret
from saltext.vault.modules.vault import read_secret_meta
from saltext.vault.modules.vault import restore_secret
from saltext.vault.modules.vault import update_config
from saltext.vault.modules.vault import wipe_secret
from saltext.vault.modules.vault import write_raw
from saltext.vault.modules.vault import write_secret
from saltext.vault.utils.functools import namespaced_function

globals_dict = globals()

clear_cache = namespaced_function(clear_cache, globals_dict)
clear_token_cache = namespaced_function(clear_token_cache, globals_dict)
delete_secret = namespaced_function(delete_secret, globals_dict)
destroy_secret = namespaced_function(destroy_secret, globals_dict)
get_server_config = namespaced_function(get_server_config, globals_dict)
list_secrets = namespaced_function(list_secrets, globals_dict)
patch_secret = namespaced_function(patch_secret, globals_dict)
policies_list = namespaced_function(policies_list, globals_dict)
policy_delete = namespaced_function(policy_delete, globals_dict)
policy_fetch = namespaced_function(policy_fetch, globals_dict)
policy_write = namespaced_function(policy_write, globals_dict)
query = namespaced_function(query, globals_dict)
read_secret = namespaced_function(read_secret, globals_dict)
read_secret_meta = namespaced_function(read_secret_meta, globals_dict)
restore_secret = namespaced_function(restore_secret, globals_dict)
update_config = namespaced_function(update_config, globals_dict)
wipe_secret = namespaced_function(wipe_secret, globals_dict)
write_raw = namespaced_function(write_raw, globals_dict)
write_secret = namespaced_function(write_secret, globals_dict)
