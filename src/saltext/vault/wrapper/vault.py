"""
SSH wrapper for the :py:mod:`vault <saltext.vault.modules.vault>` execution module.

See there for documentation.
"""

from salt.utils.functools import namespaced_function

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

clear_cache = namespaced_function(clear_cache, globals())
clear_token_cache = namespaced_function(clear_token_cache, globals())
delete_secret = namespaced_function(delete_secret, globals())
destroy_secret = namespaced_function(destroy_secret, globals())
get_server_config = namespaced_function(get_server_config, globals())
list_secrets = namespaced_function(list_secrets, globals())
patch_secret = namespaced_function(patch_secret, globals())
policies_list = namespaced_function(policies_list, globals())
policy_delete = namespaced_function(policy_delete, globals())
policy_fetch = namespaced_function(policy_fetch, globals())
policy_write = namespaced_function(policy_write, globals())
query = namespaced_function(query, globals())
read_secret = namespaced_function(read_secret, globals())
read_secret_meta = namespaced_function(read_secret_meta, globals())
restore_secret = namespaced_function(restore_secret, globals())
update_config = namespaced_function(update_config, globals())
wipe_secret = namespaced_function(wipe_secret, globals())
write_raw = namespaced_function(write_raw, globals())
write_secret = namespaced_function(write_secret, globals())
