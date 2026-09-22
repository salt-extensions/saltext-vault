from tests.support.vault import vault_plugin_deregister
from tests.support.vault import vault_plugin_list
from tests.support.vault import vault_plugin_show_pin
from tests.support.vault import vault_plugin_unpin


def reset_plugins(container):
    for plugin in vault_plugin_list(lambda x: not x["builtin"]):
        if container.is_vault_latest() and vault_plugin_show_pin(plugin["type"], plugin["name"]):
            vault_plugin_unpin(plugin["type"], plugin["name"])
        vault_plugin_deregister(plugin["type"], plugin["name"], version=plugin["version"])
