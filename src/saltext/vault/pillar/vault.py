"""
Use secrets sourced from Vault in minion pillars.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.

Setup
-----
Include this module in your :conf_master:`ext_pillar` configuration:

.. code-block:: yaml

    ext_pillar:
      - vault:
          conf: path=secret/salt

.. hint::
    You can also include multiple instances of this module in your configuration.

Now all keys of the Vault KV path ``secret/salt`` will be inserted into each
minion's pillar, which is quite inflexible and usually not what is wanted.
To work around that, you can :ref:`template the path <vault-templating>`.

.. note::
    If a pattern matches multiple paths, the results are merged according
    to the master configuration values :conf_master:`pillar_source_merging_strategy <pillar_source_merging_strategy>`
    and :conf_master:`pillar_merge_lists <pillar_merge_lists>` by default.
    If the optional :vconf:`nesting_key <pillar.nesting_key>` was defined,
    the merged result will be nested below.
    There is currently no way to nest multiple results under different keys.

Further configuration
---------------------
.. vconf:: pillar.nesting_key

``nesting_key``
    The Vault-sourced pillar values are usually merged into the root
    of the pillar. This option allows you to specify a parent key
    under which all values will be nested. If the key contains previous
    values, they will be merged.

.. vconf:: pillar.merge_strategy

``merge_strategy``
    When multiple paths are matched by a templated path, use this merge strategy
    instead of :conf_master:`pillar_source_merging_strategy <pillar_source_merging_strategy>`.

.. vconf:: pillar.merge_lists

``merge_lists``
    Override the default set by :conf_master:`pillar_merge_lists <pillar_merge_lists>`.


Complete configuration
----------------------
.. code-block:: yaml

    ext_pillar:
      - vault:
           conf: path=secret/roles/{pillar[roles]}
           nesting_key: vault_sourced
           merge_strategy: smart
           merge_lists: false
"""
import logging

import salt.utils.dictupdate
import saltext.vault.utils.vault as vault
import saltext.vault.utils.vault.helpers as vhelpers
from salt.exceptions import SaltException

log = logging.getLogger(__name__)


def ext_pillar(
    minion_id,  # pylint: disable=W0613
    pillar,  # pylint: disable=W0613
    conf,
    nesting_key=None,
    merge_strategy=None,
    merge_lists=None,
    extra_minion_data=None,
):
    """
    Get pillar data from Vault for the configuration ``conf``.
    """
    extra_minion_data = extra_minion_data or {}
    if extra_minion_data.get("_vault_runner_is_compiling_pillar_templates"):
        # Disable vault ext_pillar while compiling pillar for vault policy templates
        return {}
    comps = conf.split()

    paths = [comp for comp in comps if comp.startswith("path=")]
    if not paths:
        log.error('"%s" is not a valid Vault ext_pillar config', conf)
        return {}

    merge_strategy = merge_strategy or __opts__.get("pillar_source_merging_strategy", "smart")
    merge_lists = merge_lists or __opts__.get("pillar_merge_lists", False)

    vault_pillar = {}

    path_pattern = paths[0].replace("path=", "")
    for path in _get_paths(path_pattern, minion_id, pillar):
        try:
            vault_pillar_single = vault.read_kv(path, __opts__, __context__)
            vault_pillar = salt.utils.dictupdate.merge(
                vault_pillar,
                vault_pillar_single,
                strategy=merge_strategy,
                merge_lists=merge_lists,
            )
        except SaltException:
            log.info("Vault secret not found for: %s", path)

    if nesting_key:
        vault_pillar = {nesting_key: vault_pillar}
    return vault_pillar


def _get_paths(path_pattern, minion_id, pillar):
    """
    Get the paths that should be merged into the pillar dict
    """
    mappings = {"minion": minion_id, "pillar": pillar}

    paths = []
    try:
        for expanded_pattern in vhelpers.expand_pattern_lists(path_pattern, **mappings):
            paths.append(expanded_pattern.format(**mappings))
    except KeyError:
        log.warning("Could not resolve pillar path pattern %s", path_pattern)

    log.debug("%s vault pillar paths: %s", minion_id, paths)
    return paths
