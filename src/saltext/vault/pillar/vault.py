"""
Use secrets sourced from Vault in minion pillars.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.

.. warning::
    A minion must not be able to write to its own pillar source path,
    otherwise a core security assumption in Salt is violated.

.. versionchanged:: 1.0.0
    Previous versions of this pillar module found in Salt core were configured
    with a parameter named ``conf``, expecting a single value representing
    the path to include in the pillar with the prefix ``path=``.
    This parameter has been deprecated. Please configure this pillar module
    either by just passing the path or declaring it as ``path: <path>``.

Setup
-----
Include this module in your :conf_master:`ext_pillar` configuration:

.. code-block:: yaml

    ext_pillar:
      - vault: salt/global

.. hint::
    You can also include multiple instances of this module in your configuration.

Now all keys of the Vault KV path ``salt/global`` are inserted into each
minion's pillar, which is quite inflexible and usually not what is wanted.
To work around that, you can :ref:`template the path <vault-templating>`.

.. code-block:: yaml

    ext_pillar:
      - vault: salt/minions/{minion}
      - vault: salt/roles/{pillar[roles]}

.. note::
    There is currently no ``top.sls`` equivalent.

.. note::
    If a pattern matches multiple paths, the results are merged according
    to the master configuration values :conf_master:`pillar_source_merging_strategy <pillar_source_merging_strategy>`
    and :conf_master:`pillar_merge_lists <pillar_merge_lists>` by default.
    If the optional :vconf:`nesting_key <pillar.nesting_key>` is defined,
    the merged result is nested below.
    There is currently no way to nest multiple results under different keys.

.. vconf:: pillar

Configuration reference
-----------------------
.. vconf:: pillar.path

``path``
    The path to include in the minion pillars. Can be :ref:`templated <vault-templating>`.

.. vconf:: pillar.nesting_key

``nesting_key``
    The Vault-sourced pillar values are usually merged into the root
    of the pillar. This option allows you to specify a parent key
    under which all values are nested. If the key contains previous
    values, they are merged.

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
           path: salt/roles/{pillar[roles]}
           nesting_key: vault_sourced
           merge_strategy: smart
           merge_lists: false
"""

import logging

import salt.utils.dictupdate
from salt.exceptions import InvalidConfigError
from salt.exceptions import SaltException

from saltext.vault.utils import vault
from saltext.vault.utils.vault import helpers
from saltext.vault.utils.versions import warn_until

log = logging.getLogger(__name__)


def ext_pillar(
    minion_id,  # pylint: disable=W0613
    pillar,  # pylint: disable=W0613
    path=None,
    nesting_key=None,
    merge_strategy=None,
    merge_lists=None,
    extra_minion_data=None,
    conf=None,
):
    """
    Get pillar data from Vault for the configuration ``conf``.
    """
    extra_minion_data = extra_minion_data or {}
    if extra_minion_data.get("_vault_runner_is_compiling_pillar_templates"):
        # Disable vault ext_pillar while compiling pillar for vault policy templates
        return {}
    if conf is not None:
        comps = conf.split()
        paths = [comp for comp in comps if comp.startswith("path=")]
        if not paths:
            log.error('"%s" is not a valid Vault ext_pillar config', conf)
            return {}
        path_pattern = paths[0].replace("path=", "")
        warn_until(
            2,
            (
                "The `conf` parameter to the Vault pillar is deprecated. "
                "Please migrate to the `path` parameter. It takes the path "
                "as its parameter, without the `path=` prefix."
            ),
        )
    elif path is not None:
        comps = path.split()
        if not comps:
            log.error('"%s" is not a valid Vault ext_pillar config', path)
            return {}
        if len(comps) > 1:
            warn_until(
                2,
                (
                    "The `conf` parameter to the Vault pillar is deprecated. "
                    "Please migrate to the `path` parameter. It takes the path "
                    "as its parameter, without the `path=` prefix."
                ),
            )
            comps = [comp for comp in comps if comp.startswith("path=")]
            if not comps:
                log.error('"%s" is not a valid Vault ext_pillar config', path)
                return {}
        path = comps[0]
        if path.startswith("path="):
            warn_until(
                2,
                (
                    "The Vault pillar module should not be configured with "
                    "the `path=` prefix anymore. Please remove it from your "
                    "configuration."
                ),
            )
            path = path[5:]
        path_pattern = path
    else:
        raise InvalidConfigError("Need a Vault path to include in the pillar")

    merge_strategy = merge_strategy or __opts__.get("pillar_source_merging_strategy", "smart")
    merge_lists = merge_lists or __opts__.get("pillar_merge_lists", False)

    vault_pillar = {}

    for path in _get_paths(path_pattern, minion_id, pillar):
        try:
            vault_pillar_single = vault.read_kv(path, __opts__, __context__)
        except vault.VaultNotFoundError:
            log.info("Vault secret not found for: %s", path, exc_info_on_loglevel=logging.DEBUG)
        except SaltException:
            log.warning(
                "Error fetching Vault secret at: %s", path, exc_info_on_loglevel=logging.DEBUG
            )
        else:
            vault_pillar = salt.utils.dictupdate.merge(
                vault_pillar,
                vault_pillar_single,
                strategy=merge_strategy,
                merge_lists=merge_lists,
            )

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
        for expanded_pattern in helpers.expand_pattern_lists(path_pattern, **mappings):
            paths.append(expanded_pattern.format(**mappings))
    except KeyError:
        log.warning("Could not resolve pillar path pattern %s", path_pattern)

    log.debug("%s vault pillar paths: %s", minion_id, paths)
    return paths
