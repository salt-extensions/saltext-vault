"""
Beacon for the Vault integration. Sends events when a
lease's TTL undercuts a specified value. By default, also
tries to renew leases before sending an event.

.. versionadded:: 1.1.0

Event description
-----------------

When a lease undercuts its minimum TTL, an event is sent.

The event tag's format is: ``salt/beacon/<minion ID>/vault_lease_<lease cache key>/expire``

The event data contains (non-exhaustive):

* ``expires_in`` - number of seconds left until the lease is revoked by Vault (can be ``-1`` if already revoked)
* ``lease_id`` - the lease ID of the expiring lease
* ``ckey`` - the cache key of the expiring lease
* ``meta`` - custom metadata, e.g. for use in a reactor
* ``expired`` - if the lease is already expired

Example configuration
---------------------
.. code-block:: yaml

    beacons:
      vault_basic:
        - beacon_module: vault_lease
        - leases:
            - db.database.dynamic.basic_lease.default

      vault_advanced:
        - beacon_module: vault_lease
        - leases:
            db.database.dynamic.write_stuff.default: {}
            db.database.dynamic.monitoring.default:
              renew: false
            db.database.dynamic.read_stuff.default:
              min_ttl: 6h
              meta:
                sls: read.stuff
        - min_ttl: 1h
        - meta:
            sls: write.stuff
        - check_server: true

.. _beacon-state-example:

Example for enabling beacon via state
-------------------------------------
This beacon can be added dynamically when explicitly caching
database leases.

.. code-block:: yaml

    Important Vault lease is cached:
      vault_db.creds_cached:
        - name: my_important_role
        - valid_for: 6h  # minimum TTL for the lease to be returned by get_creds
        - revoke_delay: 30m
        - beacon: true   # also add a beacon for monitoring
        - beacon_interval: 300  # interval between beacon runs
        - min_ttl: 12h   # minimum TTL for the beacon to accept the lease as valid
        - meta: my.important.state  # can be used with a reactor
        - order: first   # leases should be cached early

Configuration reference
-----------------------
.. vconf:: lease_beacon.leases

``leases``
    The leases to monitor, referenced by their cache keys.
    This can be a string (single lease), list (multiple leases)
    or mapping (multiple leases with parameter overrides).

.. vconf:: lease_beacon.min_ttl

``min_ttl``
    The minimum TTL a monitored lease should have.
    Can be overridden per configured lease in :vconf:`lease_beacon.leases`.
    If a ``min_ttl`` was set on the lease during its creation,
    this value must be equal or greater to have any effect.
    Defaults to ``300``.

.. vconf:: lease_beacon.check_server

``check_server``
    Whether cached leases should be validated with the Vault server
    before declaring them as valid.
    Can be overridden per configured lease in :vconf:`lease_beacon.leases`.
    There is no equivalent parameter that can be set on the lease during
    its creation currently.
    Defaults to false.

.. vconf:: lease_beacon.meta

``meta``
    Arbitrary metadata to include in expiry events.
    Can be overridden per configured lease in :vconf:`lease_beacon.leases`.
    If ``meta`` was set on the lease during creation, the corresponding
    value takes precedence. If both values are either mappings or lists,
    they will be merged together.

.. vconf:: lease_beacon.renew

``renew``
    Before sending an event, try to renew the lease as needed.
    Defaults to true.
"""

import logging

import salt.utils.beacons
import salt.utils.dictupdate as dup

from saltext.vault.utils import vault
from saltext.vault.utils.vault.helpers import timestring_map

log = logging.getLogger(__name__)


__virtualname__ = "vault_lease"


def __virtual__():
    return __virtualname__


def validate(config):
    """
    Validate the beacon configuration
    """
    if not isinstance(config, list):
        return False, "Configuration for vault_lease must be a list"
    config = salt.utils.beacons.list_to_dict(config)
    if "leases" not in config:
        return False, "Requires monitored lease(s) cache key(s) in `leases`"
    if not isinstance(config["leases"], (dict, list, str)):
        return False, "`leases` must be a dict, list or str"

    if isinstance(config["leases"], str):
        if "*" in config["leases"]:
            return False, "`leases` does not support globs"
    else:
        if any("*" in lease for lease in config["leases"]):
            return False, "`leases` does not support globs"
        if isinstance(config["leases"], dict) and any(
            not isinstance(cfg, dict) for cfg in config["leases"].values()
        ):
            return False, "`leases` mapping values must be dicts"

    return True, "Valid beacon configuration."


def beacon(config):
    """
    Watch the configured lease(s).
    """
    config = _render_config(config)
    # background processes should not pass __context__
    store = vault.get_lease_store(__opts__, {})
    events = []
    for lease, lease_config in config["leases"].items():
        info = store.list_info(match=lease)
        if not info:
            events.append(_enrich_info(lease, lease_config, {"expires_in": -1, "expired": True}))
            continue
        lease_info = info[lease]
        effective_config = _merge_lease_config(lease_config, lease_info)
        if effective_config.get("check_server"):
            try:
                store.lookup(lease_info["lease_id"])
            except vault.VaultNotFoundError:
                store.revoke(lease_info["lease_id"], delta=lease_info.get("revoke_delay"))
                lease_info["expires_in"] = -1
                lease_info["expired"] = True
                events.append(_enrich_info(lease, effective_config, lease_info))
                continue
        if lease_info["expired"]:
            events.append(_enrich_info(lease, effective_config, lease_info))
            continue
        if timestring_map(effective_config["min_ttl"]) >= lease_info["expires_in"]:
            if not effective_config.get("renew", True):
                events.append(_enrich_info(lease, effective_config, lease_info))
                continue
            # attempt renewal
            res = store.get(
                lease,
                valid_for=effective_config["min_ttl"],
                revoke=False,
                check_server=effective_config.get("check_server", False),
            )
            if not res:
                events.append(_enrich_info(lease, effective_config, lease_info))
                continue
    return events


def _enrich_info(lease, effective_config, info):
    info["ckey"] = lease
    info["meta"] = effective_config.get("meta")
    info["min_ttl"] = effective_config.get("min_ttl", 300)
    info["check_server"] = effective_config.get("check_server")
    info.pop("id", None)
    info["tag"] = "expire"
    return info


def _render_config(cfg):
    config = salt.utils.beacons.list_to_dict(cfg)
    if isinstance(config["leases"], str):
        config["leases"] = {config["leases"]: {}}
    if not isinstance(config["leases"], dict):
        config["leases"] = {lease: {} for lease in config["leases"]}
    defaults = {}
    for param in ("min_ttl", "meta", "check_server", "renew"):
        if param in config:
            defaults[param] = config[param]
    return {
        "leases": {
            lease: {**defaults, **lease_config} for lease, lease_config in config["leases"].items()
        }
    }


def _merge_lease_config(cfg, lease):
    if cfg.get("min_ttl") is not None and lease.get("min_ttl") is not None:
        cfg["min_ttl"] = (
            lease["min_ttl"]
            if timestring_map(lease["min_ttl"]) >= timestring_map(cfg["min_ttl"])
            else cfg["min_ttl"]
        )
    elif lease.get("min_ttl") is not None:
        cfg["min_ttl"] = lease["min_ttl"]
    elif "min_ttl" not in cfg:
        cfg["min_ttl"] = 300
    cfg["meta"] = _merge_meta(cfg.get("meta"), lease.get("meta"))
    return cfg


def _merge_meta(default, ovrr):
    if ovrr is None:
        return default
    default = default if default is not None else {}
    for val in (default, ovrr):
        if not isinstance(val, (dict, list)):
            return ovrr
    if type(default) is not type(ovrr):
        return ovrr
    if isinstance(default, list):
        return default + ovrr
    return dup.merge(default, ovrr, merge_lists=True) or None
