"""
Use secret values sourced from Vault (or OpenBao) in ``sdb://`` URIs.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.

Setup
-----
Like all SDB modules, this module requires a configuration profile in either
the minion configuration file or a pillar:

.. code-block:: yaml

    myvault:
      driver: vault

Once configured, you can access data using a URL such as:

.. code-block:: yaml

    password: sdb://myvault/secret/passwords/mypassword

In this URL, ``myvault`` refers to the configuration profile,
``secret/passwords`` is the path where the data resides, and ``mypassword`` is
the key of the data to return.

The above URI is analogous to running the following vault command:

.. code-block:: bash

    $ vault read -field=mypassword secret/passwords


Further configuration
---------------------
The following options can be set in the profile:

.. vconf:: sdb.patch

``patch``
    When writing data, partially update the secret instead of overwriting it completely.
    This is usually the expected behavior, since without this option,
    each secret path can only contain a single mapping key safely.
    Currently defaults to ``False`` for backwards-compatibility reasons.
    Beginning with version 2 of this extension, will default to ``True``.
"""

import logging
from typing import TYPE_CHECKING

import salt.exceptions

from saltext.vault.utils import vault
from saltext.vault.utils.versions import warn_until

if TYPE_CHECKING:
    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltOpts

    __opts__: SaltOpts
    __context__: SaltContext


log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__func_alias__ = {"set_": "set"}


def set_(key, value, profile=None):
    """
    Set a key/value pair in the vault service
    """
    _, path, key = _split_key(key)
    data = {key: value}
    curr_data = {}
    profile = profile or {}
    patch = profile.get("patch")

    if patch is None:
        try:
            warn_until(
                2,
                (
                    "Beginning with version {version}, the Vault SDB module will "
                    "partially update secrets instead of overwriting it completely. "
                    "You can switch to the new behavior explicitly by specifying "
                    "patch: true in your Vault SDB configuration."
                ),
            )
            patch = False
        except RuntimeError:  # pragma: no cover
            patch = True

    if patch:
        try:
            # Patching only works on existing secrets.
            # Save the current data if patching is enabled
            # to write it back later, if any errors happen in patch_kv.
            # This also checks that the path exists, otherwise patching fails as well.
            vault.patch_kv(path, data, __opts__, __context__)
        except vault.VaultNotFoundError:
            pass
        except Exception:  # pylint: disable=broad-except
            # Intentionally broad, maybe it works with simlated patching.
            # Major targets are VaultPermissionDeniedError and VaultAuthExpired.
            # We're catching VaultAuthExpired in case num_uses of the token is 1 and we cannot PATCH in a single request.
            try:
                curr_data = vault.read_kv(path, __opts__, __context__)
            except vault.VaultNotFoundError:
                pass
            except Exception as err:  # pylint: disable=broad-except
                log.error(
                    "Failed to read secret for simulating patching! %s: %s", type(err).__name__, err
                )
                raise salt.exceptions.CommandExecutionError(err) from err
        else:
            return True

    curr_data.update(data)
    try:
        vault.write_kv(path, curr_data, __opts__, __context__)
        return True
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to write secret! %s: %s", type(err).__name__, err)
        raise salt.exceptions.CommandExecutionError(err) from err


def get(key, profile=None):  # pylint: disable=unused-argument
    """
    Get a value from the vault service
    """
    full_path, path, key = _split_key(key)

    try:
        try:
            res = vault.read_kv(path, __opts__, __context__)
            if key in res:
                return res[key]
            return None
        except vault.VaultNotFoundError:
            return vault.read_kv(full_path, __opts__, __context__)
    except vault.VaultNotFoundError:
        return None
    except Exception as err:  # pylint: disable=broad-except
        log.error("Failed to read secret! %s: %s", type(err).__name__, err)
        raise salt.exceptions.CommandExecutionError(err) from err


def _split_key(key: str) -> tuple[str, str, str]:
    if "?" in key:
        path, new_key = key.rsplit("?", 1)
    else:
        try:
            path, new_key = key.rsplit("/", 1)
        except ValueError as err:
            raise salt.exceptions.SaltInvocationError(
                f"Invalid key '{key}', must contain at least one path separator"
            ) from err
    return key, path, new_key
