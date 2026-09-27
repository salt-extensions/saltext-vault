"""
Manage Vault (or OpenBao) policies.

.. versionadded:: 1.9.0
    The functions in this module were extracted from :py:mod:`vault <saltext.vault.modules.vault>`.

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from typing import TYPE_CHECKING

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltException

from saltext.vault.utils import vault

if TYPE_CHECKING:
    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltGrains
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltOpts

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __grains__: SaltGrains

log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__func_alias__ = {"list_": "list"}
__virtualname__ = "vault_policy"


def fetch(policy):
    """
    Fetch the rules associated with an ACL policy. Returns ``None`` if the policy
    does not exist.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_policy.fetch salt_minion

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy/<policy>" {
            capabilities = ["read"]
        }

    policy
        Name of the policy to fetch.
    """
    # there is also "sys/policies/acl/{policy}"
    endpoint = f"sys/policy/{policy}"

    try:
        data = vault.api_get(endpoint, __opts__, __context__)
        return data["rules"]

    except vault.VaultNotFoundError:
        return None
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write(policy, rules):
    r"""
    Create or update an ACL policy.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_policy.write salt_minion 'path "secret/foo" {...}'

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy/<policy>" {
            capabilities = ["create", "update"]
        }

    policy
        Name of the policy to create/update.

    rules
        Rules to write, formatted as in-line HCL.
    """
    endpoint = f"sys/policy/{policy}"
    payload = {"policy": rules}
    try:
        return vault.api_put(endpoint, __opts__, __context__, payload=payload)
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete(policy):
    """
    Delete an ACL policy. Returns False if the policy does not exist.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_policy.delete salt_minion

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy/<policy>" {
            capabilities = ["delete"]
        }

    policy
        Name of the policy to delete.
    """
    endpoint = f"sys/policy/{policy}"

    try:
        return vault.api_delete(endpoint, __opts__, __context__)
    except vault.VaultNotFoundError:
        return False
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_():
    """
    List all ACL policies.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_policy.list

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/policy" {
            capabilities = ["read"]
        }
    """
    try:
        return vault.api_get("sys/policy", __opts__, __context__)["policies"]
    except SaltException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
