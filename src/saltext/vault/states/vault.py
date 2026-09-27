"""
Deprecated alias to ``vault_policy``.

.. deprecated:: 1.9.0
    This state module was renamed to ``vault_policy``.

    Please adjust your states to use
    :py:func:`vault_policy.present <saltext.vault.states.vault_policy.present>` and
    :py:func:`vault_policy.absent <saltext.vault.states.vault_policy.absent>` instead.
"""

from typing import TYPE_CHECKING

from salt.utils.versions import warn_until

if TYPE_CHECKING:

    from saltext.vault.utils._types import SaltStates

    __states__: SaltStates


def policy_present(name, rules):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_policy.present <saltext.vault.states.vault_policy.present>`.
        Please adjust your states accordingly.
        This compatibility alias will be dropped in the next major release.
    """
    warn_until(
        2,
        (
            "The `vault.policy_present` state was renamed to `vault_policy.present`. "
            "Please adjust your states accordingly. "
            "This compatibility alias will be dropped in version {version}."
        ),
    )
    return __states__["vault_policy.present"](name, rules=rules)


def policy_absent(name):
    """
    .. deprecated:: 1.9.0
        Renamed to :py:func:`vault_policy.absent <saltext.vault.states.vault_policy.absent>`.
        Please adjust your states accordingly.
        This compatibility alias will be dropped in the next major release.
    """
    warn_until(
        2,
        (
            "The `vault.policy_absent` state was renamed to `vault_policy.absent`. "
            "Please adjust your states accordingly. "
            "This compatibility alias will be dropped in version {version}."
        ),
    )
    return __states__["vault_policy.absent"](name)
