from unittest.mock import Mock

import pytest

from saltext.vault.states import vault


@pytest.fixture
def vault_policy_state():
    vpmock = Mock()
    vpmock.present.return_value = "yup"
    vpmock.absent.return_value = "yup"
    return vpmock


@pytest.fixture
def configure_loader_modules(vault_policy_state):
    return {
        vault: {
            "__opts__": {"test": False},
            "__states__": {
                "vault_policy.present": vault_policy_state.present,
                "vault_policy.absent": vault_policy_state.absent,
            },
        }
    }


@pytest.mark.parametrize(
    "func,kwargs", (("policy_present", {"rules": "yup"}), ("policy_absent", {}))
)
def test_funcs_emit_warnings(func, kwargs, vault_policy_state):
    new_func = func.rsplit("_", maxsplit=1)[1]
    _func = getattr(vault, func)
    with pytest.deprecated_call(match=f"was renamed to `vault_policy.{new_func}`"):
        assert _func("testrole", **kwargs) == "yup"
    getattr(vault_policy_state, new_func).assert_called_once_with("testrole", **kwargs)
