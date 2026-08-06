from unittest.mock import Mock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

from saltext.vault.modules import vault as vaultexe
from saltext.vault.states import vault


@pytest.fixture
def configure_loader_modules():
    return {vault: {"__opts__": {"test": False}}}


@pytest.fixture
def policy_fetch():
    fetch = Mock(return_value="test-rules", spec=vaultexe.policy_fetch)
    with patch.dict(vault.__salt__, {"vault.policy_fetch": fetch}):
        yield fetch


@pytest.fixture
def policy_write():
    write = Mock(return_value=True, spec=vaultexe.policy_write)
    with patch.dict(vault.__salt__, {"vault.policy_write": write}):
        yield write


@pytest.mark.usefixtures("policy_fetch")
@pytest.mark.parametrize("test", [False, True])
def test_policy_present_no_changes(test):
    """
    Test that when a policy is present as requested, no changes
    are reported for success, regardless of opts["test"].
    """
    with patch.dict(vault.__opts__, {"test": test}):
        res = vault.policy_present("test-policy", "test-rules")
    assert res["result"]
    assert not res["changes"]


@pytest.mark.parametrize("test", [False, True])
def test_policy_present_create(policy_fetch, policy_write, test):
    """
    Test that when a policy does not exist, it is created.
    The function should respect opts["test"].
    """
    policy_fetch.return_value = None
    with patch.dict(vault.__opts__, {"test": test}):
        res = vault.policy_present("test-policy", "test-rules")
    assert res["changes"]
    if test:
        assert res["result"] is None
        assert "would be created" in res["comment"]
        policy_write.assert_not_called()
    else:
        assert res["result"]
        assert "has been created" in res["comment"]
        policy_write.assert_called_once_with("test-policy", "test-rules")


@pytest.mark.usefixtures("policy_fetch")
@pytest.mark.parametrize("test", [False, True])
def test_policy_present_changes(policy_write, test):
    """
    Test that when a policy exists, but the rules need to be updated,
    it is detected and respects the value of opts["test"].
    """
    with patch.dict(vault.__opts__, {"test": test}):
        res = vault.policy_present("test-policy", "new-test-rules")
    assert res["changes"]
    if test:
        assert res["result"] is None
        assert "would be updated" in res["comment"]
        policy_write.assert_not_called()
    else:
        assert res["result"]
        assert "has been updated" in res["comment"]
        policy_write.assert_called_once_with("test-policy", "new-test-rules")


@pytest.mark.parametrize("test", [False, True])
def test_policy_absent_no_changes(policy_fetch, test):
    """
    Test that when a policy is absent as requested, no changes
    are reported for success, regardless of opts["test"].
    """
    policy_fetch.return_value = None
    with patch.dict(vault.__opts__, {"test": test}):
        res = vault.policy_absent("test-policy")
    assert res["result"]
    assert not res["changes"]


@pytest.mark.parametrize(
    "func,kwargs",
    [
        ("policy_present", {"rules": "test-rules"}),
        ("policy_absent", {}),
    ],
)
def test_policy_fetch_errors_are_reported(policy_fetch, func, kwargs):
    """
    Test that policy read errors are caught and reported as a failure.
    """
    policy_fetch.side_effect = CommandExecutionError("booh")
    res = getattr(vault, func)("test-policy", **kwargs)
    assert res["result"] is False
    assert not res["changes"]
    assert "Failed to read policy: booh" in res["comment"]


def test_policy_present_write_errors_are_reported(policy_fetch, policy_write):
    """
    Test that policy write errors are caught and reported as a failure.
    """
    policy_fetch.return_value = None
    policy_write.side_effect = CommandExecutionError("booh")
    res = vault.policy_present("test-policy", "test-rules")
    assert res["result"] is False
    assert not res["changes"]
    assert "Failed to write policy: booh" in res["comment"]


@pytest.mark.usefixtures("policy_fetch")
def test_policy_absent_delete_errors_are_reported():
    """
    Test that a policy that vanishes between the initial fetch and the
    deletion attempt is caught and reported as a failure.
    """
    delete = Mock(return_value=False, spec=vaultexe.policy_delete)
    with patch.dict(vault.__salt__, {"vault.policy_delete": delete}):
        res = vault.policy_absent("test-policy")
    assert res["result"] is False
    assert not res["changes"]
    assert "Failed to delete policy" in res["comment"]
    assert "initially reported as existent" in res["comment"]


@pytest.mark.usefixtures("policy_fetch")
@pytest.mark.parametrize("test", [False, True])
def test_policy_absent_changes(test):
    """
    Test that when a policy exists, it is deleted.
    The function should respect opts["test"].
    """
    delete = Mock(spec=vaultexe.policy_delete)
    with patch.dict(vault.__salt__, {"vault.policy_delete": delete}):
        with patch.dict(vault.__opts__, {"test": test}):
            res = vault.policy_absent("test-policy")
        assert res["changes"]
        if test:
            assert res["result"] is None
            assert "would be deleted" in res["comment"]
            delete.assert_not_called()
        else:
            assert res["result"]
            assert "has been deleted" in res["comment"]
            delete.assert_called_once_with("test-policy")
