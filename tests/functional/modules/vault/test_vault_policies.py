import logging

import pytest

from tests.common.containers import genmarks
from tests.common.fixtures.vault import clean_policies  # pylint: disable=unused-import
from tests.common.fixtures.vault import temp_policy  # pylint: disable=unused-import
from tests.common.fixtures.vault import temp_policy_rules  # pylint: disable=unused-import
from tests.support.vault import vault_list_policies
from tests.support.vault import vault_read_policy

pytestmark = genmarks()

log = logging.getLogger(__name__)


@pytest.fixture
def vault(modules, container, clean_policies):  # pylint: disable=unused-argument
    return modules.vault


def test_policy_fetch(vault, temp_policy_rules, temp_policy):
    ret = vault.policy_fetch(temp_policy)
    assert ret == temp_policy_rules


def test_policy_fetch_missing(vault):
    ret = vault.policy_fetch("__does_not_exist__")
    assert ret is None


def test_policy_write(vault, temp_policy_rules):
    ret = vault.policy_write("test_policy_write", temp_policy_rules)
    assert ret is True
    assert vault_read_policy("test_policy_write") == temp_policy_rules


def test_policy_delete(vault, temp_policy):
    ret = vault.policy_delete(temp_policy)
    assert ret is True
    assert temp_policy not in vault_list_policies()


def test_policies_list(vault, temp_policy):
    ret = vault.policies_list()
    assert temp_policy in ret
