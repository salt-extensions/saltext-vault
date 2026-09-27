import logging

import pytest

from tests.common.containers import genmarks
from tests.common.fixtures.vault_policy import clean_policies  # pylint: disable=unused-import
from tests.common.fixtures.vault_policy import temp_policy  # pylint: disable=unused-import
from tests.common.fixtures.vault_policy import temp_policy_rules  # pylint: disable=unused-import
from tests.support.vault import vault_list_policies
from tests.support.vault import vault_read_policy

pytestmark = genmarks()

log = logging.getLogger(__name__)


@pytest.fixture
def vault_policy(modules, container, clean_policies):  # pylint: disable=unused-argument
    return modules.vault_policy


def test_fetch(vault_policy, temp_policy_rules, temp_policy):
    ret = vault_policy.fetch(temp_policy)
    assert ret == temp_policy_rules


def test_fetch_missing(vault_policy):
    ret = vault_policy.fetch("__does_not_exist__")
    assert ret is None


def test_write(vault_policy, temp_policy_rules):
    ret = vault_policy.write("test_policy_write", temp_policy_rules)
    assert ret is True
    assert vault_read_policy("test_policy_write") == temp_policy_rules


def test_delete(vault_policy, temp_policy):
    ret = vault_policy.delete(temp_policy)
    assert ret is True
    assert temp_policy not in vault_list_policies()


def test_list(vault_policy, temp_policy):
    ret = vault_policy.list()
    assert temp_policy in ret
