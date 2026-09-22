"""
Test the ``vault_ssh`` CA states with a minion whose token only carries the
documented minimal policy for ``vault_ssh.create_ca``, i.e. it cannot read
``<mount>/config/ca``. ``read_ca`` then falls back to the unauthenticated
``<mount>/public_key`` endpoint, which returns an HTTP error status when no
CA has been configured yet.
"""

import pytest

from tests.common import gen_minion_opts
from tests.common.containers import genmarks
from tests.common.fixtures.vault_ssh import clean_ssh_issuer  # pylint: disable=unused-import
from tests.support.vault import vault_delete_policy
from tests.support.vault import vault_read
from tests.support.vault import vault_write
from tests.support.vault import vault_write_policy

pytestmark = genmarks(mounts="ssh")


POLICY = """\
path "ssh/config/ca" {
    capabilities = ["create", "update"]
}
"""


@pytest.fixture(scope="module")
def minion_config_overrides(container):  # pylint: disable=unused-argument
    vault_write_policy("ssh_ca_writeonly", POLICY)
    res = vault_write("auth/token/create", policies=["ssh_ca_writeonly"])
    try:
        opts = gen_minion_opts(auth_token=res["auth"]["client_token"])
        yield opts
    finally:
        vault_delete_policy("ssh_ca_writeonly")


@pytest.fixture
def vault_ssh(states):
    return states.vault_ssh


@pytest.mark.usefixtures("clean_ssh_issuer")
def test_ca_present(vault_ssh, testmode):
    ret = vault_ssh.ca_present("foobar", test=testmode)
    assert ret.result is (None if testmode else True)
    assert ("would have" in ret.comment) is testmode
    assert "created" in ret.changes
    assert bool(vault_read("ssh/config/ca", default=False)) is not testmode


def test_ca_absent_already_absent(vault_ssh, testmode):
    ret = vault_ssh.ca_absent("foobar", test=testmode)
    assert ret.result is True
    assert "There is no CA" in ret.comment
    assert not ret.changes
