"""
Shared fixtures for setting up MySQL-compatible database containers.

Extracted from tests/support/mysql.py, which was copied from Salt's
testsuite at tests/support/pytest/mysql.py.
"""

import pytest
from pytestskipmarkers.utils import platform

from tests.support.mysql import MySQLCombo
from tests.support.mysql import check_container_started
from tests.support.mysql import get_test_version_id
from tests.support.mysql import get_test_versions
from tests.support.mysql import set_container_name_before_start


@pytest.fixture(scope="module", params=get_test_versions(), ids=get_test_version_id)
def mysql_image(request):
    return request.param


@pytest.fixture(scope="module")
def create_mysql_combo(mysql_image):
    if platform.is_fips_enabled():
        if mysql_image.name in ("mysql-server", "percona") and mysql_image.tag == "8.0":
            pytest.skip(f"These tests fail on {mysql_image.name}:{mysql_image.tag}")

    return MySQLCombo(
        mysql_name=mysql_image.name,
        mysql_version=mysql_image.tag,
        mysql_user="salt-mysql-user",
        mysql_passwd="Pa55w0rd!",
        container_id=mysql_image.container_id,
    )


@pytest.fixture(scope="module")
def mysql_combo(create_mysql_combo):
    return create_mysql_combo


@pytest.fixture(scope="module")
def mysql_container(salt_factories, mysql_combo):

    container_environment = {
        "MYSQL_ROOT_PASSWORD": mysql_combo.mysql_passwd,
        "MYSQL_ROOT_HOST": mysql_combo.mysql_host,
        "MYSQL_USER": mysql_combo.mysql_user,
        "MYSQL_PASSWORD": mysql_combo.mysql_passwd,
    }
    if mysql_combo.mysql_database:
        container_environment["MYSQL_DATABASE"] = mysql_combo.mysql_database

    container = salt_factories.get_container(
        mysql_combo.container_id,
        "ghcr.io/saltstack/salt-ci-containers/{}:{}".format(  # pylint: disable=consider-using-f-string
            mysql_combo.mysql_name, mysql_combo.mysql_version
        ),
        pull_before_start=True,
        skip_on_pull_failure=True,
        skip_if_docker_client_not_connectable=True,
        container_run_kwargs={
            "ports": {"3306/tcp": None},
            "environment": container_environment,
        },
    )
    container.before_start(set_container_name_before_start, container)
    container.container_start_check(check_container_started, container, mysql_combo)
    with container.started():
        mysql_combo.container = container
        mysql_combo.mysql_port = container.get_host_port_binding(3306, protocol="tcp", ipv6=False)
        yield mysql_combo
