"""
This is copied from Salt's testsuite at tests/support/pytest/mysql.py.
"""

import logging
import time
from dataclasses import dataclass

import pytest
from pytestskipmarkers.utils import platform
from saltfactories.utils import random_string

# This `pytest.importorskip` here actually works because this module
# is imported into test modules, otherwise, the skipping would just fail
pytest.importorskip("docker")
import docker.errors  # isort:skip pylint:disable=wrong-import-position

log = logging.getLogger(__name__)


@dataclass(kw_only=True, slots=True)
class MySQLImage:
    name: str
    tag: str
    container_id: str

    def __str__(self):
        return f"{self.name}:{self.tag}"


@dataclass(kw_only=True, slots=True)
class MySQLCombo:
    mysql_name: str
    mysql_version: str
    mysql_port: int | None = None
    mysql_host: str = "%"
    mysql_user: str
    mysql_passwd: str
    mysql_database: str | None = None
    mysql_root_user: str = "root"
    mysql_root_passwd: str | None = None
    container: str | None = None
    container_id: str | None = None

    def __post_init__(self):
        if self.container_id is None:
            self.container_id = self._default_container_id()
        if self.mysql_root_passwd is None:
            self.mysql_root_passwd = self.mysql_passwd

    def _default_container_id(self):
        return random_string(
            "{}-{}-".format(  # pylint: disable=consider-using-f-string
                self.mysql_name.replace("/", "-"),
                self.mysql_version,
            )
        )

    def get_credentials(self, **kwargs):
        return {
            "connection_user": kwargs.get("connection_user") or self.mysql_root_user,
            "connection_pass": kwargs.get("connection_pass") or self.mysql_root_passwd,
            "connection_db": kwargs.get("connection_db") or "mysql",
            "connection_port": kwargs.get("connection_port") or self.mysql_port,
        }


def get_test_versions():
    test_versions = []
    name = "mysql-server"
    for version in ("5.5", "5.6", "5.7", "8.0"):
        test_versions.append(
            MySQLImage(
                name=name,
                tag=version,
                container_id=random_string(f"mysql-{version}-"),
            )
        )
    name = "mariadb"
    for version in ("10.3", "10.4", "10.5"):
        test_versions.append(
            MySQLImage(
                name=name,
                tag=version,
                container_id=random_string(f"mariadb-{version}-"),
            )
        )
    name = "percona"
    for version in ("5.6", "5.7", "8.0"):
        test_versions.append(
            MySQLImage(
                name=name,
                tag=version,
                container_id=random_string(f"percona-{version}-"),
            )
        )
    return test_versions


def get_test_version_id(value):
    return f"container={value}"


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


def check_container_started(timeout_at, container, combo):
    sleeptime = 0.5
    while time.time() <= timeout_at:
        try:
            if not container.is_running():
                log.warning("%s is no longer running", container)
                return False
            ret = container.run(
                "mysql",
                f"--user={combo.mysql_user}",
                f"--password={combo.mysql_passwd}",
                "-e",
                "SELECT 1",
            )
            if ret.returncode == 0:
                break
        except docker.errors.APIError:
            log.exception("Failed to run start check")
        time.sleep(sleeptime)
        sleeptime *= 2
    else:
        return False
    time.sleep(0.5)
    return True


def set_container_name_before_start(container):
    """
    This is useful if the container has to be restared and the old
    container, under the same name was left running, but in a bad shape.
    """
    container.name = random_string(
        "{}-".format(container.name.rsplit("-", 1)[0])  # pylint: disable=consider-using-f-string
    )
    container.display_name = None
    return container


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
