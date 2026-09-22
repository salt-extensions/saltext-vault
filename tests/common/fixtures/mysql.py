"""
Shared fixtures for setting up MySQL-compatible database containers.

Based on Salt's testsuite at tests/support/pytest/mysql.py.
"""

import logging
import time
from dataclasses import dataclass

import pytest

from tests.common.containers import Container
from tests.common.containers import ContainerImage

log = logging.getLogger(__name__)


@pytest.fixture(scope="module", params=("10.5",))
def mysql_container(salt_factories, request):
    image = ContainerImage(name="mariadb", tag=request.param)
    mysql_config = MySQLContainer(image=image)
    container = mysql_config.configure(salt_factories)
    with container.started():
        yield mysql_config


@dataclass(kw_only=True, slots=True, repr=False)
class MySQLContainer(Container):
    mysql_host: str = "%"
    mysql_user: str = "salt-mysql-user"
    mysql_passwd: str = "Pa55w0rd!"
    mysql_database: str | None = None
    mysql_root_user: str = "root"
    mysql_root_passwd: str | None = None

    def __post_init__(self):
        # super() is broken in slots dataclasses on Python < 3.12 (gh-90562),
        # and pyupgrade rewrites the explicit two-arg form back to it.
        Container.__post_init__(self)
        if self.mysql_root_passwd is None:
            self.mysql_root_passwd = self.mysql_passwd

    def _configure(self, salt_factories):
        env = {
            "MYSQL_ROOT_PASSWORD": self.mysql_root_passwd,
            "MYSQL_ROOT_HOST": self.mysql_host,
            "MYSQL_USER": self.mysql_user,
            "MYSQL_PASSWORD": self.mysql_passwd,
        }
        if self.mysql_database:
            env["MYSQL_DATABASE"] = self.mysql_database

        container = salt_factories.get_container(
            self.container_id,
            f"ghcr.io/saltstack/salt-ci-containers/{self.image}",
            pull_before_start=True,
            skip_on_pull_failure=True,
            skip_if_docker_client_not_connectable=True,
            container_run_kwargs={
                "ports": {"3306/tcp": None},
                "environment": env,
            },
        )
        return container

    def check_status(self, container):
        ret = container.run(
            "mysql",
            f"--user={self.mysql_user}",
            f"--password={self.mysql_passwd}",
            "-e",
            "SELECT 1",
        )
        if ret.returncode == 0:
            time.sleep(0.5)
            return True
        return False

    def _default_port(self) -> int:
        return 3306
