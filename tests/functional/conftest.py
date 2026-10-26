from __future__ import annotations

import logging
import shutil
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any

import pytest
from saltfactories.utils import random_string

from tests.common import ExtendedLoaders
from tests.common.helpers import _pillar_files
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_read
from tests.support.vault import vault_write

if TYPE_CHECKING:
    from _pytest.tmpdir import TempPathFactory
    from saltfactories.manager import FactoriesManager  # Needs lazy import

    from tests._types import SaltLoader
    from tests._types import Yielder

log = logging.getLogger(__name__)


@pytest.fixture(params=(False, True))
def testmode(request):
    return request.param


@pytest.fixture(scope="package")
def minion_id() -> str:  # pragma: no cover
    # Random to avoid factory directory collisions, e.g. with pytest-xdist
    return random_string("func-tests-minion-")


@pytest.fixture(scope="module")
def state_tree(tmp_path_factory: TempPathFactory) -> Yielder[Path]:  # pragma: no cover
    state_tree_path = tmp_path_factory.mktemp("state-tree-base")
    try:
        yield state_tree_path
    finally:
        shutil.rmtree(str(state_tree_path), ignore_errors=True)


@pytest.fixture(scope="module")
def state_tree_prod(tmp_path_factory: TempPathFactory) -> Yielder[Path]:  # pragma: no cover
    state_tree_path = tmp_path_factory.mktemp("state-tree-prod")
    try:
        yield state_tree_path
    finally:
        shutil.rmtree(str(state_tree_path), ignore_errors=True)


@pytest.fixture(scope="module")
def minion_opts(
    salt_factories: FactoriesManager,
    minion_id: str,
    state_tree: Path,
    state_tree_prod: Path,
    minion_config_defaults: dict[str, Any],
    minion_config_overrides: dict[str, Any],
) -> dict[str, Any]:  # pragma: no cover
    minion_config_overrides.update(
        {
            "file_client": "local",
            "file_roots": {
                "base": [
                    str(state_tree),
                ],
                "prod": [
                    str(state_tree_prod),
                ],
            },
        }
    )
    factory = salt_factories.salt_minion_daemon(
        minion_id,
        defaults=minion_config_defaults or None,
        overrides=minion_config_overrides,
    )
    return factory.config.copy()


@pytest.fixture(scope="module")
def master_opts(
    salt_factories: FactoriesManager,
    state_tree: Path,
    state_tree_prod: Path,
    master_config_defaults: dict[str, Any],
    master_config_overrides: dict[str, Any],
) -> dict[str, Any]:  # pragma: no cover
    master_config_overrides.update(
        {
            "file_client": "local",
            "file_roots": {
                "base": [
                    str(state_tree),
                ],
                "prod": [
                    str(state_tree_prod),
                ],
            },
        }
    )
    factory = salt_factories.salt_master_daemon(
        "func-tests-master-opts",
        defaults=master_config_defaults or None,
        overrides=master_config_overrides,
    )
    return factory.config.copy()


@pytest.fixture(scope="module")
def loaders(minion_opts: dict[str, Any]) -> ExtendedLoaders:  # pragma: no cover
    return ExtendedLoaders(minion_opts, loaded_base_name=f"{__name__}.loaded")


@pytest.fixture(scope="module")
def master_loaders(master_opts: dict[str, Any]) -> ExtendedLoaders:  # pragma: no cover
    return ExtendedLoaders(master_opts, loaded_base_name=f"{__name__}.master.loaded")


@pytest.fixture(autouse=True)
def reset_loaders_state(
    loaders: ExtendedLoaders, master_loaders: ExtendedLoaders
) -> Yielder[None]:  # pragma: no cover
    try:
        # Run the tests
        yield
    finally:
        # Reset the loaders state
        loaders.reset_state()
        master_loaders.reset_state()


@pytest.fixture(scope="module")
def modules(loaders: ExtendedLoaders) -> SaltLoader:  # pragma: no cover
    return loaders.modules


@pytest.fixture(scope="module")
def states(loaders: ExtendedLoaders) -> SaltLoader:  # pragma: no cover
    return loaders.states


@pytest.fixture(scope="module")
def pillar_base(pillar_defaults, minion, loaders):
    """
    Module-scoped fixture to create pillars.
    """
    files, refresh = _pillar_files(pillar_defaults, "*")
    with ExitStack() as stack:
        for pillar, contents in files:
            stack.enter_context(minion.pillar_tree.base.temp_file(pillar, contents))
        if refresh:
            loaders.refresh_pillar()
        yield


@pytest.fixture(scope="module")
def approle(container, request):  # pylint: disable=unused-argument
    defaults = {
        "token_ttl": "60m",
        "token_num_uses": 0,
        "secret_id_ttl": "60m",
        "secret_id_num_uses": 0,
        "token_policies": ["salt_minion"],
    }
    defaults.update(getattr(request, "param", {}))
    mount = random_string("approle-testsuite", uppercase=False)
    role = "test-role"
    assert vault_enable_auth_method("approle", mount)
    try:
        vault_write(f"auth/{mount}/role/{role}", **defaults)
        role_id = vault_read(f"auth/{mount}/role/{role}/role-id")["data"]["role_id"]
        secret_id = None
        if defaults.get("bind_secret_id", True):
            secret_id = vault_write(f"auth/{mount}/role/{role}/secret-id")["data"]["secret_id"]
        yield {"mount": mount, "role_id": role_id, "secret_id": secret_id, "name": role}
    finally:
        assert vault_disable_auth_method(mount)
