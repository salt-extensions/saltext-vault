from tests.common import PACKAGE_ROOT_REL
from tests.common import TESTS_DIR_REL

CHANGED_FILES_MAP = (
    (  # Full run when any of the core modules, noxfile or pyproject.toml have changes. Also CHANGELOG for release PR.
        (
            "noxfile.py",
            "pyproject.toml",
            "CHANGELOG.md",
            f"{TESTS_DIR_REL}/conftest.py",
            f"{TESTS_DIR_REL}/common/__init__.py",
            f"{TESTS_DIR_REL}/common/containers.py",
            f"{TESTS_DIR_REL}/common/helpers/__init__.py",
            f"{PACKAGE_ROOT_REL}/__init__.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/__init__.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/auth.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/cache.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/client.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/exceptions.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/factory.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/helpers.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/leases.py",
        ),
        ("*",),
    ),
    (  # api util affects many modules
        rf"{PACKAGE_ROOT_REL}/utils/vault/api\.py",
        (
            "tests/*/modules/test_vault_approle.py",
            "tests/*/modules/vault_approle/test_*.py",
            "tests/*/runners/test_vault.py",
            "tests/*/runners/vault/test_*.py",
            "tests/*/states/test_vault_approle.py",
            "tests/*/states/vault_approle/test_*.py",
            "tests/*/utils*/test_approle.py",
            "tests/*/utils*/test_factory.py",
            "tests/*/utils*/factory/test_*.py",
            "tests/*/*/test_*api.py",
            "tests/*/*/*api/test_*.py",
        ),
    ),
    (  # kv util affects many modules
        rf"{PACKAGE_ROOT_REL}/utils/vault/kv\.py",
        (
            "tests/*/modules/test_vault.py",
            "tests/*/modules/vault/test_*.py",
            "tests/*/pillar/test_vault.py",
            "tests/*/pillar/vault/test_*.py",
            "tests/*/sdb/test_vault.py",
            "tests/*/sdb/vault/test_*.py",
            "tests/*/states/test_vault_secret.py",
            "tests/*/states/vault_secret/test_*.py",
            "tests/*/wrapper/test_vault.py",
            "tests/*/wrapper/vault/test_*.py",
            "tests/*/utils*/test_factory.py",
            "tests/*/utils*/factory/test_*.py",
            "tests/*/utils*/test_vault.py",
            "tests/*/*/test_*kv.py",
            "tests/*/*/*kv/test_*.py",
        ),
    ),
    (  # other vault utils like approle
        rf"{PACKAGE_ROOT_REL}/utils/vault/(?P<mod_name>\w+?)\.py",
        (
            "tests/*/*/test_*{mod_name}.py",
            "tests/*/*/*{mod_name}/test_*.py",
        ),
    ),
    (  # functools util affects all wrappers
        rf"{PACKAGE_ROOT_REL}/utils/functools\.py",
        (
            "tests/*/wrapper/*.py",
            "tests/*/utils/test_functools.py",
        ),
    ),
    (  # other non-vault utils like types/version
        rf"{PACKAGE_ROOT_REL}/utils/(?P<mod_name>\w+?)\.py",
        (
            "tests/unit/*/test_*.py",
            "tests/*/utils/test_{mod_name}.py",
            "tests/*/utils/{mod_name}/test_*.py",
        ),
    ),
    (  # vault runner module changes can affect a lot
        rf"{PACKAGE_ROOT_REL}/runners/vault.py",
        (
            "tests/*/runners/test_vault.py",
            "tests/*/runners/vault/test_*.py",
            "tests/*/pillar/test_vault.py",
            "tests/*/pillar/vault/test_*.py",
            "tests/*/sdb/test_vault.py",
            "tests/*/sdb/vault/test_*.py",
            "tests/*/wrapper/test_vault.py",
            "tests/*/wrapper/vault/test_*.py",
            "tests/*/utils*/test_factory.py",
            "tests/*/utils*/factory/test_*.py",
            "tests/functional/test_argspec_works.py",
        ),
    ),
    (  # the vault execution module additionally backs the vault_secret state
        rf"{PACKAGE_ROOT_REL}/modules/vault\.py",
        (
            "tests/*/modules/test_vault.py",
            "tests/*/modules/vault/test_*.py",
            "tests/*/states/test_vault.py",
            "tests/*/states/vault/test_*.py",
            "tests/*/states/test_vault_secret.py",
            "tests/*/states/vault_secret/test_*.py",
            "tests/*/wrapper/test_vault.py",
            "tests/*/wrapper/vault/test_*.py",
            "tests/functional/test_argspec_works.py",
        ),
    ),
    (  # execution module changes affect states and wrappers
        rf"{PACKAGE_ROOT_REL}/modules/(?P<mod_name>\w+?)\.py",
        (
            "tests/*/modules/test_{mod_name}.py",
            "tests/*/modules/{mod_name}/test_*.py",
            "tests/*/states/test_{mod_name}.py",
            "tests/*/states/{mod_name}/test_*.py",
            "tests/*/wrapper/test_{mod_name}.py",
            "tests/*/wrapper/{mod_name}/test_*.py",
            "tests/functional/test_argspec_works.py",
        ),
    ),
    (  # other modules usually just affect themselves
        rf"{PACKAGE_ROOT_REL}/(?P<mod_type>\w+?)/(?P<mod_name>\w+?)\.py",
        (
            "tests/*/{mod_type}/test_{mod_name}.py",
            "tests/*/{mod_type}/{mod_name}/test_*.py",
            "tests/functional/test_argspec_works.py",
        ),
    ),
    (
        rf"{TESTS_DIR_REL}/support/vault\.py",
        (
            "tests/functional/*/test_*.py",
            "tests/integration/*/test_*.py",
        ),
    ),
    (  # db fixtures/helpers also affect the lease beacon tests
        rf"{TESTS_DIR_REL}/common/(?:fixtures/mysql|(?:fixtures|helpers)/vault_db)\.py",
        (
            "tests/functional/*/test_vault_db.py",
            "tests/functional/*/vault_db/test_*.py",
            "tests/integration/*/test_vault_db.py",
            "tests/integration/*/vault_db/test_*.py",
            "tests/functional/*/test_vault_lease.py",
            "tests/functional/*/vault_lease/test_*.py",
            "tests/integration/*/test_vault_lease.py",
            "tests/integration/*/vault_lease/test_*.py",
        ),
    ),
    (  # Core vault fixtures affect kv/policy/cache-related and sdb (via conftest) tests
        rf"{TESTS_DIR_REL}/common/fixtures/vault\.py",
        (
            "tests/functional/modules/vault/test_vault_kv.py",
            "tests/functional/modules/vault/test_vault_policies.py",
            "tests/functional/runners/vault/test_clear_cache_revokes_all_tokens.py",
            "tests/functional/utils/factory/test_clear_cache.py",
            "tests/functional/utils/test_vault_kv.py",
            "tests/functional/utils/test_vault_leases.py",
            "tests/*/sdb/vault/test_*.py",
            "tests/integration/wrapper/test_vault.py",
        ),
    ),
    (  # auth cache helpers are only used by the integration runner tests
        rf"{TESTS_DIR_REL}/common/helpers/vault\.py",
        ("tests/integration/runners/vault/test_*.py",),
    ),
    (  # per-module shared fixtures/helpers affect the module's tests
        rf"{TESTS_DIR_REL}/common/(?:fixtures|helpers)/(?P<mod_name>\w+?)\.py",
        (
            "tests/*/*/test_{mod_name}.py",
            "tests/*/*/{mod_name}/test_*.py",
        ),
    ),
    (  # shared unit test fixtures
        rf"{TESTS_DIR_REL}/unit/fixtures/.*\.py",
        ("tests/unit/*/test_*.py",),
    ),
    (  # run unit tests for other support modules - including this one
        rf"{TESTS_DIR_REL}/support/.*\.py",
        ("tests/unit/*/test_*.py",),
    ),
    (  # conftest changes affect all siblings and children. Root conftest is handled earlier
        rf"{TESTS_DIR_REL}/(?P<parent>.+)/conftest\.py",
        (
            f"{TESTS_DIR_REL}/{{parent}}/test_*.py",
            f"{TESTS_DIR_REL}/{{parent}}/*/test_*.py",
        ),
    ),
    (  # policy files gate permissions for most functional/integration tests
        rf"{TESTS_DIR_REL}/common/files/.*",
        ("*",),
    ),
    (  # wrapper test modules reuse the functional execution module tests
        rf"{TESTS_DIR_REL}/functional/modules/(?:(?P<pkg>\w+)/)?test_(?P<name>\w+)\.py",
        (
            "tests/functional/modules/{pkg}*test_{name}.py",  # the changed file itself
            "tests/integration/wrapper/{pkg}*test_{name}.py",  # same-named wrapper module
            "tests/integration/wrapper/test_{pkg}.py",  # e.g. vault/test_vault_kv.py -> wrapper/test_vault.py
        ),
    ),
    (  # always run changed tests
        rf"{TESTS_DIR_REL}(?P<testmod>.*/test_\w+\.py)",
        (f"{TESTS_DIR_REL}{{testmod}}",),
    ),
)
