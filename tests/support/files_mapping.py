from pathlib import Path

from saltext.vault import PACKAGE_ROOT

TESTS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = TESTS_DIR.parent
PACKAGE_ROOT_REL = PACKAGE_ROOT.relative_to(REPO_ROOT)
TESTS_DIR_REL = TESTS_DIR.relative_to(REPO_ROOT)

CHANGED_FILES_MAP = (
    (  # Full run when any of the core modules, noxfile or pyproject.toml have changes. Also CHANGELOG for release PR.
        (
            "noxfile.py",
            "pyproject.toml",
            "CHANGELOG.md",
            f"{TESTS_DIR_REL}/conftest.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/__init__.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/auth.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/cache.py",
            f"{PACKAGE_ROOT_REL}/utils/vault/client.py",
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
        ("tests/*/wrapper/*.py",),
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
    (
        rf"{TESTS_DIR_REL}/support/mysql\.py",
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
    (
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
    (  # always run changed tests
        rf"{TESTS_DIR_REL}(?P<testmod>.*/test_\w+\.py)",
        (f"{TESTS_DIR_REL}{{testmod}}",),
    ),
)
