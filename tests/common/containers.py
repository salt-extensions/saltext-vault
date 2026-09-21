from collections.abc import Sequence
from typing import Literal
from typing import TypeAlias

import pytest

from tests.common import CONTAINER_TARGETS

require_vault_bin = pytest.mark.skip_if_binaries_missing("vault")
no_container_parametrization = pytest.mark.parametrize(
    "container", (CONTAINER_TARGETS[0],), indirect=True
)


FIXTURE_KWARGS = {
    "vault_secrets": "secrets",
    "secret_mounts": "mounts",
    "pillar_base": "pillar",
    "vault_policies": "policies",
}

Mount: TypeAlias = str | tuple[str, str] | tuple[str, str, str]


def genmarks(
    *fixtures,
    internal_logic_only: bool = False,
    pillar: bool = False,
    policies: Literal[True] | str | Sequence[str] | Sequence[Sequence[str]] | None = None,
    mounts: Literal[True] | str | Sequence[Mount] | Sequence[Sequence[Mount]] | None = None,
    secrets: bool = False,
    **parametrizations,
):
    """
    Generate whole-module ``pytestmark`` contents for functional/integration tests.
    Also ensures the ``docker`` library is available, otherwise skips the tests.

    internal_logic_only
        Set this to true to avoid running the test module with multiple containers.
        Should only be used when the tests don't depend on the API (because they test internal logic only).

    pillar
        Enable the ``pillar_base`` fixture. You can then define a module-scoped ``pillar_defaults``
        fixture that gets applied. A functional-scoped ``pillar_override`` fixture additionally
        allows to override that pillar for specific tests.

    policies
        Ensure specific policies are present in Vault.
        Set this to true to auto-derive the necessary policies from the master config.
        Set this to a name or a sequence of names to ensure they are present.

    secret_mounts
        Ensure specific secret engine mounts are present.
        Set this to true to enable one KVv2 mount at ``secrets``.
        Set this to a string (e. g. ``pki``) to enable the same-named secret engine
        at its default mount location (also ``pki``).
        Can also be a sequence, where the first item is the name of the secret engine,
        the second item is the mount name, and the optional third item a string or
        sequence of strings of options to pass to the mount command.

    vault_secrets
        Ensure specific secrets are present on all KV (!) mounts defined in ``secret_mounts``.
        Define the values that should be written in a module-scoped ``vault_secrets_defaults`` fixture
        that returns a mapping of "<vault path>" to a dictionary of secret data.

    variadic args
        Pass arbitrary additional ``usefixtures``.

    variadic kwargs
        Pass arbitrary ``parametrize`` definitions. Keys are fixture names,
        values their parameters. If fixtures are not in ``usefixtures`` already,
        they are added automatically. All parametrizations are created with ``indirect=True``.
    """
    pytest.importorskip("docker")
    marks = [require_vault_bin]
    usefixtures = ["container"] + list(fixtures)
    parametrize = []

    if pillar:
        usefixtures.append("pillar_base")

    if mounts:
        usefixtures.append("secret_mounts")
        if mounts is not True:
            parametrize.append(
                pytest.mark.parametrize(
                    "secret_mounts",
                    (mounts,) if isinstance(mounts, str) else mounts,
                    indirect=True,
                )
            )

    if secrets:
        usefixtures.append("vault_secrets")

    if policies:
        usefixtures.append("vault_policies")
        if policies is not True:
            parametrize.append(
                pytest.mark.parametrize(
                    "vault_policies",
                    (policies,) if isinstance(policies, str) else policies,
                    indirect=True,
                )
            )

    for fixture, params in parametrizations.items():
        if fixture in FIXTURE_KWARGS:
            raise TypeError(f"`{fixture}` is configured via the `{FIXTURE_KWARGS[fixture]}` kwarg")
        if fixture not in usefixtures:
            usefixtures.append(fixture)
        if isinstance(params, str) or not isinstance(params, Sequence):
            params = (params,)
        parametrize.append(pytest.mark.parametrize(fixture, params, indirect=True))

    marks.append(pytest.mark.usefixtures(*usefixtures))
    marks.extend(parametrize)
    if internal_logic_only:
        marks.append(no_container_parametrization)

    return marks
