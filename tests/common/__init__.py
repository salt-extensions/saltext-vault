import functools
import os
import typing
from collections.abc import Mapping
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

import salt.exceptions
from salt.utils.dictupdate import set_dict_key_value
from salt.utils.dictupdate import update
from salt.version import __version_info__ as _SALT_VERSION
from saltfactories.utils.functional import PATCH_TARGET
from saltfactories.utils.functional import Loaders
from saltfactories.utils.functional import StateResult

from saltext.vault import PACKAGE_ROOT

# Repo layout
TESTS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = TESTS_DIR.parent
FILES_DIR = TESTS_DIR / "common/files"
PACKAGE_ROOT_REL = PACKAGE_ROOT.relative_to(REPO_ROOT)
TESTS_DIR_REL = TESTS_DIR.relative_to(REPO_ROOT)

# Salt version in test venv
if os.environ.get("SALT_REQUIREMENT") == "salt==master":
    SALT_VERSION = (_SALT_VERSION[0] + 1, 0)
else:
    SALT_VERSION = tuple(_SALT_VERSION)

# Other constants
DEFAULT_ROOT_TOKEN = "testsecret"

VaultPillar: typing.TypeAlias = str | Mapping[str, typing.Any]


def gen_master_opts(
    overrides: Mapping[str, typing.Any] | None = None,
    *,
    allow_override: bool | None = None,
    auth_token: str | None = None,
    auth_roleid: str | None = None,
    auth_secid: str | None = None,
    auth_mount: str | None = None,
    approle: Mapping[str, str] | None = None,
    backend: str | None = None,
    entity_metadata: Mapping[str, str] | None = None,
    expire_events: bool | None = None,
    issue: str | None = None,
    params: Mapping[str, typing.Any] | None = None,
    pillars: VaultPillar | Sequence[VaultPillar] | None = None,
    policies: str | Sequence[str] | None = None,
    policy_cache_time: int | None = None,
    url: str | None = None,
) -> dict[str, typing.Any]:
    """
    Generate master config without typing all nested dicts.
    ``approle`` should be the value of the fixture with the same name.

    Note: ``policies`` automatically ensures ``salt_minion`` is included.
    """
    vault_opts = {}
    if issue is not None:
        set_dict_key_value(vault_opts, "issue:type", issue)
    if params is not None:
        set_dict_key_value(vault_opts, f"issue:{issue or 'token'}:params", params)
    if allow_override is not None:
        set_dict_key_value(vault_opts, "issue:allow_minion_override_params", allow_override)
    if policies is not None:
        set_dict_key_value(
            vault_opts,
            "policies:assign",
            ["salt_minion"] + ([policies] if isinstance(policies, str) else list(policies or [])),
        )
    if policy_cache_time is not None:
        set_dict_key_value(vault_opts, "policies:cache_time", policy_cache_time)
    if entity_metadata is not None:
        set_dict_key_value(vault_opts, "metadata:entity", entity_metadata)
    opts = _gen_opts(
        vault_opts,
        overrides,
        approle=approle,
        auth_token=auth_token,
        auth_roleid=auth_roleid,
        auth_secid=auth_secid,
        auth_mount=auth_mount,
        backend=backend,
        expire_events=expire_events,
        url=url,
    )
    if pillars is not None:
        opts.setdefault("ext_pillar", []).extend(
            [
                {"vault": pillar}
                for pillar in ([pillars] if isinstance(pillars, (str, Mapping)) else pillars or [])
            ]
        )
    return opts


def gen_minion_opts(
    overrides: Mapping[str, typing.Any] | None = None,
    *,
    approle: Mapping[str, str] | None = None,
    auth_token: str | None = None,
    auth_roleid: str | None = None,
    auth_secid: str | None = None,
    auth_mount: str | None = None,
    backend: str | None = None,
    config_location: str | None = None,
    expire_events: bool | None = None,
    params: Mapping[str, typing.Any] | None = None,
    token_lifecycle: Mapping[str, typing.Any] | None = None,
    url: str | None = None,
    x509v2: bool = False,
) -> dict[str, typing.Any]:
    """
    Generate minion config without typing all nested dicts.
    ``approle`` should be the value of the fixture with the same name.
    """
    vault_opts = {}
    if config_location is not None:
        vault_opts["config_location"] = config_location
    if params is not None:
        vault_opts["issue_params"] = params
    if token_lifecycle is not None:
        set_dict_key_value(vault_opts, "auth:token_lifecycle", token_lifecycle)
    return _gen_opts(
        vault_opts,
        overrides,
        approle=approle,
        auth_token=auth_token,
        auth_roleid=auth_roleid,
        auth_secid=auth_secid,
        auth_mount=auth_mount,
        backend=backend,
        expire_events=expire_events,
        url=url,
        x509v2=x509v2,
    )


def _gen_opts(
    vault_opts: dict[str, typing.Any],
    overrides: Mapping[str, typing.Any] | None = None,
    *,
    approle: Mapping[str, str] | None,
    auth_token: str | None,
    auth_roleid: str | None,
    auth_secid: str | None,
    auth_mount: str | None,
    backend: str | None,
    expire_events: bool | None,
    url: str | None,
    x509v2: bool = False,
) -> dict[str, typing.Any]:
    if auth_token is not None:
        set_dict_key_value(vault_opts, "auth:token", auth_token)
    if auth_roleid is not None:
        set_dict_key_value(vault_opts, "auth:role_id", auth_roleid)
        set_dict_key_value(vault_opts, "auth:method", "approle")
    if auth_secid is not None:
        set_dict_key_value(vault_opts, "auth:secret_id", auth_secid)
    if auth_mount is not None:
        set_dict_key_value(vault_opts, "auth:approle_mount", auth_mount)
    if approle is not None:  # return value of the `approle` fixture
        auth = vault_opts.setdefault("auth", {})
        auth["method"] = "approle"
        auth["approle_mount"] = approle["mount"]
        auth["role_id"] = approle["role_id"]
        auth["secret_id"] = approle["secret_id"]
        auth["approle_name"] = approle["name"]
    if backend is not None:
        set_dict_key_value(vault_opts, "cache:backend", backend)
    if expire_events is not None:
        set_dict_key_value(vault_opts, "cache:expire_events", expire_events)
    if url is not None:
        set_dict_key_value(vault_opts, "server:url", url)

    opts = {"vault": vault_opts}
    if x509v2 and SALT_VERSION[0] < 3008:
        # Need to enable x509_v2 explicitly on Salt <3008
        opts["features"] = {"x509_v2": True}

    opts = update(opts, overrides or {})
    _validate_vault_opts(opts["vault"])
    return opts


@functools.cache
def _vault_config_schema() -> dict[str, typing.Any]:
    from saltext.vault.utils.vault import factory  # pylint: disable=import-outside-toplevel

    schema = factory.parse_config({}, validate=False)
    # Valid keys without a default value
    return update(
        schema,
        {
            "auth": {"role_id": None, "token": None},
            "config_location": None,
            "server": {"url": None},
        },
    )


# Mappings with free-form keys. Their values must be flat though.
_OPEN_PARAM_DICTS = frozenset(
    (
        ("issue", "approle", "params"),
        ("issue", "token", "params"),
        ("issue_params",),
        ("metadata", "entity"),
        ("metadata", "secret"),
    )
)


def _validate_vault_opts(vault_opts: Mapping[str, typing.Any]) -> None:
    """
    Ensure the generated ``vault`` configuration only contains valid key paths.
    Salt ignores misplaced configuration silently, causing tests to validate
    default behavior instead of the intended one.
    """

    def _validate(opts, schema, path):
        if path in _OPEN_PARAM_DICTS:
            for key, value in opts.items():
                if isinstance(value, Mapping):
                    raise ValueError(
                        f"'vault:{':'.join(path)}' takes flat parameters, "
                        f"but {key!r} is a nested mapping. Note that the generators "
                        "nest issuance `params` automatically"
                    )
            return
        for key, value in opts.items():
            if key not in schema:
                raise ValueError(
                    f"Invalid config key 'vault:{':'.join(path + (key,))}'. "
                    f"Valid keys here: {', '.join(sorted(schema))}"
                )
            if isinstance(value, Mapping):
                if not isinstance(schema[key], Mapping) and path + (key,) not in _OPEN_PARAM_DICTS:
                    raise ValueError(
                        f"Config key 'vault:{':'.join(path + (key,))}' does not take a mapping"
                    )
                _validate(value, schema[key], path + (key,))

    _validate(vault_opts, _vault_config_schema(), ())


class PatchedEnviron:
    """
    Create a patched environment
    """

    def __init__(self, **kwargs):
        self.cleanup_keys = kwargs.pop("__cleanup__", ())
        self.kwargs = kwargs
        self.original_environ: dict[str, str] | None = None

    def __enter__(self):
        self.original_environ = os.environ.copy()
        for key in self.cleanup_keys:
            os.environ.pop(key, None)
        os.environ.update(**self.kwargs)
        return self

    def __exit__(self, *args):
        os.environ.clear()
        os.environ.update(self.original_environ or {})


class WrappedMod:
    def __init__(self, cli, mod, exc=salt.exceptions.CommandExecutionError):
        self.cli = cli
        self.mod = mod
        self.exc = exc

    def __getattr__(self, key):
        def _call(*args, _expect_fail=False, **kwargs):
            ret = self.cli.run(f"{self.mod}.{key}", *args, **kwargs)
            if _expect_fail is True:
                assert ret.returncode > 0
                return ret
            if (
                self.exc is not None
                and ret.returncode > 0
                and isinstance(ret.data, str)
                and ret.data.startswith("An Exception occurred")
            ):
                raise self.exc(ret.data.split(":", maxsplit=1)[1].lstrip())
            assert ret.returncode == 0
            return ret.data

        return _call

    def __repr__(self):
        return f"{self.__class__.__name__}<{self.mod}.*>"


class WrappedState:
    def __init__(self, cli, mod):
        self.cli = cli
        self.mod = mod

    def __getattr__(self, key):
        def _call(name, *args, _expect_fail=False, **kwargs):
            ret = self.cli.run("state.single", f"{self.mod}.{key}", name=name, *args, **kwargs)
            assert (ret.returncode > 0) is _expect_fail
            return StateResult(ret.data)  # type: ignore

        return _call

    def __repr__(self):
        return f"{self.__class__.__name__}<{self.mod}.*>"


class CliFuncProxy:
    """
    Behave similarly to a loaded module in functional tests while executing via
    salt_call_cli/salt_ssh_cli instead.

    Allows to duplicate functional tests for execution modules into wrapper
    integration tests without most necessary modifications. Still consider
    reducing the test amount since wrapper integration tests are costly.

    Usage:

    .. code-block:: py

        @pytest.fixture
        def my_module(salt_ssh_cli):
            try:
                yield CliFuncProxy(salt_ssh_cli, exc=CommandExecutionError).my_module
            finally:
                # Do cleanup or something

        def test_foo(my_module):
            res = my_module.foo("foo", bar=False)
            assert res is True

        def test_foo_failure(my_module):
            with pytest.raises(CommandExecutionError, match="Meh.*"):
                my_module.foo("foo", bar=True)

        def test_foo_required_arg(my_module):
            my_module.exc = SaltInvocationError
            with pytest.raises(SaltInvocationError, match="Wut.*"):
                my_module.foo("foo")
    """

    def __init__(self, cli, exc=salt.exceptions.CommandExecutionError, states=False):
        self.cli = cli
        self.exc = exc
        self.states = states

    def __getattr__(self, attr):
        if self.states:
            return WrappedState(self.cli, attr)
        return WrappedMod(self.cli, attr, exc=self.exc)


class ExtendedLoaders(Loaders):
    """
    Provide more module types for functional tests.
    Also supports master options for runner tests.
    """

    def __init__(self, opts, loaded_base_name=None):
        self._master = opts.get("__role", "minion") == "master"
        self._beacons = self._runners = self._pillars = self._sdb = None
        self._initializing = True
        super().__init__(opts, loaded_base_name=loaded_base_name)
        self._initializing = False

    @property
    def modules(self):
        """
        The execution or runner modules loaded by the salt loader, depending on
        the passed-in opts (specifically ``opts["__role"]``).
        """
        if self._master:
            # Need to patch this to return runners because the base class calls
            # self.modules.saltutil.sync_all in __init__ and we want to be DRY.
            if self._initializing:
                return self.runners
            # We could load a MasterMinion
            raise NotImplementedError
        return super().modules

    @property
    def grains(self):
        if self._master:
            # We could load a MasterMinion
            return {"id": self.opts["id"]}
        return super().grains

    @property
    def pillar(self):
        if self._master:
            # We could load a MasterMinion
            raise NotImplementedError
        return super().pillar

    def refresh_pillar(self):
        if not self._master:
            super().refresh_pillar()

    @property
    def states(self):
        if self._master:
            # We could load a MasterMinion like the orchestrate runner
            raise NotImplementedError
        return super().states

    @property
    def beacons(self):
        """
        The beacon modules loaded by the salt loader.
        """
        if self._master:
            raise NotImplementedError

        # Do not move these deferred imports. It allows running against a Salt
        # onedir build in salt's repo checkout.
        import salt.loader  # pylint: disable=import-outside-toplevel

        if self._beacons is None:
            self._beacons = salt.loader.beacons(
                self.opts,
                functions=self.modules,
                context=self.context,
                loaded_base_name=self.loaded_base_name,
            )
        return self._beacons

    @property
    def runners(self):
        """
        The runner modules loaded by the salt loader.
        """
        if not self._master:
            raise NotImplementedError

        # Do not move these deferred imports. It allows running against a Salt
        # onedir build in salt's repo checkout.
        import salt.loader  # pylint: disable=import-outside-toplevel

        # Unlike with execution modules, do not hydrate the state runner returns (not necessary atm)
        if self._runners is None:
            self._runners = salt.loader.runner(
                self.opts,
                utils=self.utils,
                context=self.context,
                loaded_base_name=self.loaded_base_name,
            )
        return self._runners

    @property
    def pillars(self):
        """
        The pillar modules loaded by the salt loader.
        """
        # Do not move these deferred imports. It allows running against a Salt
        # onedir build in salt's repo checkout.
        import salt.pillar  # pylint: disable=import-outside-toplevel

        if self._pillars is None:
            with patch(PATCH_TARGET, self.loaded_base_name):
                self._pillars = salt.pillar.get_pillar(
                    self.opts,
                    self.grains,
                    self.opts["id"],
                    saltenv=self.opts["saltenv"],
                    pillarenv=self.opts.get("pillarenv"),
                ).ext_pillars._dict
        return self._pillars

    @property
    def sdb(self):
        """
        The sdb modules loaded by the salt loader.
        Note that functional tests can also access modules.config/runners.config
        as well as modules.sdb/runners.sdb, which should be tested primarily.
        """
        # Do not move these deferred imports. It allows running against a Salt
        # onedir build in salt's repo checkout.
        import salt.loader  # pylint: disable=import-outside-toplevel

        if self._sdb is None:
            self._sdb = salt.loader.sdb(
                self.opts,
                functions=self.modules,
                utils=self.utils,
                loaded_base_name=self.loaded_base_name,
            )
        return self._sdb

    def reload_all(self):
        """
        Reload all loaders.
        """
        for attr in ("_beacons", "_runners", "_pillars", "_sdb"):
            if (_loader := getattr(self, attr)) is not None:
                _loader.clean_modules()
                _loader.clear()
                setattr(self, attr, None)
        super().reload_all()
        if self._master:
            self.opts.pop("grains", None)
