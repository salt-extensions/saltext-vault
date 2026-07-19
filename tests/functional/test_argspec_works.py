import pytest
import salt.payload
import salt.state
import salt.utils.args


@pytest.fixture
def sys_mod(modules):
    return modules.sys


def test_module_argspec_can_be_pickled(modules, sys_mod):
    """
    Ensure sys.argspec works for all modules.
    Specifically, this means no classes as default values.
    Context: https://github.com/saltstack/salt/issues/61084
    """
    modules._load_all()
    for func in modules._dict:
        if not func.startswith("vault"):
            continue
        result = sys_mod.argspec(func)
        assert isinstance(result, dict)
        assert isinstance(result.get(func), dict)
        salt.payload.dumps(result)


def test_state_argspec_can_be_pickled(states):
    """
    Ensure sys.state_argspec works for all states.
    """
    states._load_all()

    for func in states._dict:
        if not func.startswith("vault"):
            continue
        # Don't use sysmod.state_argspec, it re-initializes states for each call.
        result = salt.utils.args.argspec_report(states, func)
        assert isinstance(result, dict)
        assert isinstance(result.get(func), dict)
        salt.payload.dumps(result)


def test_runner_argspec_can_be_pickled(master_loaders):
    """
    Ensure sys.runner_argspec works for all runners.
    """
    master_loaders.runners._load_all()

    for func in master_loaders.runners._dict:
        if not func.startswith("vault"):
            continue
        # Don't use sysmod.runner_argspec, it re-initializes runners for each call.
        result = salt.utils.args.argspec_report(master_loaders.runners, func)
        assert isinstance(result, dict)
        assert isinstance(result.get(func), dict)
        salt.payload.dumps(result)
