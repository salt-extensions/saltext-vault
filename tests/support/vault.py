import json
import logging
import subprocess

import pytest
import salt.utils.files
import salt.utils.path
from pytestshellutils.utils.processes import ProcessResult

from tests.support.runtests import RUNTIME_VARS

log = logging.getLogger(__name__)


def _vault_cmd(cmd, textinput=None, raw=False):
    vault_binary = salt.utils.path.which("vault")
    proc = subprocess.run(
        [vault_binary] + cmd,
        check=False,
        input=textinput,
        capture_output=True,
        text=True,
    )

    ret = ProcessResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        cmdline=proc.args,
    )

    if raw:
        return ret
    if ret.returncode != 0:
        log.debug("Failed to run vault %s:\n%s", " ".join(cmd), ret)
        raise RuntimeError()
    return ret


def vault_write_policy(name, rules):
    try:
        _vault_cmd(["policy", "write", name, "-"], textinput=rules)
    except RuntimeError:
        pytest.fail(f"Unable to write policy `{name}`")


def vault_write_policy_file(policy, filename=None):
    if filename is None:
        filename = policy
    try:
        _vault_cmd(
            [
                "policy",
                "write",
                policy,
                f"{RUNTIME_VARS.FILES}/vault/policies/{filename}.hcl",
            ]
        )
    except RuntimeError:
        pytest.fail(f"Unable to write policy `{policy}`")


def vault_read_policy(policy):
    ret = _vault_cmd(["policy", "read", "-format=json", policy], raw=True)
    if ret.returncode != 0:
        if "No policy named" in ret.stderr:
            return None
        log.debug("Failed to read policy `%s`:\n%s", policy, ret)
        pytest.fail(f"Unable to read policy `{policy}`")
    res = json.loads(ret.stdout)
    return res["policy"]


def vault_list_policies():
    try:
        ret = _vault_cmd(["policy", "list", "-format=json"])
    except RuntimeError:
        pytest.fail("Unable to list policies")
    return json.loads(ret.stdout)


def vault_delete_policy(policy):
    try:
        _vault_cmd(["policy", "delete", policy])
    except RuntimeError:
        pytest.fail(f"Unable to delete policy `{policy}`")


def vault_enable_secret_engine(name, options=None):
    if options is None:
        options = []
    try:
        ret = _vault_cmd(["secrets", "enable"] + options + [name])
    except RuntimeError:
        pytest.fail(f"Could not enable secret engine `{name}`")

    if "path is already in use at" in ret.stdout:
        return False
    if "Success" in ret.stdout:
        return True
    log.debug("Failed to enable secret engine `%s`:\n%s", name, ret)
    pytest.fail(f"Could not enable secret engine `{name}`: {ret.stdout}")


def vault_disable_secret_engine(name):
    try:
        ret = _vault_cmd(["secrets", "disable", name])
    except RuntimeError:
        pytest.fail(f"Could not disable secret engine `{name}`")

    if "Success" in ret.stdout:
        return True
    log.debug("Failed to disable secret engine `%s`:\n%s", name, ret)
    pytest.fail(f"Could not disable secret engine `{name}`: {ret.stdout}")


def vault_enable_auth_method(name, options=None, **kwargs):
    if options is None:
        options = []
    cmd = ["auth", "enable"] + options + [name] + [f"{k}={v}" for k, v in kwargs.items()]
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError:
        pytest.fail(f"Could not enable auth method `{name}`")

    if "path is already in use at" in ret.stdout:
        return False
    if "Success" in ret.stdout:
        return True
    log.debug("Failed to enable auth method `%s`:\n%s", name, ret)
    pytest.fail(f"Could not enable auth method `{name}`: {ret.stdout}")


def vault_disable_auth_method(name):
    try:
        ret = _vault_cmd(["auth", "disable", name])
    except RuntimeError:
        pytest.fail(f"Could not disable auth method `{name}`")

    if "Success" in ret.stdout:
        return True
    log.debug("Failed to disable auth method `%s`:\n%s", name, ret)
    pytest.fail(f"Could not disable auth method `{name}`: {ret.stdout}")


def vault_write_secret(path, **kwargs):
    cmd = ["kv", "put", path] + [f"{k}={v}" for k, v in kwargs.items()]
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError:
        pytest.fail(f"Failed to write secret at `{path}`")

    if vault_read_secret(path) != kwargs:
        log.debug("Failed to write secret at `%s`:\n%s", path, ret)
        pytest.fail(f"Failed to write secret at `{path}`")
    return True


def vault_write_secret_file(path, data_name):
    data_path = f"{RUNTIME_VARS.FILES}/vault/data/{data_name}.json"
    with salt.utils.files.fopen(data_path) as f:
        data = json.load(f)
    cmd = ["kv", "put", path, f"@{data_path}"]
    try:
        ret = _vault_cmd([cmd])
    except RuntimeError:
        pytest.fail(f"Failed to write secret at `{path}`")

    if vault_read_secret(path) != data:
        log.debug("Failed to write secret at `%s`:\n%s", path, ret)
        pytest.fail(f"Failed to write secret at `{path}`")
    return True


def vault_read_secret(path):
    ret = _vault_cmd(["kv", "get", "-format=json", path], raw=True)

    if ret.returncode != 0:
        if "No value found at" in ret.stderr:
            return None
        log.debug("Failed to read secret at `%s`:\n%s", path, ret)
        pytest.fail(f"Failed to read secret at `{path}`")
    res = json.loads(ret.stdout)
    if "data" in res["data"]:
        return res["data"]["data"]
    return res["data"]


def vault_list_secrets(path):
    ret = _vault_cmd(["kv", "list", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list secrets at `%s`:\n%s", path, ret)
        pytest.fail(f"Failed to list secrets at `{path}`")
    return json.loads(ret.stdout)


def vault_delete_secret(path, metadata=False):
    try:
        ret = _vault_cmd(["kv", "delete", path])
    except RuntimeError:
        pytest.fail(f"Failed to delete secret at `{path}`")

    if vault_read_secret(path) is not None:
        log.debug("Failed to delete secret at `%s`:\n%s", path, ret)
        pytest.fail(f"Failed to delete secret at `{path}`")

    if not metadata:
        return True

    ret = _vault_cmd(["kv", "metadata", "delete", path], raw=True)
    if ret.returncode != 0 and "Metadata not supported on KV Version 1" not in ret.stderr:
        log.debug("Failed to delete secret metadata at `%s`:\n%s", path, ret)
        pytest.fail(f"Failed to delete secret metadata at `{path}`")
    return True


def vault_list(path):
    try:
        ret = _vault_cmd(["list", "-format=json", path])
    except RuntimeError:
        pytest.fail(f"Failed to list path at `{path}`")
    return json.loads(ret.stdout)
