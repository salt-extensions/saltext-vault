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
        log.debug("Failed to run vault %s:\n%s\nSTDERR: %s", " ".join(cmd), ret, ret.stderr)
        raise RuntimeError(ret.stderr or ret.stdout)
    return ret


def vault_write_policy(name, rules):
    try:
        _vault_cmd(["policy", "write", name, "-"], textinput=rules)
    except RuntimeError as err:
        pytest.fail(f"Unable to write policy `{name}`: {err}")


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
    except RuntimeError as err:
        pytest.fail(f"Unable to write policy `{policy}`: {err}")


def vault_read_policy(policy):
    ret = _vault_cmd(["policy", "read", "-format=json", policy], raw=True)
    if ret.returncode != 0:
        if "No policy named" in ret.stderr:
            return None
        log.debug("Failed to read policy `%s`:\n%s\nSTDERR: %s", policy, ret, ret.stderr)
        pytest.fail(f"Unable to read policy `{policy}`: {ret.stderr or ret.stdout}")
    res = json.loads(ret.stdout)
    return res["policy"]


def vault_list_policies():
    try:
        ret = _vault_cmd(["policy", "list", "-format=json"])
    except RuntimeError as err:
        pytest.fail(f"Unable to list policies: {err}")
    return json.loads(ret.stdout)


def vault_delete_policy(policy):
    try:
        _vault_cmd(["policy", "delete", policy])
    except RuntimeError as err:
        pytest.fail(f"Unable to delete policy `{policy}`: {err}")


def vault_enable_secret_engine(name, options=None):
    if options is None:
        options = []
    try:
        ret = _vault_cmd(["secrets", "enable"] + options + [name])
    except RuntimeError as err:
        pytest.fail(f"Could not enable secret engine `{name}`: {err}")

    if "path is already in use at" in ret.stdout:
        return False
    if "Success" in ret.stdout:
        return True
    log.debug("Failed to enable secret engine `%s`:\n%s\nSTDERR: %s", name, ret, ret.stderr)
    pytest.fail(f"Could not enable secret engine `{name}`: {ret.stderr or ret.stdout}")


def vault_disable_secret_engine(path):
    try:
        ret = _vault_cmd(["secrets", "disable", path])
    except RuntimeError as err:
        pytest.fail(f"Could not disable secret engine at `{path}`: {err}")

    if "Success" in ret.stdout:
        return True
    log.debug(
        "Failed to disable secret engine at path `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr
    )
    pytest.fail(f"Could not disable secret engine at path `{path}`: {ret.stderr or ret.stdout}")


def vault_enable_auth_method(name, options=None, **kwargs):
    if options is None:
        options = []
    cmd = ["auth", "enable"] + options + [name] + [f"{k}={v}" for k, v in kwargs.items()]
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Could not enable auth method `{name}`: {err}")

    if "path is already in use at" in ret.stdout:
        return False
    if "Success" in ret.stdout:
        return True
    log.debug("Failed to enable auth method `%s`:\n%s\nSTDERR: %s", name, ret, ret.stderr)
    pytest.fail(f"Could not enable auth method `{name}`: {ret.stderr or ret.stdout}")


def vault_disable_auth_method(name):
    try:
        ret = _vault_cmd(["auth", "disable", name])
    except RuntimeError as err:
        pytest.fail(f"Could not disable auth method `{name}`: {err}")

    if "Success" in ret.stdout:
        return True
    log.debug("Failed to disable auth method `%s`:\n%s\nSTDERR: %s", name, ret, ret.stderr)
    pytest.fail(f"Could not disable auth method `{name}`: {ret.stderr or ret.stdout}")


def vault_write_secret(path, **kwargs):
    cmd = ["kv", "put", path] + [f"{k}={v}" for k, v in kwargs.items()]
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to write secret at `{path}`: {err}")

    if vault_read_secret(path) != kwargs:
        log.debug("Failed to write secret at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to write secret at `{path}`: {ret.stderr or ret.stdout}")
    return True


def vault_write_secret_file(path, data_name):
    data_path = f"{RUNTIME_VARS.FILES}/vault/data/{data_name}.json"
    with salt.utils.files.fopen(data_path) as f:
        data = json.load(f)
    cmd = ["kv", "put", path, f"@{data_path}"]
    try:
        ret = _vault_cmd([cmd])
    except RuntimeError as err:
        pytest.fail(f"Failed to write secret at `{path}`: {err}")

    if vault_read_secret(path) != data:
        log.debug("Failed to write secret at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to write secret at `{path}`: {ret.stderr or ret.stdout}")
    return True


def vault_read_secret(path):
    ret = _vault_cmd(["kv", "get", "-format=json", path], raw=True)

    if ret.returncode != 0:
        if "No value found at" in ret.stderr:
            return None
        log.debug("Failed to read secret at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to read secret at `{path}`: {ret.stderr or ret.stdout}")
    res = json.loads(ret.stdout)
    if "data" in res["data"]:
        return res["data"]["data"]
    return res["data"]


def vault_list_secrets(path):
    ret = _vault_cmd(["kv", "list", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list secrets at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to list secrets at `{path}`: {ret.stderr or ret.stdout}")
    return json.loads(ret.stdout)


def vault_delete_secret(path, metadata=False):
    try:
        ret = _vault_cmd(["kv", "delete", path])
    except RuntimeError:
        pytest.fail(f"Failed to delete secret at `{path}`")

    if vault_read_secret(path) is not None:
        log.debug("Failed to delete secret at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to delete secret at `{path}`: {ret.stderr or ret.stdout}")

    if not metadata:
        return True

    ret = _vault_cmd(["kv", "metadata", "delete", path], raw=True)
    if ret.returncode != 0 and "Metadata not supported on KV Version 1" not in ret.stderr:
        log.debug(
            "Failed to delete secret metadata at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr
        )
        pytest.fail(f"Failed to delete secret metadata at `{path}`: {ret.stderr or ret.stdout}")
    return True


def vault_delete(path):
    try:
        ret = _vault_cmd(["delete", "-format=json", path])
    except RuntimeError as err:
        pytest.fail(f"Failed to delete path at `{path}`: {err}")
    try:
        return json.loads(ret.stdout) or True
    except json.decoder.JSONDecodeError:
        return True


def vault_list(path):
    ret = _vault_cmd(["list", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list path at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to list path at `{path}`: {ret.stderr or ret.stdout}")
    return json.loads(ret.stdout)


def vault_list_detailed(path):
    ret = _vault_cmd(["list", "-detailed", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list path at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to list path at `{path}`: {ret.stderr or ret.stdout}")
    return json.loads(ret.stdout)["data"]


def vault_read(path):
    try:
        ret = _vault_cmd(["read", "-format=json", path])
    except RuntimeError as err:
        pytest.fail(f"Failed to read path at `{path}`: {err}")
    return json.loads(ret.stdout)


def vault_write(path, *args, **kwargs):
    kwargs_ = [f"{k}={v}" for k, v in kwargs.items()]
    cmd = (
        ["write", "-format=json"]
        + (["-f"] if not (args or kwargs) else [])
        + [path]
        + list(args)
        + kwargs_
    )
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to write to path at `{path}`: {err}")
    try:
        return json.loads(ret.stdout) or True
    except json.decoder.JSONDecodeError:
        return True


def vault_revoke(lease_id, prefix=False):
    cmd = ["lease", "revoke"]
    if prefix:
        cmd += ["-prefix"]
    cmd += [lease_id]
    try:
        _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to revoke lease `{lease_id}`: {err}")
    return True
