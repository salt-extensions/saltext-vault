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
    log.debug("Running Vault cmd: %s", " ".join(cmd))
    if textinput:
        log.debug("Vault cmd stdin: %s", textinput)
    proc = subprocess.run(
        [vault_binary] + cmd,
        check=False,
        input=textinput,
        capture_output=True,
        text=True,
    )

    data = None
    if proc.returncode == 0 and "-format=json" in cmd:
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            pass

    ret = ProcessResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        cmdline=proc.args,
        data=data,
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
    return ret.data["policy"]


def vault_list_policies():
    try:
        ret = _vault_cmd(["policy", "list", "-format=json"])
    except RuntimeError as err:
        pytest.fail(f"Unable to list policies: {err}")
    return ret.data


def vault_delete_policy(policy):
    try:
        _vault_cmd(["policy", "delete", policy])
    except RuntimeError as err:
        pytest.fail(f"Unable to delete policy `{policy}`: {err}")


def vault_enable_secret_engine(name, path=None, options=None):
    if options is None:
        options = []
    elif isinstance(options, str):
        options = [options]
    elif not isinstance(options, list):
        options = list(options)
    if path is not None:
        options.append(f"-path={path}")
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


def vault_write_approle(name, mount="approle", **kwargs):
    cmd = ["write", "-f", f"auth/{mount}/role/{name}"] + [f"{k}={v}" for k, v in kwargs.items()]
    try:
        _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to write approle `{name}` at `{mount}`: {err}")


def vault_delete_approle(name, mount="approle"):
    cmd = ["delete", f"auth/{mount}/role/{name}"]
    try:
        _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to delete approle `{name}` at `{mount}`: {err}")


def vault_get_role_id(name, mount="approle"):
    cmd = ["read", "-format=json", f"auth/{mount}/role/{name}/role-id"]
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to read role-id for `{name}` at `{mount}`: {err}")
    return ret.data["data"]["role_id"]


def vault_create_secret_id(name, mount="approle"):
    cmd = ["write", "-f", "-format=json", f"auth/{mount}/role/{name}/secret-id"]
    try:
        ret = _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to create secret-id for `{name}` at `{mount}`: {err}")
    return ret.data["data"]["secret_id"]


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
    if "data" in ret.data["data"]:
        return ret.data["data"]["data"]
    return ret.data["data"]


def vault_list_secrets(path):
    ret = _vault_cmd(["kv", "list", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list secrets at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to list secrets at `{path}`: {ret.stderr or ret.stdout}")
    return ret.data


def vault_delete_secret(path, metadata=False):
    """
    Delete secret.
    Does not fail if the secret does not exist.
    Does not fail when trying to delete metadata on KV v1.
    Ensures the secret cannot be read, no need to check.
    """
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


def vault_delete(path, silent=False):
    try:
        ret = _vault_cmd(["delete", "-format=json", path])
    except RuntimeError as err:
        if silent:
            return True
        pytest.fail(f"Failed to delete path at `{path}`: {err}")
    return ret.data or True


def vault_list(path):
    ret = _vault_cmd(["list", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list path at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to list path at `{path}`: {ret.stderr or ret.stdout}")
    return ret.data


def vault_list_detailed(path):
    ret = _vault_cmd(["list", "-detailed", "-format=json", path], raw=True)
    if ret.returncode != 0:
        if ret.returncode == 2:
            return []
        log.debug("Failed to list path at `%s`:\n%s\nSTDERR: %s", path, ret, ret.stderr)
        pytest.fail(f"Failed to list path at `{path}`: {ret.stderr or ret.stdout}")
    return ret.data["data"]


def vault_read(path, default=..., raise_errors=False):
    try:
        ret = _vault_cmd(["read", "-format=json", path])
    except RuntimeError as err:
        if raise_errors:
            raise
        if default is not ...:
            return default
        pytest.fail(f"Failed to read path at `{path}`: {err}")
    return ret.data


def vault_write(path, *args, _nofail=False, **kwargs):
    cmd = (
        ["write", "-format=json"]
        + (["-f"] if not (args or kwargs) else [])
        + [path]
        + list(args)
        + ["-"]
    )
    try:
        ret = _vault_cmd(cmd, textinput=json.dumps(kwargs), raw=_nofail)
    except RuntimeError as err:
        pytest.fail(f"Failed to write to path at `{path}`: {err}")
    if _nofail:
        if ret.returncode != 0:
            return None, False
        return ret.data, True
    return ret.data or True


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


def vault_plugin_list(flt=None):
    return [
        plugin
        for plugin in vault_read("sys/plugins/catalog")["data"]["detailed"]
        if not flt or flt(plugin)
    ]


def vault_plugin_read(plugin_type, name, version=None, *, _nofail=False, **_):
    cmd = ["plugin", "info", "-format=json"]
    if version:
        cmd += [f"-version={version}"]
    cmd += [plugin_type, name]
    try:
        ret = _vault_cmd(cmd).data
    except RuntimeError as err:
        if _nofail:
            return False
        pytest.fail(f"Failed to read {plugin_type} plugin {name}: {err}")
    # Make output more similar to read endpoint for easier assertions
    ret.pop("deprecation_status", None)
    if "oci_image" in ret and not ret["oci_image"]:
        ret.pop("oci_image")
    if "runtime" in ret and not ret["runtime"]:
        ret.pop("runtime")
    return ret


def vault_plugin_register(
    plugin_type,
    name,
    *,
    sha256=None,
    command=None,
    args=None,
    env=None,
    version=None,
    oci_image=None,
    runtime=None,
    download=False,
):
    endpoint = f"sys/plugins/catalog/{plugin_type}/{name}"
    payload = {}
    if sha256 is not None:
        payload["sha256"] = sha256
    if command is not None:
        payload["command"] = command
    if args is not None:
        payload["args"] = args
    if env is not None:
        payload["env"] = env
    if version is not None:
        payload["version"] = version
    if oci_image is not None:
        payload["oci_image"] = oci_image
    if runtime is not None:
        payload["runtime"] = runtime
    if download:
        payload["download"] = download
    return vault_write(endpoint, **payload)


def vault_plugin_deregister(plugin_type, name, version=None):
    cmd = ["plugin", "deregister"]
    if version:
        cmd += [f"-version={version}"]
    cmd += [plugin_type, name]
    try:
        _vault_cmd(cmd)
    except RuntimeError as err:
        pytest.fail(f"Failed to deregister {plugin_type} plugin {name}: {err}")
    return True


def vault_plugin_pin(plugin_type, name, version):
    return vault_write(f"sys/plugins/pins/{plugin_type}/{name}", version=version)


def vault_plugin_show_pin(plugin_type, name):
    return vault_read(
        f"sys/plugins/pins/{plugin_type}/{name}", default={"data": {"version": False}}
    )["data"]["version"]


def vault_plugin_unpin(plugin_type, name):
    return vault_delete(f"sys/plugins/pins/{plugin_type}/{name}")
