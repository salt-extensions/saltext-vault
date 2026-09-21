import json

import pytest
import salt.version
from packaging.version import Version


@pytest.fixture(scope="module", autouse=True)
def _check_host_python(salt_ssh_cli):
    """
    When testing Salt 3006.*, the host's default Python version
    needs to be <3.12, otherwise Salt just crashes with an ImportError
    regarding ``backports.ssl_match_hostname``.
    """
    if Version(salt.version.__version__) >= Version("3007"):
        return
    ret = salt_ssh_cli.run("--raw", "python3 --version")
    assert ret.returncode == 0
    assert isinstance(ret.data, dict)
    python_version = Version(ret.data["stdout"].split(" ")[1])
    if python_version >= Version("3.12"):
        pytest.skip(
            f"The host Python ({python_version}) is not supported by Salt {salt.version.__version__}"
        )


@pytest.fixture(scope="module", params=("40.0",))
def _check_cryptography(salt_ssh_cli, request):
    """
    Skip when the host Python's cryptography library is missing or older
    than ``minimum`` (version tuple). Returns the installed version.
    """
    minimum = tuple(int(x) for x in request.param.split("."))
    # Cannot use `pip.list` since it fails in the test suite as well
    # with missing `pkg_resources`.
    ret = salt_ssh_cli.run("--raw", "python3 -m pip list --format=json")
    assert ret.returncode == 0
    assert isinstance(ret.data, dict)
    res = json.loads(ret.data["stdout"])
    for pkg in res:
        if pkg["name"] == "cryptography":
            version = tuple(int(x) for x in pkg["version"].split("."))
            break
    else:
        pytest.skip("The host Python does not have cryptography")
    if version < minimum:
        pytest.skip(
            f"These modules require at least cryptography v{request.param} on the host. "
            f"Installed: {'.'.join(str(x) for x in version)}"
        )
    return version
