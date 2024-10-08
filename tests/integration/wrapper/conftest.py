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
