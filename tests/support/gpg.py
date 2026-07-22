"""
Test helpers for interfacing with GnuPG.
"""

import shutil
import subprocess
from pathlib import Path

import psutil
from saltfactories.utils import random_string


def gpg(modules, gpghome):  # pylint: disable=unused-argument
    return modules.gpg


def _kill_gpg_agent(root):
    gpg_connect_agent = shutil.which("gpg-connect-agent")
    if gpg_connect_agent:
        gnupghome = root / ".gnupg"
        if not gnupghome.is_dir():
            gnupghome = root
        try:
            subprocess.run(
                [gpg_connect_agent, "killagent", "/bye"],
                env={"GNUPGHOME": str(gnupghome)},
                shell=False,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            # This is likely CentOS 7 or Amazon Linux 2
            pass

    # If the above errored or was not enough, as a last resort, let's check
    # the running processes.
    for proc in psutil.process_iter():
        try:
            if "gpg-agent" in proc.name():
                for arg in proc.cmdline():
                    if str(root) in arg:
                        proc.terminate()
        except Exception:  # pylint: disable=broad-except
            pass


def gpghome(tmp_path_factory):
    root = tmp_path_factory.mktemp("gpghome")
    root.chmod(mode=0o0700)
    # just use /tmp, this test module does not run on OSes other than Linux/macOS
    syml = Path("/tmp/" + random_string("gnupg"))
    syml.symlink_to(root)  # the actual path can get too long for gpg
    try:
        yield syml
    finally:
        # Make sure we don't leave any gpg-agents running behind
        _kill_gpg_agent(root)
        syml.unlink()
        shutil.rmtree(root, ignore_errors=True)
