import os
import tempfile
from pathlib import Path
from shutil import rmtree

from . import prompt
from .cmd import CommandNotFound
from .cmd import local
from .copier import discover_project_name
from .copier import discover_venv_python

# Fallback when the `venv_python` answer is unavailable.
# Should follow the version used for relenv packages, see
# https://github.com/saltstack/salt/blob/master/cicd/shared-gh-workflows-context.yml
RECOMMENDED_PYVER = "3.14"
# For discovery of existing virtual environment, descending priority.
VENV_DIRS = (
    ".venv",
    "venv",
    ".env",
    "env",
)


def discover_uv():
    try:
        return local["uv"]
    except CommandNotFound:
        pass


def system_site_packages_requested():
    """
    Whether the development venv should inherit system-wide packages,
    e.g. for OS-specific extensions whose dependencies are only
    available as system packages.
    """
    return os.environ.get("VENV_SYSTEM_SITE_PACKAGES", "0") == "1"


def is_venv(path):
    if (venv_path := Path(path)).is_dir() and (venv_path / "pyvenv.cfg").exists():
        return venv_path
    return False


def discover_venv(project_root="."):
    base = Path(project_root).resolve()
    for name in VENV_DIRS:
        if found := is_venv(base / name):
            return found
    raise RuntimeError(f"No venv found in {base}")


def venv_pyver(venv):
    for line in (venv / "pyvenv.cfg").read_text().splitlines():
        if line.startswith("version =") or line.startswith("version_info ="):
            pyver = line.split(" = ")[1].split(".")
            return f"{pyver[0]}.{pyver[1]}"


def venv_system_site_packages(venv):
    for line in (venv / "pyvenv.cfg").read_text().splitlines():
        if line.startswith("include-system-site-packages"):
            return line.split("=")[1].strip().lower() == "true"
    return False


def get_venv_pyver():
    """
    Return the Python version the project venv should use,
    as configured in the answers file (`venv_python`).
    """
    try:
        return discover_venv_python() or RECOMMENDED_PYVER
    except RuntimeError:
        return RECOMMENDED_PYVER


def create_venv(project_root=".", directory=None, pyver=None, system_site_packages=None):
    if system_site_packages is None:
        system_site_packages = system_site_packages_requested()
    pyver = pyver or get_venv_pyver()
    base = Path(project_root).resolve()
    venv = (base / (directory or VENV_DIRS[0])).resolve()
    if is_venv(venv):
        raise RuntimeError(f"Venv at {venv} already exists")
    prompt.status(f"Creating virtual environment at {venv}")
    # When inheriting system-wide packages, the venv must be based on the
    # system Python (uv-managed interpreters don't carry system packages).
    uv = None if system_site_packages else discover_uv()
    if uv is not None:
        prompt.status("Found `uv`. Creating venv")
        uv(
            "venv",
            # Install pip/setuptools/wheel for compatibility
            "--seed",
            "--python",
            pyver,
            f"--prompt=saltext-{discover_project_name()}",
            directory or VENV_DIRS[0],
        )
    else:
        if system_site_packages:
            prompt.status("System-site-packages venv requested. Using `venv`")
        else:
            prompt.status("Did not find `uv`. Falling back to `venv`")
        venv_params = ["--system-site-packages"] if system_site_packages else []
        try:
            python = local[f"python{pyver}"]
        except CommandNotFound as err:
            try:
                python = local["python3"]
            except CommandNotFound:
                python = local["python"]  # Windows needs this without uv
            version = python("--version").split(" ")[1]
            if not version.startswith(pyver):
                raise RuntimeError(
                    f"No `python{pyver}` executable found in $PATH, exiting"
                ) from err
        python(
            "-m",
            "venv",
            directory or VENV_DIRS[0],
            f"--prompt=saltext-{discover_project_name()}",
            *venv_params,
        )
    return venv


def ensure_project_venv(project_root=".", reinstall=True, install_extras=False, pyver=None):
    """
    Ensure the project venv exists and uses the configured Python version.

    ``reinstall`` semantics:
      * ``True``: always (re)install the project into the venv
      * ``"auto"``: only install if the venv was freshly created
      * ``False``: never install, just ensure the venv exists
    """
    exists = False
    pyver = pyver or get_venv_pyver()
    system_site_packages = system_site_packages_requested()
    try:
        venv = discover_venv(project_root)
        prompt.status(f"Found existing virtual environment at {venv}")

        existing_pyver = venv_pyver(venv)
        if existing_pyver != pyver:
            prompt.status(
                f"Existing venv has Python {existing_pyver}, but configured is {pyver}. Recreating."
            )
            rmtree(venv)
            raise RuntimeError("Existing venv does not use configured Python version")

        if venv_system_site_packages(venv) != system_site_packages:
            if system_site_packages:
                msg = (
                    "Existing venv does not inherit system site packages, "
                    "but $VENV_SYSTEM_SITE_PACKAGES is set. Recreating."
                )
            else:
                msg = (
                    "Existing venv inherits system site packages, "
                    "but $VENV_SYSTEM_SITE_PACKAGES is unset. Recreating."
                )
            prompt.status(msg)
            rmtree(venv)
            raise RuntimeError("Existing venv does not match system site packages request")

        exists = True
    except RuntimeError:
        venv = create_venv(project_root, pyver=pyver, system_site_packages=system_site_packages)
    if reinstall == "auto":
        reinstall = not exists
    if not reinstall:
        return venv
    extras = ["dev", "tests", "docs"]
    if install_extras:
        extras.append("dev_extra")
    prompt.status(("Reinstalling" if exists else "Installing") + " project and dependencies")
    with local.venv(venv):
        # uv pip install does not consider packages inherited via
        # --system-site-packages (astral-sh/uv#4466), so avoid it for such venvs.
        uv = None
        if not system_site_packages:
            uv = discover_uv()
            if uv is None:
                try:
                    # We install uv into the virtualenv, so it might be available now.
                    # It speeds up this step a lot.
                    uv = local["uv"]
                except CommandNotFound:
                    pass
        if uv is not None:
            uv("pip", "install", "-e", f".[{','.join(extras)}]")
        else:
            # Salt does not build correctly with setuptools >= 75.6.0.
            # uv reads this constraint from pyproject.toml, but pip needs this workaround.
            with tempfile.NamedTemporaryFile(delete=False) as constraints_file:
                setuptools_constraint = "setuptools<75.6.0"
                constraints_file.write(setuptools_constraint.encode())
            try:
                with local.env(PIP_CONSTRAINT=constraints_file.name):
                    local["python"]("-m", "pip", "install", "-e", f".[{','.join(extras)}]")
            finally:
                Path(constraints_file.name).unlink()
        if not exists or not (Path(project_root) / ".git" / "hooks" / "pre-commit").exists():
            prompt.status("Installing pre-commit hooks")
            local["python"]("-m", "pre_commit", "install", "--install-hooks")
    return venv
