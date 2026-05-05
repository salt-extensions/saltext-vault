import pytest
from saltfactories.utils.functional import Loaders


@pytest.fixture(scope="module")
def loaders(master_opts):  # pragma: no cover
    return Loaders(master_opts, loaded_base_name=f"{__name__}.loaded")


@pytest.fixture
def runners(loaders):
    def _runners(self):
        """
        The runners loaded by the salt loader.
        We need to patch this in since it's currently not
        supported by pytest-salt-factories.
        """
        # Do not move these deferred imports. It allows running against a Salt
        # onedir build in salt's repo checkout.
        import salt.loader  # pylint: disable=import-outside-toplevel

        if self._runners is None:
            self._runners = salt.loader.runner(
                self.opts,
                utils=self.utils,
                context=self.context,
                loaded_base_name=self.loaded_base_name,
            )
        return self._runners

    def _reload_all(self):
        loaders.reload_all()
        if self._runners is not None:
            self._runners.clean_modules()
            self._runners.clear()
            self._runners = None

    try:
        loaders._runners = None
        type(loaders).runners = property(_runners)
        loaders.reload_all = _reload_all
        yield loaders.runners
    finally:
        loaders.reset_state()
        delattr(loaders, "_runners")
        delattr(type(loaders), "runners")
