import pytest


@pytest.fixture
def beacons(loaders):
    def _beacons(self):
        """
        The beacons loaded by the salt loader.
        We need to patch this in since it's currently not
        supported by pytest-salt-factories.
        """
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

    def _reload_all(self):
        loaders.reload_all()
        if self._beacons is not None:
            self._beacons.clean_modules()
            self._beacons.clear()
            self._beacons = None

    try:
        loaders._beacons = None
        type(loaders).beacons = property(_beacons)
        loaders.reload_all = _reload_all
        yield loaders.beacons
    finally:
        loaders.reset_state()
        delattr(loaders, "_beacons")
        delattr(type(loaders), "beacons")
