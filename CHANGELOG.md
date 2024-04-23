The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## v1.0.0 (2024-04-23)


### Deprecated

- Deprecated Vault pillar configuration with `conf` parameter and `path=` prefix [#30](https://github.com/salt-extensions/saltext-vault/issues/30)


### Changed

- Changed Vault pillar module configuration [#30](https://github.com/salt-extensions/saltext-vault/issues/30)


### Fixed

- Fixed Salt master does not renew token [#10](https://github.com/salt-extensions/saltext-vault/issues/10)
- Fixed vault module fetching more than one secret in one run with single-use tokens [#11](https://github.com/salt-extensions/saltext-vault/issues/11)
- Fixed Vault verify option to work on minions when only specified in master config [#12](https://github.com/salt-extensions/saltext-vault/issues/12)
- Fixed vault command errors configured locally [#13](https://github.com/salt-extensions/saltext-vault/issues/13)
- Fixed sdb.get_or_set_hash with Vault single-use tokens [#14](https://github.com/salt-extensions/saltext-vault/issues/14)
- Fixed Vault session storage to allow unlimited use tokens [#15](https://github.com/salt-extensions/saltext-vault/issues/15)
- Fixed salt-minion 3006.0 KeyError without 'vault' config key [#22](https://github.com/salt-extensions/saltext-vault/issues/22)
- Fixed verify parameter for unwrap requests [#34](https://github.com/salt-extensions/saltext-vault/issues/34)


### Added

- Added Vault AppRole and identity issuance to minions [#16](https://github.com/salt-extensions/saltext-vault/issues/16)
- Added Vault AppRole auth mount path configuration option [#17](https://github.com/salt-extensions/saltext-vault/issues/17)
- Added distribution of Vault authentication details via response wrapping [#18](https://github.com/salt-extensions/saltext-vault/issues/18)
- Added Vault token lifecycle management [#19](https://github.com/salt-extensions/saltext-vault/issues/19)
- Added Vault lease management utility [#20](https://github.com/salt-extensions/saltext-vault/issues/20)
- Added patch option to Vault SDB driver [#21](https://github.com/salt-extensions/saltext-vault/issues/21)
- Added inline specification of trusted CA root certificate for Vault [#23](https://github.com/salt-extensions/saltext-vault/issues/23)
- Added support for dictionary keys in pattern [#26](https://github.com/salt-extensions/saltext-vault/issues/26)
