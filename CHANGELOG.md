The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## v1.1.1 (2024-07-24)


### Changed

- Required x509_v2 modules to be available for specific parameters to `vault_pki`, dropped direct dependency on cryptography [#78](https://github.com/salt-extensions/saltext-vault/issues/78)


### Fixed

- Fixed vault.update_config crash [#77](https://github.com/salt-extensions/saltext-vault/issues/77)


## v1.1.0 (2024-07-23)


### Removed

- Dropped support for Python 3.7 [#59](https://github.com/salt-extensions/saltext-vault/issues/59)
- Dropped support for Salt 3005 [#70](https://github.com/salt-extensions/saltext-vault/issues/70)


### Fixed

- Fixed a crash when renewing/revoking leases that have been revoked on the Vault server early [#45](https://github.com/salt-extensions/saltext-vault/issues/45)


### Added

- Added an optional switch for validating cached leases with the Vault server before returning them from the LeaseStore [#46](https://github.com/salt-extensions/saltext-vault/issues/46)
- Implemented setting per-lease defaults of lifecycle parameters [#47](https://github.com/salt-extensions/saltext-vault/issues/47)
- Implemented caching arbitrary metadata together with a lease and included it in expiry events [#48](https://github.com/salt-extensions/saltext-vault/issues/48)
- Added a LeaseStore method for listing cached lease information [#49](https://github.com/salt-extensions/saltext-vault/issues/49)
- Added `vault_db` modules for management and usage of the Vault database secret backend [#52](https://github.com/salt-extensions/saltext-vault/issues/52)
- Added `vault_lease` beacon module to monitor and renew cached leases [#53](https://github.com/salt-extensions/saltext-vault/issues/53)
- Added vault_pki modules for interfacing with the PKI backend and managing X.509 certificates [#58](https://github.com/salt-extensions/saltext-vault/issues/58)
- Added support for retry logic and specific connection settings in `vault:client` [#65](https://github.com/salt-extensions/saltext-vault/issues/65)


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
