The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## 1.9.0 (2026-08-16)


### Changed

- Somewhat breaking change: Renamed `type` => `key_type` and `key_type` => `key_algo` parameters in `vault_pki.generate_root`. If you used to pass both by keyword, you need to migrate to the new names (the previous names still work). If you passed one positionally and the other by keyword, this upgrade will break that call.


### Fixed

- Fixed `vault_pki.read_issuer` reading missing default issuer raising an exception instead of returning `None`
- Fixed running `vault_pki.certificate_managed` when another state run is queued


### Added

- Added `leaf_not_after_behavior` and `revocation_signature_algorithm` parameters to `vault_pki.update_issuer`
- Added `list_keys`, `generate_key`, `get_key_id`, `generate_intermediate_csr`, `import_issuer_intermediate`, `import_issuer` and `write_urls` functions to `vault_pki` for the respective API methods. Also added `generate_intermediate`, which relies on the `x509_v2` modules to automatically sign an intermediate CA certificate for use by Vault.
- Added `name`, `aia_url_templating` and `delta_crl_endpoints` parameters to `vault_pki.update_issuer`
- Added `vault_pki.intermediate_issuer_present` state that manages an intermediate issuer as the default issuer on a mount. It signs the public key using the `x509_v2` modules.
- Added `vault_pki.root_issuer_present` state that manages a root issuer as the default issuer on a mount
- Added certificate revocation with private key. Access to this endpoint requires a lot less trust.

## 1.8.0 (2026-08-09)


### Changed

- Made `destroy` and `wipe` operations proxy to `delete` on KV v1 secrets instead of refusing with an exception


### Fixed

- Fixed `vault_pki.certificate_managed` not detecting changes to requested `alt_names` [#127](https://github.com/salt-extensions/saltext-vault/issues/127)
- Fixed KV lookup failures in very specific situations when a KV v1 mount has the full name of a KV v2 mount as a prefix
- Fixed KVv2 paths whose root key started with KVv2 prefixes such as `data` (example: `secret_mount/database`) from being mishandled and leading to permission denied/not found errors
- Fixed LeaseStore.get not flushing already expired leases from cache when called without `revoke` argument
- Fixed `sdb.get`/`sdb.set` raising an unhandled `ValueError` instead of a usage error when the SDB URI did not contain a path/key separator
- Fixed `sdb.set` with SDB module and single-use tokens issued by the master when the `patch` option was enabled in the profile
- Fixed `sdb.set` with the `patch` option enabled unexpectedly overwriting the complete secret when its data could not be read (e.g. write-only policies or exhausted token uses)
- Fixed `vault.auth_info` runner crashing when AppRole is configured with `bind_secret_id: false`
- Fixed `vault.clear_cache` runner not clearing cached AppRole metadata/rendered policies when `cache:backend` is `session` and not revoking impersonated minion tokens
- Fixed `vault_db.connection_present` failing and rewriting the connection on every run for plugins with secret parameters other than `password`, e.g. `private_key` for `mongodb_atlas`
- Fixed `vault_db.connection_present` mishandling `root_rotation_statements` passed as a string
- Fixed `vault_db.connection_present` raising an uncaught exception instead of failing cleanly when required plugin parameters were missing
- Fixed `vault_db.creds_cached` crashing or misdetecting the need for renewal when the cached lease's `min_ttl` and the requested `valid_for` were specified as a mix of time strings and integers
- Fixed `vault_db.creds_cached` resetting cached lease attributes (`renew_increment`, `revoke_delay`, `meta`) that were not specified in the state call when applying other changes
- Fixed `vault_db.creds_cached`/`creds_uncached` raising uncaught exceptions instead of reporting failures via the state result
- Fixed `vault_lease` beacon configuration validation raising an exception instead of reporting a validation failure when lease cache keys were not strings
- Fixed `vault_pki.certificate_managed` crashing instead of failing cleanly when the issuer reference did not exist
- Fixed `vault_pki.certificate_managed` crashing on subsequent runs when `encoding` was set to `der`
- Fixed `vault_pki.certificate_managed` with `append_ca_chain` never converging for binary encodings. The chain is now included for `pkcs7_der`, while the impossible combination with `der` fails early
- Fixed `vault_pki.issue_certificate`/`sign_certificate` corrupting SANs when `alt_names` is passed as a mapping
- Fixed `vault_pki.list_certificates`/`list_revoked_certificates` raising an exception instead of returning an empty list when no (revoked) certificates are present
- Fixed `vault_pki.role_managed` rewriting the role on every run when list-type (e.g. `allowed_domains`) or duration (`not_before_duration`, not `ttl`/`max_ttl`) parameters were specified as strings
- Fixed `vault_secret.present` crashing when replacing an existing scalar value with a mapping in the default patch mode
- Fixed `vault_secret.present` failing or silently dropping secret keys named like function parameters (e.g. `path`) or prefixed with double underscores
- Fixed `vault_ssh.ca_present/absent` failing to work as expected when the authenticated read CA config path was denied
- Fixed `vault_ssh.get_signing_policy` reporting a phantom empty principal/extension when `allowed_users`, `allowed_domains` or `allowed_extensions` are unset on the role
- Fixed `vault_ssh.list_roles_ip` returning None instead of an empty list when no role matches IP on recent Vault releases
- Fixed `vault_ssh.role_present_ca` never converging when `allowed_user_key_lengths` values were specified as comma-separated strings
- Fixed authenticated unwrap requests not deducting a token use
- Fixed cache handling of static DB role credentials
- Fixed cached accessor information being lost when token/SecretID information was refreshed
- Fixed clearing session cache not invalidating active client in context, which could reintroduce stale data into permanent cache or cause unexpected permission issues during long-running contexts
- Fixed crash during loading of `vault_pki` modules when `cryptography` was not available. This should not happen in most cases since it's a requirement of this extension and a Salt core requirement, but might happen when this extension is forwarded to the target host via Salt-SSH.
- Fixed handling of `all_principals` in `vault_ssh` `ssh_pki` backend
- Fixed handling of multiple values in `default_user` in `vault_ssh` `ssh_pki` backend
- Fixed raw KeyError when `cert_type` was not passed and not inferrable from a role definition in the `vault_ssh` `ssh_pki` backend
- Fixed remaining token ttl being corrupted by the templated policy rendering logic released in 1.7.0 (only used in `vault_ssh` backend for `ssh_pki.certificate_managed`)
- Fixed several execution module functions (`vault.clear_cache`/`clear_token_cache`/`update_config`, `vault_pki.read_issuer`, `vault_ssh.list_roles_ip`) leaking Vault exceptions instead of raising `CommandExecutionError`
- Fixed the `vault_lease` beacon crashing when `min_ttl` was explicitly set to `null` in the beacon configuration
- Fixed the `vault_lease` beacon firing duplicate lease expiry events on the Salt event bus when `cache:expire_events` was enabled
- Fixed the `vault_lease` beacon reporting stale lease information in expiry events when a renewal attempt did not manage to extend the lease to `min_ttl`
- Fixed the client unexpectedly raising ValueErrors when an error return was not valid JSON
- Improved error and implemented a workaround when trying to set otherNames while simultaneously passing a private key to `vault_pki.sign_certificate`


### Added

- Added the ability to override `server:url` in the minion config. The new value must be in a list of allowed values specified in the master configuration in `server:url_alts` to take effect. [#156](https://github.com/salt-extensions/saltext-vault/issues/156)
- Added `vault.patch_raw` to patch secret data that cannot be passed as keyword arguments
- Added `vault_approle` execution, state and wrapper modules to manage and utilize the AppRole auth backend
- Added `vault_gpg` execution, state and wrapper modules to interface with the custom plugin [LeSuisse/vault-gpg-plugin](https://github.com/LeSuisse/vault-gpg-plugin/). It's now possible to generate, manage, import and export GPG keys and sign, decrypt and verify data.
- Added `vault_plugin` execution, state and wrapper modules to manage plugins and pinned versions
- Added expected creation path verification for wrapped secrets embedded in the `vault.get_config` response (token and role_id), derived from the fresh config itself
- Added support for `allow_commas_in_identity_templates` for SSH secret backend roles in OpenBao
- Added support for rendering of identity templates in `allowed_users`, `allowed_domains` and `default_user` in `vault_ssh` `ssh_pki` backend

## 1.7.0 (2026-07-08)


### Fixed

- Fixed SDB patch fallback when PATCH requests are not allowed
- Fixed `vault_db.creds_uncached` clearing cached credentials with custom cache key when cache key was not specified
- Fixed `vault_db.static_role_present` management of `rotation_statements`, which was not passed to Vault, but the failure was alerted about
- Fixed `vault_pki.certificate_managed` deleting symlinks in test mode when `follow_symlinks` is explicitly set to `false`
- Fixed an existing DB connection's explicit `plugin_version` being reset when it was not specified in a call to `vault_db.write_connection`
- Fixed autodetermination of unspecified `cert_type` in `ssh_pki` backend functionality
- Fixed clearing cache when `vault:cache:backend` overrides Salt's `cache`
- Fixed exception in `read_issuer_crl` when issuer is missing - now returns `None`, as intended
- Fixed merging of `default_critical_options` and `default_extensions` with overrides in `ssh_pki` backend
- Fixed passing multiple entries of the same SAN type in `vault_pki.(issue|sign)_certificate`
- Fixed reported failure in `vault_ssh.role_present_otp` when `port` was not set. The state application still worked.
- Fixed reporting of multiple subject element changes in `vault_pki.certificate_managed`
- Fixed revocation delay of leases with `renew_increment` set
- Fixed the pillar module's `merge_lists` being ignored when it was set to `false` and Salt's `pillar_merge_lists` was enabled
- Synchronized event format for `vault/lease/*/expire` between sources to `ttl` - `ttl` and `ttl_left` were both used before, depending on the source of the event


### Added

- Added `read_certificate_full` execution function to the `vault_pki` module, returning the certificate, its CA chain and miscellaneous information as a dictionary. [#145](https://github.com/salt-extensions/saltext-vault/issues/145)
- Added support for rendering identity templates in the `ssh_pki` backend, which fixes idempotency when `default_extensions_template` is enabled. This functionality requires an adjusted policy

## 1.6.0 (2026-05-20)


### Fixed

- Fixed SSH wrappers in 3008.x [#149](https://github.com/salt-extensions/saltext-vault/issues/149)
- Fixed issued AppRoles unnecessarily being rewritten when config or SecretID were requested by minions and a TTL configuration was set as a time string [#151](https://github.com/salt-extensions/saltext-vault/issues/151)


### Added

- Added compatibility for `vault_ssh` to be used as the `backend` for the new `ssh_pki.certificate_managed` state introduced in Salt 3008, making stateful SSH certificate management using Vault-issued certificates possible on Salt 3008+ [#138](https://github.com/salt-extensions/saltext-vault/issues/138)

## 1.5.0 (2026-03-09)


### Fixed

- Fixed `vault_ssh.ca_(present|absent)` in OpenBao


### Added

- Added official OpenBao support [#139](https://github.com/salt-extensions/saltext-vault/issues/139)

## 1.4.0 (2026-02-15)


### Changed

- Marked some API methods using `POST`/`PATCH` requests as safe to retry by default since they are effectively idempotent [#97](https://github.com/salt-extensions/saltext-vault/issues/97)


### Fixed

- Fixed handling of `retry_after_max` with urllib3 2.6.3, which introduced the same parameter and set its default to 6h. When `retry_after_max` is explicitly set to `None`, we default to 6h from now on too, otherwise the previous default of 60s applies. [#130](https://github.com/salt-extensions/saltext-vault/issues/130)
- Fixed SDB URI resolution in `auth:token` to make documented token-from-env behavior work [#133](https://github.com/salt-extensions/saltext-vault/issues/133)
- Fixed Vault client token lookups using an accessor. These lookups used the wrong API method (`GET` instead of `POST`)


### Added

- Added the ability to disallow non-impersonated authentication requests via `issue:block_minion_requests`, effectively limiting authentication credential issuance to the master only [#109](https://github.com/salt-extensions/saltext-vault/issues/109)
- Added SDB URI resolution for `auth:role_id` and `auth:secret_id` to achieve feature parity between auth methods [#134](https://github.com/salt-extensions/saltext-vault/issues/134)

## 1.3.2 (2025-05-04)


### Fixed

- Fixed vault_pki.certificate_managed always recreating certificate with `append_ca_chain=True` [#123](https://github.com/salt-extensions/saltext-vault/issues/123)

## 1.3.1 (2025-03-24)


### Fixed

- Fixed running `vault.sync_approles` on a fresh, empty mount [#111](https://github.com/salt-extensions/saltext-vault/issues/111)

## 1.3.0 (2024-12-09)


### Fixed

- Fixed a crash when a templated field accesses an out-of-bounds list index


### Added

- When metadata that is written to Vault is templated using a list or dict, in addition to concatenating the values into a sorted comma-separated list, the master now additionally creates a separate suffixed key for each individual item [#106](https://github.com/salt-extensions/saltext-vault/issues/106)


## 1.2.2 (2024-11-10)


### Fixed

- Fixed compatibility with master cluster mode [#99](https://github.com/salt-extensions/saltext-vault/issues/99)


## 1.2.1 (2024-11-07)


### Fixed

- Fixed the client used for unwrapping authentication credentials not respecting `client` configuration when no cached configuration is available [#95](https://github.com/salt-extensions/saltext-vault/issues/95)


## v1.2.0 (2024-10-02)


### Changed

- Readded direct package dependency on cryptography


### Fixed

- Change unseal query to be always unauthenticated. [#85](https://github.com/salt-extensions/saltext-vault/issues/85)


### Added

- Added support for credential orchestration in Salt-SSH wrappers, added wrappers for vault, vault_db, vault_pki modules [#54](https://github.com/salt-extensions/saltext-vault/issues/54)
- Added `vault_ssh` execution, state and wrapper modules for managing and using the SSH secret backend [#58](https://github.com/salt-extensions/saltext-vault/issues/58)
- Improved handling of KV v2 secret versions [#61](https://github.com/salt-extensions/saltext-vault/issues/61)
- Added `vault_secret` state module for statefully managing secrets [#62](https://github.com/salt-extensions/saltext-vault/issues/62)


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
