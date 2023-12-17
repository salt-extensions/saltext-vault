# Migration from Salt Core
:::{important}
The `vault` modules found in Salt >=3007 have the same core, so migration from
these versions is frictionless. There are some
[further deprecations](#3007-changes) you should be aware of though.
:::

This Salt Extension is based on a significant, but backwards-compatible
refactoring of the `vault` modules found in Salt core <3007. If you're migrating
from these older modules, there is a single necessary change to make:

## `peer_run`
This extension uses different endpoints for configuration and credential
distribution. While it provides a fallback for legacy config to keep working,
this requires unnecessary roundtrips and will be removed in some future release.

What was previously
```yaml
peer_run:
  .*:
    - vault.generate_token
```

should be changed to:
```yaml
peer_run:
  .*:
    - vault.get_config
    - vault.generate_new_token
```

## Notable changes
The [changelog](#changelog-target) for version `1.0.0` gives an overview of notable
improvements versus the previous Salt core <3007 modules.

## Changed config structure
Since there were many additions and changes, a new configuration structure
was introduced. The old one is still recognized, but deprecated.
Please take measures to migrate to the new structure at your discretion.
The compatibility layer will be removed in some future release.

### Renamed
- `auth:token_backend` --> {vconf}`cache:backend`
- `role_name` --> {vconf}`issue:token:role_name`
- `policies` --> {vconf}`policies:assign`
- `url` --> {vconf}`server:url`
- `verify` --> {vconf}`server:verify`
- `namespace` --> {vconf}`server:namespace`
- `auth:allow_minion_override` --> {vconf}`issue:allow_minion_override_params`
- `auth:ttl` -->
    * for the master parameter --> {vconf}`issue:token:params:explicit_max_ttl <issue:token:params>`
    * for the minion override --> {vconf}`issue_params:explicit_max_ttl <issue_params>`
- `auth:uses` -->
    * for the master parameter --> {vconf}`issue:token:params:num_uses <issue:token:params>`
    * for the minion override --> {vconf}`issue_params:num_uses <issue_params>`

## Deprecated functions
### Execution module
- [vault.clear_token_cache](saltext.vault.modules.vault.clear_token_cache) (use [vault.clear_cache](saltext.vault.modules.vault.clear_cache))

### Runner
- [vault.generate_token](saltext.vault.runners.vault.generate_token)

(3007-changes)=
## Deprecated defaults/configuration
There are some planned changes not found in any version of Salt core.

### Execution module
* [vault.list_secrets](saltext.vault.modules.vault.list_secrets) used to return
  a single-key dict like `{keys: [a, b]}`.
  This will be changed to returning the list only in the next major release.
  Set `keys_only=true` when calling it to migrate early and avoid warnings.

### SDB module
* The SDB module used to overwrite the whole secret when writing a single key.
  This behavior can be configured now with the {vconf}`patch <sdb.patch>` profile value.
  This value defaults to `false` for now, but will be changed to `true` in the next
  major release since it is usually the desired behavior and in line with other SDB modules.

### Pillar module
* The `vault` pillar module was previously configured in two styles:
  ```yaml
  ext_pillar:
    - vault: path=secret/salt
    - vault:
        conf: path=secret/salt2
  ```
  This has been simplified to:
  ```yaml
  ext_pillar:
    - vault: secret/salt
    - vault:
        path: secret/salt2
  ```
  Please update your configuration, the previous method will stop working
  in the next major release.
