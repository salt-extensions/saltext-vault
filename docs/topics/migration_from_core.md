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
## Changes versus the 3007 release
There are some planned changes not found in any version of Salt core.

### Deprecated defaults/configuration

#### SDB module
* The SDB module used to overwrite the whole secret when writing a single key.
  This behavior can be configured now with the {vconf}`patch <sdb.patch>` profile value.
  This value defaults to `false` for now, but will be changed to `true` in the next
  major release since it is usually the desired behavior and in line with other SDB modules.

#### Pillar module
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

### Deprecated functions
- [vault.policy_fetch](saltext.vault.modules.vault.policy_fetch) (use [vault_policy.fetch](saltext.vault.modules.vault_policy.fetch))
- [vault.policy_write](saltext.vault.modules.vault.policy_write) (use [vault_policy.write](saltext.vault.modules.vault_policy.write))
- [vault.policy_delete](saltext.vault.modules.vault.policy_delete) (use [vault_policy.delete](saltext.vault.modules.vault_policy.delete))
- [vault.policies_list](saltext.vault.modules.vault.policies_list) (use [vault_policy.list](saltext.vault.modules.vault_policy.list_))
- [vault.read_secret](saltext.vault.modules.vault.read_secret) (use [vault_secret.read](saltext.vault.modules.vault_secret.read))
- [vault.read_secret_meta](saltext.vault.modules.vault.read_secret_meta) (use [vault_secret.read_meta](saltext.vault.modules.vault_secret.read_meta))
- [vault.write_secret](saltext.vault.modules.vault.write_secret) (use [vault_secret.write](saltext.vault.modules.vault_secret.write))
- [vault.write_raw](saltext.vault.modules.vault.write_raw) (use [vault_secret.write_raw](saltext.vault.modules.vault_secret.write_raw))
- [vault.patch_secret](saltext.vault.modules.vault.patch_secret) (use [vault_secret.patch](saltext.vault.modules.vault_secret.patch))
- [vault.patch_raw](saltext.vault.modules.vault.patch_raw) (use [vault_secret.patch_raw](saltext.vault.modules.vault_secret.patch_raw))
- [vault.list_secrets](saltext.vault.modules.vault.list_secrets) (use [vault_secret.list](saltext.vault.modules.vault_secret.list_))
- [vault.delete_secret](saltext.vault.modules.vault.delete_secret) (use [vault_secret.delete](saltext.vault.modules.vault_secret.delete))
- [vault.restore_secret](saltext.vault.modules.vault.restore_secret) (use [vault_secret.restore](saltext.vault.modules.vault_secret.restore))
- [vault.destroy_secret](saltext.vault.modules.vault.destroy_secret) (use [vault_secret.destroy](saltext.vault.modules.vault_secret.destroy))
- [vault.wipe_secret](saltext.vault.modules.vault.wipe_secret) (use [vault_secret.wipe](saltext.vault.modules.vault_secret.wipe))

### Deprecated states
- [vault.policy_present](saltext.vault.states.vault.policy_present) (use [vault_policy.present](saltext.vault.states.vault_policy.present))
- [vault.policy_absent](saltext.vault.states.vault.policy_absent) (use [vault_policy.absent](saltext.vault.states.vault_policy.absent))
