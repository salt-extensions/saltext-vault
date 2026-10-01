# AppRole issuance

This guide describes how to set up the Salt master to orchestrate minion
authentication by issuing [AppRoles][]. For an overview and help with
deciding on an authentication flavor, see the [Quickstart](vault-setup) guide.

[AppRoles]: https://developer.hashicorp.com/vault/docs/auth/approle

## Prerequisites

:::{include} includes/prereq-note.md
:::

A Vault server (cluster) is assumed to be available.

### Minion AppRole mount
Issued AppRoles should be managed on a separate (unused) mount of the AppRole
auth backend, called `salt-minions` by default:

```bash
vault auth enable -path=salt-minions approle
# You will need the mount accessor to replace the placeholder
# in the policy below, so look it up now:
vault read -format json sys/auth/salt-minions | jq '.data.accessor'
```

### Master policy
The Salt master needs access to the AppRole and entity management endpoints:

```vaultpolicy
# This is the required Salt master policy for issuing AppRoles.
# Note that credentials should be issued from a distinct mount,
# not the one the Salt master AppRole is configured at.
# This separate mount is called `salt-minions` by default.

# List existing AppRoles
path "auth/salt-minions/role" {
  capabilities = ["list"]
}

# Manage AppRoles
# This enables the Salt Master to create roles with arbitrary policies.
# If you need to restrict the assignable policies, issue tokens instead.
path "auth/salt-minions/role/*" {
  capabilities = ["read", "create", "update", "delete"]
}

# Lookup mount accessor
path "sys/auth/salt-minions" {
  capabilities = ["read", "sudo"]
}

# Lookup entities by alias name (role-id) and alias mount accessor
path "identity/lookup/entity" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "alias_name" = []
    # Replace `auth_approle_0a1b2c3d` with the output of the previous step
    "alias_mount_accessor" = ["auth_approle_0a1b2c3d"]
  }
}

# Manage entities with name prefix salt_minion_
path "identity/entity/name/salt_minion_*" {
  capabilities = ["read", "create", "update", "delete"]
}

# Create entity aliases – you can restrict the mount_accessor.
# This might allow privilege escalation in case the Salt master
# is compromised and the attacker knows the entity ID of an
# entity with relevant policies attached - although you might
# have other problems at that point.
path "identity/entity-alias" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "id" = []
    "canonical_id" = []
    # Replace `auth_approle_0a1b2c3d` with the output of the previous step
    "mount_accessor" = ["auth_approle_0a1b2c3d"]
    "name" = []
  }
}
```

You can write it to a file (e.g. `salt-master.hcl`) and create the policy like this:

```bash
vault policy write salt-master salt-master.hcl
```

### Master credentials
The Salt master itself needs statically configured authentication credentials,
which should be associated with the `salt-master` policy created above.
Create them as described in the [Vault-side setup](local-vault-setup) section
of the local configuration guide.

### Minion policies
Create policies for minions as needed. Examples are shown in the
[secrets setup](approle-secrets-setup) section below.

## Salt master configuration

### Authentication
Configure the master's own authentication, server connection and a persistent
cache as described in the [Node configuration](local-node-config) section
of the local configuration guide.

### Credential orchestration
To allow minions to pull configuration and credentials from the Salt master,
add this segment to the master configuration:

```{code-block} yaml
:caption: /etc/salt/master.d/peer_run.conf

peer_run:
  .*:
    - vault.get_config
    - vault.generate_secret_id
```

### Credential issuance
Reference the AppRole mount created during the prerequisites:

```{code-block} yaml
:caption: /etc/salt/master.d/vault.conf

vault:
  issue:
    type: approle
    approle:
      mount: salt-minions  # <-- mount the Salt master manages
```

### Credential validity
The validity defaults for issued credentials are sane for light use; depending
on how heavily you use Vault and whether you create dynamic leases such as database credentials,
they might have to be customized.
See {vconf}`issue:approle:params` for details.

:::{include} includes/issuance-policies.md
:::

### Entity metadata
You can customize the {vconf}`metadata <metadata:entity>` that is written to Vault
when creating [Entities][]. [Templating](#vault-templating) is supported. This metadata can then
be used in a templated Vault policy, reducing the need for boilerplate policies a lot:

```yaml
vault:
  metadata:
    entity:
      minion-id: '{minion}'
      roles: '{pillar[roles]}'
```

List values are expanded into several indexed keys (e.g. `roles__0`); see
[entity metadata templating](metadata-templating-target) for details.

This allows you to create a single policy like:

```vaultpolicy
path "salt/data/minions/{{identity.entity.metadata.minion-id}}" {
    capabilities = ["create", "read", "update", "delete", "patch"]
}

path "salt/data/roles/{{identity.entity.metadata.roles__0}}" {
    capabilities = ["read"]
}
```

[Entities]: https://developer.hashicorp.com/vault/docs/concepts/identity

:::{note}
AppRole policies and entity metadata are generally not updated
automatically. After a change, you need to synchronize
them by running [vault.sync_approles](saltext.vault.runners.vault.sync_approles)
or [vault.sync_entities](saltext.vault.runners.vault.sync_entities) respectively.
:::

### Complete example

```{code-block} yaml
:caption: /etc/salt/master.d/vault.conf

vault:
  auth:
    method: approle
    approle_mount: approle  # <-- mount the Salt master authenticates at
    role_id: e5a7b66e-5d08-da9c-7075-71984634b882
    secret_id: 841771dc-11c9-bbc7-bcac-6a3945a69cd9
  cache:
    backend: disk
  issue:
    type: approle
    approle:
      mount: salt-minions   # <-- mount the Salt master manages
  metadata:
    entity:
      minion-id: '{minion}'
      roles: '{pillar[roles]}'
  policies:
    assign:
      - salt_minion
  server:
    url: https://vault.example.com:8200
```

(approle-secrets-setup)=
:::{include} includes/secrets-setup.md
:::

When issuing AppRoles, you can take advantage of minion metadata for templated Vault policies.
This means a single policy should cover most minions and roles:

```bash
vault policy write salt_minion - <<'EOF'
path "salt/data/general/*" {
    capabilities = ["read"]
}

path "salt/data/minions/{{identity.entity.metadata.minion-id}}" {
    capabilities = ["read"]
}

path "salt/data/roles/{{identity.entity.metadata.roles__0}}" {
    capabilities = ["read"]
}

path "salt/data/roles/{{identity.entity.metadata.roles__1}}" {
    capabilities = ["read"]
}

path "salt/data/roles/{{identity.entity.metadata.roles__2}}" {
    capabilities = ["read"]
}

path "salt/data/roles/{{identity.entity.metadata.roles__3}}" {
    capabilities = ["read"]
}
EOF
```

:::{hint}
See [entity metadata templating](metadata-templating-target) for details, especially
to understand why the `roles` mapping is repeated multiple times.
:::

:::{include} includes/test-access.md
:::

If it still fails, manually sync AppRoles and entities,
clear the minion's cached data and try again:
```bash
salt-run vault.sync_approles
salt-run vault.sync_entities
salt elliott vault.clear_cache
```
