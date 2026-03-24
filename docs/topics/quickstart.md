(vault-setup)=
# Quickstart
For authenticating on a Vault server, each node needs credentials.
Currently supported authentication methods are [AppRoles][] and [tokens][].

To ease the management overhead, this extension allows the Salt master to
distribute configuration and credentials to minions on demand.
Thus, you only need to configure the master for the general case.

Issued credentials can either be tokens or AppRoles again.

:::{note}
It's generally recommended to authenticate with and distribute AppRoles because
this is more secure and allows for advanced behavior. For simplicity, this
extension currently defaults to token authentication/issuance though.

For background information, see the [auth FAQ](auth-faq-target),
specifically the sections on [static auth methods](auth-tradeoff-target) and
[credential issuance](issuance-tradeoff-target).
:::

:::{hint}
You can explicitly choose to configure each minion manually instead of relying on
the master ({vconf}`config_location`). From here on, this guide assumes you are
setting up a Salt master for credential orchestration.
:::

[AppRoles]: https://developer.hashicorp.com/vault/docs/auth/approle
[Tokens]: https://developer.hashicorp.com/vault/docs/concepts/tokens

## Security

It is highly recommended that you have a general understanding of the Vault
authentication and authorization mechanisms that you intend to use with this
extension and how this usage fits into your security model.

The following is a non-exhaustive list of points to consider:

* Using [templating](#vault-templating) with grains might allow minions to access Vault policies
  they are not supposed to since they control the content themselves. Consider using
  pillars or hard coding policies instead.
* In general, minions should never be allowed to mutate their own pillar, otherwise
  the pillar's trustworthiness degrades to the level of grains. Specifically, if you
  employ the Vault pillar module, a minion must not have write access to its pillar's
  source path.
* Using AppRole authentication allows the Salt Master to create roles with arbitrary
  policies. A compromised Salt Master can thus escalate its privileges within the
  Vault namespace. In the present, this [cannot be worked around with parameter constraints](https://github.com/hashicorp/vault/issues/8789#issuecomment-1321983227)
  in a sensible way. This may not be a problem if the Salt Master manages the Vault
  server already or if it is dedicated to Salt.

## Prerequisites

:::{important}
This list shows basic examples of how to create the necessary resources to get you
rolling quickly. It does not necessarily represent recommended practices, specifically
regarding token/SecretID validity.
:::

:::{tab} Token
1. A Vault server (cluster).
2. A [Token Role](token-role-target). This is not strictly required, but if
   omitted, issued minion tokens are bound to the Salt master's token
   validity and able to inherit all its policies.

   ```bash
   vault write auth/token/roles/salt-master \
     orphan=true \
     allowed_policies=salt_minion \
     allowed_policies_glob='salt_minion_*,salt_role_*'
   ```
3. A policy allowing the Salt master access to token issuance endpoints:
   ```vaultpolicy
   # This is the required Salt master policy for issuing Tokens.

   # Issue tokens
   path "auth/token/create" {
     capabilities = ["create", "read", "update"]
   }

   # Issue tokens with Token Roles
   # Substitute `salt-master` with the role name the master is configured with
   path "auth/token/create/salt-master" {
     capabilities = ["create", "read", "update"]
   }
   ```
   You can write it to a file (e.g. `salt-master.hcl`) and create the policy like this:
   ```bash
   vault policy write salt-master salt-master.hcl
   ```
4. Authentication credentials for the Salt master:
   ```bash
   vault auth enable -path=approle approle
   vault write auth/approle/role/salt-master \
     token_policies=salt-master \
     secret_id_num_uses=0 \
     secret_id_ttl=720h \
     token_ttl=30m \
     token_max_ttl=0
   # Show RoleID
   vault read auth/approle/role/salt-master/role-id
   # Generate new SecretID
   vault write -f auth/approle/role/salt-master/secret-id
   ```
5. Policies for minions as needed.
:::

:::{tab} AppRole
1. A Vault server (cluster).
2. A separate (unused) mount of the AppRole auth backend, called `salt-minions` by default:
   ```bash
   vault auth enable -path=salt-minions approle
   # You will need the mount accessor to replace the placeholder
   # in the policy below, so look it up now:
   vault read -format json sys/auth/salt-minions | jq '.data.accessor'
   ```
3. A policy allowing the Salt master access to AppRole issuance endpoints:

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
4. Authentication credentials for the Salt master.
   ```bash
   vault auth enable -path=approle approle
   vault write auth/approle/role/salt-master \
     token_policies=salt-master \
     secret_id_num_uses=0 \
     secret_id_ttl=720h \
     token_ttl=30m \
     token_max_ttl=0
   # Show RoleID
   vault read auth/approle/role/salt-master/role-id
   # Generate new SecretID
   vault write -f auth/approle/role/salt-master/secret-id
   ```
5. Policies for minions as needed.
:::

## Salt master configuration

### Credential orchestration
To allow minions to pull configuration and credentials from the Salt master,
add this segment to the master configuration, e.g. in `/etc/salt/master.d/peer_run.conf`:

:::{tab} Token
```yaml
peer_run:
  .*:
    - vault.get_config
    - vault.generate_new_token
```
:::

:::{tab} AppRole
```yaml
peer_run:
  .*:
    - vault.get_config
    - vault.generate_secret_id
```
:::

### Required parameters
All parameters for this extension should be put under the `vault` key inside the
configuration, e.g. in `/etc/salt/master.d/vault.conf`.

#### Master authentication
:::{tab} AppRole auth
```yaml
vault:
  auth:
    method: approle
    role_id: <your-salt-master-role-id>
    secret_id: <your-salt-master-secret-id>
  server:
    url: https://vault.example.org:8200
```
:::

:::{tab} Token auth
```yaml
vault:
  auth:
    token: <your-auth-token>
  server:
    url: https://vault.example.org:8200
```
:::

(token-role-target)=
#### Credential issuance
:::{tab} Token
By default, token issuance endpoints restrict assignment to only a subset
of the requester's policies and tie the child token's validity to the parent token.
This configuration requires the Salt master to possess all policies it assigns
to minions. Additionally, it allows minions to potentially inherit token issuance
authorizations.

To overcome these restrictions without relying on `sudo` capabilities, it is highly
recommended to configure a Token Role. This allows for specifying assignable
policies without these constraints and optionally enables the "orphaning" of child tokens,
allowing them to remain valid beyond the Salt master token's expiration.

```yaml
vault:
  issue:
    token:
      role_name: <your-token-role>
```

:::


:::{tab} AppRole
```yaml
vault:
  issue:
    type: approle
```
:::


### Common customizations
A couple of configuration values are not required, but commonly customized.

#### Cache
For historical reasons, this extension currently defaults to not employing a persistent cache.
This is a very inefficient setup and does not work with long-lived leases, so you should
configure a persistent {vconf}`cache <cache:backend>`:

```yaml
vault:
  cache:
    backend: disk  # synonyms: file, localfs
```

#### Credential validity
Depending on your usage of Vault, the validity defaults for issued credentials might have
to be customized.

:::{tab} Token
Again for historical reasons, token issuance has very inefficient defaults.
For each request to Vault, the minion requests a new token by default.
It is generally recommended to raise the defaults:

```yaml
vault:
  issue:
    token:
      explicit_max_ttl: 30  # Tokens are valid for 30s
      num_uses: 10          # Tokens are limited to 10 uses
```
:::

:::{tab} AppRole
The defaults are sane for light usage.
:::

#### Policies
Authenticated clients need associated authorizations to be useful. Policies describe the
operations a client is allowed to perform.

By default, minions receive the following named policies:
* `saltstack/minions`
* `saltstack/<minion_id>`

:::{important}
You need to create these policies yourself. Missing policies do not cause errors, but minions
are left with the default permissions only if none of the assigned policies exist.
:::

You can customize which policies are assigned to minions. They can be [templated](#vault-templating).

```yaml
vault:
  policies:
    assign:
      - salt_minion
      - salt_minion_{minion}
      - salt_role_{pillar[roles]}
      # While it's theoretically possible to use {grains[roles]} here
      # for backwards-compatibility reasons, it's HIGHLY discouraged.
      # The minion reports grains itself, so a compromised minion would
      # be able to assign arbitrary roles to itself.
```

:::{note}
AppRole policies and entity metadata are generally not updated
automatically. After a change, you need to synchronize
them by running [vault.sync_approles](saltext.vault.runners.vault.sync_approles)
or [vault.sync_entities](saltext.vault.runners.vault.sync_entities) respectively.
:::

#### Entity metadata
You can customize the {vconf}`metadata <metadata:entity>` that is written to Vault
when creating [Entities][]. [Templating](#templating) is supported. This metadata can then
be used in a templated Vault policy, reducing the need for boilerplate policies a lot:

```yaml
vault:
  metadata:
    entity:
      minion-id: '{minion}'
      role: '{pillar[role]}'
```

This allows you to create a single policy like:

```vaultpolicy
  path "salt/data/minions/{{identity.entity.metadata.minion-id}}" {
      capabilities = ["create", "read", "write", "delete", "patch"]
  }

  path "salt/data/roles/{{identity.entity.metadata.role}}" {
      capabilities = ["read"]
  }
```

:::{important}
Entities are only created when issuing AppRoles, not tokens.
:::

[Entities]: https://developer.hashicorp.com/vault/docs/concepts/identity

(example-config-target)=
### Complete examples
:::{tab} Token

```yaml
vault:
  auth:
    # This master authenticates with an AppRole, but
    # issues tokens
    method: approle
    role_id: e5a7b66e-5d08-da9c-7075-71984634b882
    secret_id: 841771dc-11c9-bbc7-bcac-6a3945a69cd9
  cache:
    backend: disk
  issue:
    type: token
    token:
      role_name: salt-master
      params:
        explicit_max_ttl: 30
        num_uses: 10
  policies:
    assign:
      - 'salt_minion'
      - 'salt_minion_{minion}'
      - 'salt_role_{pillar[roles]}'
  server:
    url: https://vault.example.com:8200
```
:::

:::{tab} AppRole

```yaml
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
:::

## Secrets setup

Decide how you want to map minions to authorizations. A common pattern is to create policies
based on minion IDs and minion roles, as shown in the [example config](example-config-target) above.
This example setup is continued here.

### Mount the KV backend
Mount the Key/Value v2 backend to a path, e.g. ``salt``:

```bash
vault secrets enable -path=salt -version=2 kv
```

### Create secrets
Write a secret that is accessible to all minions:

```bash
vault kv put -mount=salt general/accessible_for_all_minions all_foo=bar
```

Write a secret that is accessible to any minion that has the ``db`` role:

```bash
vault kv put -mount=salt roles/db db_foo=baz
```

Write a secret that is accessible to a specific minion named ``elliott``:

```bash
vault kv put -mount=salt minions/elliott minion_foo=quux
```

### Create policies
Create the policies that map necessary authorizations. The optimal setup
depends on the {vconf}`issued credential type<issue:type>`

:::{warning}
If a secret path is used as a minion pillar, the minion **must not have
write access**, otherwise a core security assumption in Salt is violated.
:::

:::{important}
Even if you only intend to use the secrets for minion pillars, you need
to create minion policies. The master uses these policies to decide
whether a minion should receive a specific pillar. The master should not
have access to secret paths itself. For details, see [Pillar impersonation](pillar-impersonation-target).
:::

:::{tab} Token
When issuing tokens, you cannot take advantage of minion metadata for templated Vault policies.
You need to create all policies explicitly (consider automating this):

```bash
vault policy write salt_minion - <<'EOF'
path "salt/data/general/*" {
  capabilities = ["read"]
}
EOF

vault policy write salt_role_db - <<'EOF'
path "salt/data/roles/db" {
  capabilities = ["read"]
}
EOF
# + other roles as needed

vault policy write salt_minion_elliott - <<'EOF'
path "salt/data/minions/elliott" {
  capabilities = ["read"]
}
EOF
# + other minions as needed
```
:::

:::{tab} AppRole
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

::::{hint}
See [entity metadata templating](metadata-templating-target) for details, especially
to understand why the ``roles`` mapping is repeated multiple times.
::::

### Test access

Now you can test that the minion is able to read all secrets:

```console
[root@master ~]# salt elliott vault.read_secret salt/general/accessible_for_all_minions
elliott:
    ----------
    all_foo: bar
[root@master ~]# salt elliott vault.read_secret salt/roles/db
elliott:
    ----------
    db_foo: baz
[root@master ~]# salt elliott vault.read_secret salt/minions/elliott
elliott:
    ----------
    minion_foo: quux
```

If this fails, re-issue the minion's token and try again:
```bash
salt elliott vault.clear_cache
```

If it still fails and you are issuing AppRoles, manually sync AppRoles and Entities,
re-issue the minion's SecretID and try again:
```bash
salt-run vault.sync_approles
salt-run vault.sync_entities
salt elliott vault.clear_cache
```

Lastly, verify that minions without authorization to access these can't.
