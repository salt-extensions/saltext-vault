(vault-setup)=
# Basic Configuration
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

:::{tab} Token
1. A Vault server (cluster).
2. Authentication credentials for the Salt master.
3. A policy allowing the Salt master access to token issuance endpoints:
   ```vaultpolicy
   # This is the required Salt master policy for issuing Tokens.

   # Issue tokens
   path "auth/token/create" {
     capabilities = ["create", "read", "update"]
   }

   # Issue tokens with token roles
   # You can substitute the glob with the role name the master is configured with
   path "auth/token/create/*" {
     capabilities = ["create", "read", "update"]
   }
   ```
4. A [Token Role][] and policies as needed. This is not strictly required, but if
   omitted, issued minion tokens will be bound to the Salt master one's and be able
   to inherit all its policies. The linked guide is for Nomad since the Vault
   documentation on this is slim.
:::

:::{tab} AppRole
1. A Vault server (cluster).
2. A separate (unused) mount of the AppRole auth backend, called `salt-minions` by default.
3. Authentication credentials for the Salt master.
4. A policy allowing the Salt master access to AppRole issuance endpoints:

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
       "mount_accessor" = ["auth_approle_0a1b2c3d"]
       "name" = []
     }
   }
   ```
5. Policies for minions as needed.
:::

[Token Role]: https://developer.hashicorp.com/nomad/docs/integrations/vault/acl#vault-token-role-configuration

## Salt master configuration

### Credential issuance
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
:::{tab} Token auth
```yaml
vault:
  auth:
    token: <your-auth-token>
  server:
    url: https://vault.example.org:8200
```
:::

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

#### Credential issuance
:::{tab} Token
It is strongly recommended to configure a [Token Role][] (but not strictly required):

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
For each request to Vault, the minion will request a new token by default.
It is generally recommended to raise the defaults:

```yaml
vault:
  issue:
    token:
      explicit_max_ttl: 30  # Tokens will be valid for 30s
      num_uses: 10          # Tokens will be limited to 10 uses
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
```

:::{note}
AppRole policies and entity metadata are generally not updated
automatically. After a change, you will need to synchronize
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
      role_name: salt_minion
      params:
        explicit_max_ttl: 30
        num_uses: 10
  policies:
    assign:
      - 'salt_minion'
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
    mount: approle         # <-- mount the salt master authenticates at
    role_id: e5a7b66e-5d08-da9c-7075-71984634b882
    secret_id: 841771dc-11c9-bbc7-bcac-6a3945a69cd9
  cache:
    backend: disk
  issue:
    type: approle
    approle:
      mount: salt-minions  # <-- mount the salt master manages
  metadata:
    entity:
      minion-id: '{minion}'
      role: '{pillar[role]}'
  server:
    url: https://vault.example.com:8200
```
:::
