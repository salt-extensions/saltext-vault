(local-configuration)=
# Local configuration

Each node needs credentials for the Vault server. By default, minions pull
their configuration and credentials from the Salt master, so only the master
itself needs to be configured with explicit credentials.

Minions can opt out of master-provided configuration by setting
{vconf}`config_location` to `local`. This guide describes how to set up
a single node – master or minion – with explicit credentials.

(local-vault-setup)=
## Vault-side setup
Statically configured credentials can either be an AppRole or a token.
Using AppRoles is generally recommended; see the section on
[static auth methods](auth-tradeoff-target) in the auth FAQ for details.

:::{include} includes/prereq-note.md
:::

### AppRole
If you chose to authenticate your node via an AppRole, follow these steps:

1. If not present yet, enable a mount of the AppRole auth backend:

   ```bash
   vault auth enable -path=approle approle
   ```
2. Create an AppRole for the node with the appropriate policies:

   ```bash
   vault write auth/approle/role/salt-master \
     token_policies=salt-master \
     secret_id_num_uses=0 \
     secret_id_ttl=720h \
     token_ttl=30m \
     token_max_ttl=0
   ```
3. Look up its RoleID and generate a SecretID:

   ```bash
   # Show RoleID
   vault read auth/approle/role/salt-master/role-id
   # Generate new SecretID
   vault write -f auth/approle/role/salt-master/secret-id
   ```

### Token
**Alternatively**, if you chose to authenticate your node via a token,
just create one with the appropriate policies:

```bash
vault token create -policy=salt-master
```

:::{note}
These examples assume you are setting up a Salt master for credential
orchestration, hence the association with a `salt-master` policy. The required
contents of this policy depend on the type of issued credentials; see the
[Token issuance](quickstart_token.md) and [AppRole issuance](quickstart_approle.md)
guides. For other nodes, substitute names and policies as appropriate.
:::

(local-node-config)=
## Node configuration
All parameters for this extension should be put under the `vault` key inside the
configuration.

Minions that should use their local configuration instead of requesting
one from the master additionally need to set {vconf}`config_location` to `local`,
regardless of the authentication method:

```{code-block} yaml
:caption: /etc/salt/minion.d/vault.conf

vault:
  config_location: local
```

### AppRole authentication
If you chose to authenticate your node via an AppRole, apply this configuration:

```{code-block} yaml
:caption: /etc/salt/{master,minion}.d/vault.conf

vault:
  auth:
    method: approle
    approle_mount: approle  # <-- mount the node authenticates at
    role_id: <your-role-id>
    secret_id: <your-secret-id>
  server:
    url: https://vault.example.org:8200
```

### Token authentication
**Alternatively**, if you chose to authenticate your node via a token, apply this configuration:

```{code-block} yaml
:caption: /etc/salt/{master,minion}.d/vault.conf

vault:
  auth:
    token: <your-auth-token>
  server:
    url: https://vault.example.org:8200
```

### Cache
For historical reasons, this extension currently defaults to not employing a persistent cache.
This is a very inefficient setup and does not work with long-lived leases, so you should
configure a persistent {vconf}`cache <cache:backend>`:

```{code-block} yaml
:caption: /etc/salt/{master,minion}.d/vault.conf

vault:
  cache:
    backend: disk  # synonyms: file, localfs
```

### Advanced credential sources
The credential values ({vconf}`token <auth:token>`, {vconf}`role_id <auth:role_id>`
and {vconf}`secret_id <auth:secret_id>`) do not need to be specified as plaintext.

They can be set to an `sdb://` URI, e.g. to avoid persisting them in the
configuration file by pulling them from environment variables:

```{code-block} yaml
:caption: /etc/salt/{master,minion}.d/vault.conf

vault:
  auth:
    method: token
    token: sdb://osenv/VAULT_TOKEN
  server:
    url: https://vault.example.org:8200

osenv:
  driver: env
```

In very specialized setups, they can furthermore be set to the complete return payload
of a [response wrapping request][], which is unwrapped on first use. The payload
must be embedded as a YAML mapping containing the `wrap_info` key, not as its
raw string representation. For wrapped `role_id`/`secret_id` values, ensure
{vconf}`auth:approle_mount` and {vconf}`auth:approle_name` match the AppRole
the response was created for, since the wrapping token's creation path is
validated against them to detect tampering.

[response wrapping request]: https://developer.hashicorp.com/vault/docs/concepts/response-wrapping

## Complete config examples
### Master
#### AppRole
```{code-block} yaml
:caption: /etc/salt/master.d/vault.conf

vault:
  auth:
    method: approle
    approle_mount: approle
    role_id: e5a7b66e-5d08-da9c-7075-71984634b882
    secret_id: 841771dc-11c9-bbc7-bcac-6a3945a69cd9

  cache:
    backend: disk

  server:
    url: https://vault.example.com:8200
```

#### Token
```{code-block} yaml
:caption: /etc/salt/master.d/vault.conf

vault:
  auth:
    token: hvs.CAESIK41QQzo5O0HNj4AZQhW_S7suut

  cache:
    backend: disk

  server:
    url: https://vault.example.com:8200
```

### Minion
#### AppRole
```{code-block} yaml
:caption: /etc/salt/minion.d/vault.conf

vault:
  config_location: local

  auth:
    method: approle
    approle_mount: approle
    role_id: e5a7b66e-5d08-da9c-7075-71984634b882
    secret_id: 841771dc-11c9-bbc7-bcac-6a3945a69cd9

  cache:
    backend: disk

  server:
    url: https://vault.example.com:8200
```

#### Token
```{code-block} yaml
:caption: /etc/salt/minion.d/vault.conf

vault:
  config_location: local

  auth:
    token: hvs.CAESIK41QQzo5O0HNj4AZQhW_S7suut

  cache:
    backend: disk

  server:
    url: https://vault.example.com:8200
```
