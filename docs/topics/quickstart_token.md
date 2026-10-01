# Token issuance

This guide describes how to set up the Salt master to orchestrate minion
authentication by issuing Vault [tokens][]. For an overview and help with
deciding on an authentication flavor, see the [Quickstart](vault-setup) guide.

[Tokens]: https://developer.hashicorp.com/vault/docs/concepts/tokens

## Prerequisites

:::{include} includes/prereq-note.md
:::

A Vault server (cluster) is assumed to be available.

(token-role-target)=
### Token Role
By default, token issuance endpoints restrict assignment to only a subset
of the requester's policies and tie the child token's validity to the parent token.
This configuration requires the Salt master to possess all policies it assigns
to minions. Additionally, it allows minions to potentially inherit token issuance
authorizations.

To overcome these restrictions without relying on `sudo` capabilities, it is highly
recommended to configure a Token Role. This allows for specifying assignable
policies without these constraints and optionally enables the "orphaning" of child tokens,
allowing them to remain valid beyond the Salt master token's expiration.

```bash
vault write auth/token/roles/salt-master \
  orphan=true \
  allowed_policies=salt_minion \
  allowed_policies_glob='salt_minion_*,salt_role_*'  # Note: the (legacy) default policies need saltstack/*
```

### Master policy
The Salt master needs access to the token issuance endpoints:

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

### Master credentials
The Salt master itself needs statically configured authentication credentials,
which should be associated with the `salt-master` policy created above.
Create them as described in the [Vault-side setup](local-vault-setup) section
of the local configuration guide.

### Minion policies
Create policies for minions as needed. Examples are shown in the
[secrets setup](token-secrets-setup) section below.

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
    - vault.generate_new_token
```

### Credential issuance
Reference the [Token Role](token-role-target) created during the prerequisites:

```{code-block} yaml
:caption: /etc/salt/master.d/vault.conf

vault:
  issue:
    type: token  # this is the default
    token:
      role_name: salt-master
```

### Credential validity
For historical reasons, token issuance has very inefficient defaults.
For each request to Vault, the minion requests a new token unless configured
otherwise. It is generally recommended to raise the defaults:

```yaml
vault:
  issue:
    token:
      params:
        explicit_max_ttl: 30  # Tokens are valid for 30s
        num_uses: 10          # Tokens are limited to 10 uses
```

Depending on how heavily you use Vault and whether you create dynamic leases
such as database credentials, these parameters might have to be customized further.
See {vconf}`issue:token:params` for details.

:::{include} includes/issuance-policies.md
:::

(example-config-target)=
### Complete example

```{code-block} yaml
:caption: /etc/salt/master.d/vault.conf

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

(token-secrets-setup)=
:::{include} includes/secrets-setup.md
:::

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

:::{include} includes/test-access.md
:::
