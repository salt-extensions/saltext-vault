(vault-templating)=
# Templating

Several Vault extension configuration values allow templating.

:::{admonition} Templating is allowed in...
:class: dropdown

* minion policies
* minion entity metadata
* minion token/AppRole metadata
* pillar paths
:::

## Available variables
Generally available template variables are:

`{minion}`
    : The minion's ID.

`{pillar[<var>]}`
    : The minion's pillar value with the key `<var>`.

      :::{important}
      Pillar values sourced from Vault should never be referenced here:

      * In the general case, they are undefined to prevent circular references.
        If you use the Vault integration during rendering of some your regular pillar
        `sls` files, all values originating from these are undefined, even the ones that do not
        depend on Vault. It is thus highly encouraged to avoid calling the Vault modules
        during pillar rendering if you rely on pillar templating in this extension.
        You can use the dedicated Vault pillar module or reference secrets during
        **state** rendering instead, possibly in conjunction with map files
        to avoid hardcoding Vault sources in the states themselves.
      * In some cases, a cached pillar is used for performance
        reasons, which can contain Vault-sourced values. This only happens during
        **token** (not AppRole) policy rendering and can be disabled by setting
        {vconf}`policies:refresh_pillar <policies:refresh_pillar>` to `true`.

      Pillar values originating from previously rendered pillars can be used to template
      [Vault Pillar](saltext.vault.pillar.vault) paths. Using pillar values to template
      Vault pillar paths requires them to be defined before the Vault ext_pillar is called.
      Especially consider the significancy of the
      {conf_master}`ext_pillar_first <ext_pillar_first>` master config setting.
      :::

`{grains[<var>]}`
    : The minion's grain value with the key `<var>`.

      :::{important}
      See {external+salt:ref}`Is Targeting using Grain Data Secure?
      <faq-grain-security>` for important security information. In short,
      everything except `grains[id]` is minion-controlled and should thus be avoided.
      :::

### Metadata
Metadata configuration values additionally provide:

`{jid}`
    : Salt Job ID that issued the secret.

`{user}`
    : The user the Salt daemon issuing the secret was running as.

## Rendering
In general, the templating works like regular Python f-strings.

### Complex data
Lists and dictionary keys are special-cased in the same way: They are expanded
and result in separate items.

For example, given a pillar of:
```yaml
roles:
  - mail
  - web

roles_map:
  mail:
    some: value
  web: {}
```

A pattern of `salt_role_{pillar[roles]}` (or `salt_role_{pillar[roles_map]}`)
is expanded into:

```yaml
- salt_role_mail
- salt_role_web
```

The way in which this expanded result is handled depends on the scope of the template.

#### Policies/pillar paths
Policies and pillar paths treat the values separately, as intended.

(metadata-templating-target)=
#### Entity/authentication metadata
Entity and authentication metadata is written to Vault, which
[only supports strings](https://github.com/hashicorp/vault/issues/12039).
Consequently, it's impossible to apply [templated ACL policies](https://developer.hashicorp.com/vault/tutorials/policies/policy-templating) for composite values like lists
(typically minion roles) the same way as for simple ones (e.g. minion ID).
A general solution to this involves templating {vconf}`policies:assign` and creating regular policies instead.

:::{versionadded} 1.3.0
:::
This extension supports an inelegant workaround though,
which allows to rely on templated ACL policies even when composite values are in play.

Assuming the following master configuration:

```yaml
vault:
  metadata:
    entity:
      roles: '{pillar[roles]}'
```

A minion's metadata is rendered as follows:

* The configured metadata key (`roles`) contains all values concatenated into a
  lexicographically sorted comma-separated list.
* Furthermore, each value in this list implicitly receives its own metadata key, whose name
  is derived by concatenating the configured key, a double underscore and the list item's index.

Thus, a minion with `pillar[roles]` == `[web, db]` effectively receives the following metadata:

```yaml
roles: db,web
roles__0: db
roles__1: web
```

To make use of this in a templated ACL policy, repeat each definition for as many times
as the number of items you want to support for the composite template variable,
only changing the metadata key index:

```{code-block} vaultpolicy
:caption: This policy respects at most 3 different roles per minion

# Resolves to salt/data/roles/db
path "salt/data/roles/{{identity.entity.metadata.roles__0}}" {
    capabilities = ["read"]
}
# Resolves to salt/data/roles/web
path "salt/data/roles/{{identity.entity.metadata.roles__1}}" {
    capabilities = ["read"]
}
# Ignored in this example
path "salt/data/roles/{{identity.entity.metadata.roles__2}}" {
    capabilities = ["read"]
}
```

:::{note}
Since this expansion of a single user-defined key into an arbitrary
number of generated ones can theoretically lead to conflicts, it is skipped entirely
if any user-defined key begins with the designated prefix
(`roles__` in the above example).
:::
