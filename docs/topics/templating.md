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
      Make sure to only reference pillars that are not sourced from Vault since
      the latter ones might be unavailable during rendering. If you use
      the Vault integration in one of your pillar `sls` files, all values from
      that file will be absent during rendering, even the ones that do not
      depend on Vault.

      Pillar values from previously rendered pillars can be used to template
      [Vault Pillar](saltext.vault.pillar.vault) paths.

      Using pillar values to template Vault pillar paths requires them to be defined
      before the Vault ext_pillar is called. Especially consider the significancy
      of the {conf_master}`ext_pillar_first <ext_pillar_first>` master config setting.
      :::

`{grains[<var>]}`
    : The minion's grain value with the key `<var>`.

      :::{important}
      See {external+salt:ref}`Is Targeting using Grain Data Secure?
      <faq-grain-security>` for important security information. In short,
      everything except `grains[id]` is minion-controlled.
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
will be expanded to:

```yaml
- salt_role_mail
- salt_role_web
```

How this is used depends on the scope.
* Policies and pillar paths will use the values separately, as intended.
* Entity and authentication metadata is written to Vault, which does not
  support complex values. The expanded values are thus concatenated into
  a sorted comma-separated list.
