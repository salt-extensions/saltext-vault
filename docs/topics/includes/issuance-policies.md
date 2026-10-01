### Policies
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
