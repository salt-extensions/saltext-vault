## Secrets setup

Decide how you want to map minions to authorizations. A common pattern is to create policies
based on minion IDs and minion roles, as shown in the complete example above.
This example setup is continued here.

### Mount the KV backend
Mount the Key/Value v2 backend to a path, e.g. `salt`:

```bash
vault secrets enable -path=salt -version=2 kv
```

### Create secrets
Write a secret that is accessible to all minions:

```bash
vault kv put -mount=salt general/accessible_for_all_minions all_foo=bar
```

Write a secret that is accessible to any minion that has the `db` role:

```bash
vault kv put -mount=salt roles/db db_foo=baz
```

Write a secret that is accessible to a specific minion named `elliott`:

```bash
vault kv put -mount=salt minions/elliott minion_foo=quux
```

### Create policies
Create the policies that map necessary authorizations.

:::{warning}
If a secret path is used as a minion pillar, the minion **must not have
write access**, otherwise a core security assumption in Salt is violated.
:::

:::{important}
Even if you only intend to use the secrets for minion pillars, you need
to create minion policies. The master uses these policies to decide
whether a minion should receive a specific pillar. The master token should not
have access to secret paths itself. For details, see [Pillar impersonation](pillar-impersonation-target).
:::
