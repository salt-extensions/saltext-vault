### Test access

Now you can test that the minion is able to read all secrets:

```console
[root@master ~]# salt elliott vault_secret.read salt/general/accessible_for_all_minions
elliott:
    ----------
    all_foo: bar
[root@master ~]# salt elliott vault_secret.read salt/roles/db
elliott:
    ----------
    db_foo: baz
[root@master ~]# salt elliott vault_secret.read salt/minions/elliott
elliott:
    ----------
    minion_foo: quux
```

Also verify that minions without authorization to access these secrets can't.

If reading fails, clear the minion's cached Vault data, which forces new
credentials to be requested, and try again:
```bash
salt elliott vault.clear_cache
```
