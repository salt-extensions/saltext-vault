# Installation

Generally, extensions need to be installed into the same Python environment Salt uses.

:::{tab} State
```yaml
Install Salt Vault extension:
  pip.installed:
    - name: saltext-vault
```
:::

:::{tab} Onedir installation
```bash
salt-pip install saltext-vault
```
:::

:::{tab} Regular installation
```bash
pip install saltext-vault
```
:::

:::{hint}
Saltexts are not distributed automatically via the fileserver like custom modules, they need to be installed
on each node you want them to be available on.
:::
