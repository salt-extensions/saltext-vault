``saltext-vault``: Integrate Salt with Vault
============================================

This Salt Extension provides modules for interacting with Vault by HashiCorp,
a secrets and encryption management system. You only need to setup your Salt master,
which will then orchestrate minion authentications for you.

Currently, you can
------------------
* manage and dynamically retrieve secrets from the KV v1 and v2 secret backends
* manage Vault policies
* manage the Database secret engine
* manage and issue certificates via the PKI secret engine
* request, renew and monitor short-lived database credentials
* write your own modules on top of the provided utilities

There's much more coming though.

References
----------
What's Salt?
    A remote execution, configuration management and automation system written in Python.
    See the `Salt guide <https://docs.saltproject.io/salt/user-guide/en/latest/topics/overview.html>`_ for details.

What's Vault?
    A self-hostable service that allows you to securely store and retrieve secrets, manage
    dynamic database credentials, a centralized Public Key Infrastructure and more.
    See the `Vault homepage <https://www.hashicorp.com/products/vault>`_ for details.

Want to contribute?
    Come over to our `GitHub repo <https://github.com/salt-extensions/saltext-vault>`_.

Found a bug or missing a feature?
    File a report on our `issue tracker <https://github.com/salt-extensions/saltext-vault/issues>`_.


.. toctree::
  :maxdepth: 2
  :caption: Guides
  :hidden:

  topics/installation
  topics/migration_from_core
  topics/basic_configuration
  topics/templating

.. toctree::
  :maxdepth: 2
  :caption: Provided Modules
  :hidden:

  ref/beacons/index
  ref/modules/index
  ref/pillar/index
  ref/runners/index
  ref/sdb/index
  ref/states/index
  ref/utils/index

.. toctree::
  :maxdepth: 2
  :caption: Reference
  :hidden:

  ref/configuration
  changelog


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
