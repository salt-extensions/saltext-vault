(vault-setup)=
# Quickstart
For authenticating with a Vault server, each node needs credentials.
Currently supported authentication methods are [AppRoles][] and [tokens][].

To ease the management overhead, this extension allows the Salt master to
distribute configuration and credentials to minions on demand.

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
* Distributing AppRoles allows the Salt Master to create roles with arbitrary
  policies. A compromised Salt Master can thus escalate its privileges within the
  Vault namespace. In the present, this [cannot be worked around with parameter constraints](https://github.com/hashicorp/vault/issues/8789#issuecomment-1321983227)
  in a sensible way. This may not be a problem if the Salt Master manages the Vault
  server already or if it is dedicated to Salt.

## Choosing a setup

### Orchestration vs local configuration
By default, minions pull their configuration and credentials from the Salt
master, meaning you only need to set up the master for credential orchestration.
This is the recommended approach and the one this guide focuses on.

Alternatively, each minion can be configured with explicit credentials locally
({vconf}`config_location`), as described in [Local configuration](quickstart_local.md).
The Salt master itself always requires locally configured credentials.

### Issued credential type
When orchestrating credentials, the Salt master can issue either tokens or
AppRoles to minions.

It's generally recommended to issue AppRoles because this allows for advanced behavior,
although tokens can be preferable when the Vault namespace is shared with other consumers.
For simplicity, this extension currently defaults to token issuance.

For background information, see the [auth FAQ](auth-faq-target),
specifically the sections on [static auth methods](auth-tradeoff-target) and
[credential issuance](issuance-tradeoff-target).

### Guides
Continue with the guide for your chosen setup:

* [Token issuance](quickstart_token.md) – orchestration with issued tokens, the current default
* [AppRole issuance](quickstart_approle.md) – orchestration with issued AppRoles, generally recommended
* [Local configuration](quickstart_local.md) – explicit per-node credentials, also covers the master's own setup

:::{toctree}
:hidden:
:maxdepth: 1

quickstart_token
quickstart_approle
quickstart_local
:::
