(auth-faq-target)=
# Auth and lifecycle FAQ

This page gives an overview of internal aspects regarding master authentication and authentication issuance to minions
to address frequent sources of confusion and common setup questions by users.

## Manually configured daemon auth

Masters and minions (opt-in via {vconf}`config_location`) can be configured statically.

(auth-tradeoff-target)=
### Token vs AppRole
Tokens are the basic entity of authentication. They carry metadata regarding validity, renewal and authorization (policies).
Any other authentication method results in the generation of a token. Configuring a token directly gives simple and minute
control over its properties. If the configured token becomes invalid, e.g. because it was not renewed in time, you need to
update the daemon configuration with a new valid one and restart it.

AppRoles are a very flexible method of authentication. They consist of a static RoleID and (optionally, but by default) a
generated SecretID. The primary advantage of having two separate pieces of information is that they can be distributed to
nodes independently of each other. If the token obtained from authenticating via the configured AppRole becomes invalid,
the daemon can re-authenticate using its credentials and obtain a fresh token. In the context of this extension, authenticating
via AppRoles can thus be considered more stable. When the configured SecretID becomes invalid, you still need to update
the daemon configuration with a new valid one and restart it, but missing token renewals is usually a non-issue.

The general recommendation is to use AppRoles for manually configured authentication, which generally means the master.

### Caching

By default, obtained tokens are not persisted or shared between Salt processes.
This is not a major issue when the token can be read from configuration. But if it was obtained via AppRole authentication,
each invocation re-authenticates to the Vault server using the configured SecretID, and if it was pulled from the master,
each invocation issues a new token.

It's thus highly recommended to {vconf}`configure a persistent cache <cache:backend>`, usually the `disk` backend, which
writes tokens (in plaintext) to the daemon's `cachedir`. This reduces token procurement overhead.

### Renewal

Active tokens are renewed any time this extension is invoked. You can configure the {vconf}`minimum validity <auth:token_lifecycle:minimum_ttl>`
that triggers renewals and the {vconf}`renewal increment <auth:token_lifecycle:renew_increment>` that is requested
when renewing a token.

If there is no persistent background activity that invokes this extension regularly, a daemon's token can become invalid.
That is usually not an issue, but if leases such as database credentials are in play, they are revoked at that point.
To avoid missing renewals, it's recommended to configure the {py:mod}`vault_lease beacon <saltext.vault.beacons.vault_lease>`.
When configured, it is invoked regularly and renews the token, until its maximum ttl is reached. It also renews leases.

### Validity

Statically configured tokens or SecretIDs should be valid for many uses over a long time since they need to be
refreshed manually when expired.

Consider setting ``secret_id_num_uses`` (for SecretIDs)/``num_uses`` (for tokens) to ``0``.
``secret_id_ttl``/``token_max_ttl`` should follow a custom assessment, e.g. ``30d``.


## Automatically issued minion auth

By default, minions automatically request and refresh authentication credentials via the master.

(issuance-tradeoff-target)=
### Token vs Approle

The decision whether to issue tokens or AppRoles should be made based on the following questions:

1. **Is a compromised master outside of your threat model or is your Vault namespace/server dedicated solely to Salt?**

   Issuing tokens allows to restrict which policies the master is able to assign to minions via a [Token Role](token-role-target)'s
   ``allowed_policies``/``allowed_policies_glob``. There is no simple equivalent when issuing AppRoles,
   meaning a compromised master can usually assign arbitary policies.

   If you answered both questions with ``no``, consider issuing tokens.

2. **Do you need a large set of dynamically named policies and want to reduce their management overhead, e.g.
   when using minion roles or minion ID-specific secrets?**

   Issuing AppRoles has the advantage that the master can manage minion entities and their metadata, which can be
   referenced in generic [templated policies](metadata-templating-target). This currently does not work when issuing tokens,
   meaning you need to create a separate regular policy on the Vault server for each of the
   {vconf}`assigned policies <policies:assign>`.

   If you answered ``yes``, consider issuing AppRoles.

(pillar-impersonation-target)=
## Pillar impersonation

The {py:mod}`vault pillar <saltext.vault.pillar.vault>`, which is rendered on the master daemon on behalf of the minion,
must respect configured Vault policies when distributing secrets to minions.
In order to verify that a minion has access to a secret, the master issues minion-specific credentials to itself,
authenticates to Vault using these and requests the secret.

This means the **master token does not need access to pillar secret paths**, the **minion tokens do**.

This impersonation also happens when any Vault execution module is invoked via ``salt-ssh`` (i.e. with {doc}`Wrapper modules </ref/wrapper/index>`).

If the master cannot issue valid credentials to minions, this impersonation fails.
