# Configuration Reference

This page provides a description of all supported configuration options.
All values should be placed under the `vault` key in the Salt configuration.

## General configuration
:::{vconf} auth
:::
### `auth`
Contains authentication parameters for the local machine.

:::{vconf} auth:approle_mount
:::
#### approle_mount
The name of the AppRole authentication mount point. Defaults to `approle`.

:::{vconf} auth:approle_name
:::
#### approle_name
The name of the AppRole. Defaults to `salt-master`.

:::{note}
Only relevant when a locally configured {vconf}`role_id`/{vconf}`secret_id` is set to the return
payload of a wrapping request, so only in very specialized use cases.
:::

:::{vconf} auth:method
:::
#### method
Currently only `token` and `approle` auth types are supported.
Defaults to `token`.

:::{hint}
In addition to a plain string, the required authentication credentials can also
be specified as a dictionary that includes `wrap_info`, i.e. the return payload
of a wrapping request.
:::

:::{vconf} auth:role_id
:::
#### role_id
The role ID of the AppRole. Required if {vconf}`auth:method` == `approle`.

:::{vconf} auth:secret_id
:::
#### secret_id
The SecretID of the AppRole. Only required if the configured AppRole requires it.

:::{vconf} auth:token
:::
#### token
Token to authenticate to Vault with. Required if {vconf}`auth:method` == `approle`.

:::{hint}
You can also pull configuration values, e.g. the token, from environment variables
using the `env` SDB module:

```yaml
vault:
  auth:
    method: token
    token: sdb://osenv/VAULT_TOKEN
  server:
    url: https://vault.service.domain:8200

osenv:
  driver: env
```
:::

:::{vconf} auth:token_lifecycle
:::
#### token_lifecycle
Token renewal settings.

:::{note}
This setting can be specified inside a minion's configuration as well
and will override the master's default for the minion.

Token lifecycle settings have significancy for any authentication method,
not just `token`.
:::

:::{vconf} auth:token_lifecycle:minimum_ttl
:::
minimum_ttl
    : Specifies the time (in seconds or as a time string like `24h`) an in-use
      token should be valid for. If the current validity period is less than this
      and the token is renewable, a renewal will be attempted. If it is not renewable
      or a renewal does not extend the ttl beyond the specified minimum, a new token
      will be generated.

      :::{hint}
      Since leases like database credentials are tied to a token, setting this to
      a much higher value than the default can be necessary, depending on your
      specific use case and configuration.
      :::

:::{vconf} auth:token_lifecycle:renew_increment
:::
renew_increment
    : Specifies the amount of time the token's validity should be requested to be
      renewed for when renewing a token. When unset, will extend the token's validity
      by its default ttl. Set this to `false` to disable token renewals.

      :::{note}
      The Vault server is allowed to disregard this request.
      :::

:::{vconf} cache
:::
### `cache`
Configures token/lease and metadata cache (for KV secrets) on all hosts as well as
configuration cache on minions that receive issued credentials.

:::{vconf} cache:backend
:::
#### backend
The cache backend in use. Defaults to `session`, which will store the
Vault configuration in memory only for that specific Salt run.
`disk`/`file`/`localfs` will force using the localfs driver, regardless
of configured minion data cache.
Setting this to anything else will use the default configured cache for
minion data ({conf_master}`cache <cache>`), by default the local filesystem
as well.

:::{vconf} cache:clear_attempt_revocation
:::
#### clear_attempt_revocation
When flushing still valid cached tokens and leases, attempt to have them
revoked after a (short) delay. Defaults to `60`.
Set this to false to disable revocation (not recommended).

:::{vconf} cache:clear_on_unauthorized
:::
#### clear_on_unauthorized
When encountering an `Unauthorized` response with an otherwise valid token,
flush the cache and request new credentials. Defaults to true.

:::{tip}
If your policies are relatively stable, disabling this will prevent
a lot of unnecessary overhead, with the tradeoff that once they change,
you might have to clear the cache manually or wait for the token to expire.
:::

:::{vconf} cache:config
:::
#### config
The time in seconds to cache queried configuration from the master.
Defaults to `3600` (one hour). Set this to `null` to disable
cache expiration. Changed {vconf}`server` configuration on the master will
still be recognized, but changes in {vconf}`auth` and {vconf}`cache` will need
a manual update using [vault.update_config](saltext.vault.modules.vault.update_config)
or cache clearance using [vault.clear_cache](saltext.vault.modules.vault.clear_cache).

:::{note}
Expiring the configuration will also clear cached authentication
credentials and leases.
:::

:::{vconf} cache:expire_events
:::
#### expire_events
Fire an event when the session cache containing leases is cleared
(`vault/cache/<scope>/clear`) or cached leases have expired
(`vault/lease/<cache_key>/expire`).
A reactor can be employed to ensure fresh leases are issued.
Defaults to false.

:::{vconf} cache:kv_metadata
:::
#### kv_metadata
The time in seconds to cache KV metadata used to determine if a path
is using version 1/2 for. Defaults to `connection`, which will clear
the metadata cache once a new configuration is requested from the
master. Setting this to `null` will keep the information
indefinitely until the cache is cleared manually using
[vault.clear_cache](saltext.vault.modules.vault.clear_cache) with `connection=false`.

:::{vconf} cache:secret
:::
#### secret
The time in seconds to cache tokens/SecretIDs for. Defaults to `ttl`,
which caches the secret for as long as it is valid, unless a new configuration
is requested from the master.

:::{vconf} client
:::
### `client`
:::{versionadded} 1.1.0
:::

Configures Vault API client behavior. By default,
the client retries requests with a backoff strategy,
unless the response includes a `Retry-After` header, which is respected.
Connection errors as well as responses with the status codes
`412`, `429`, `500`, `502`, `503`, `504` are retried.

:::{vconf} client:connect_timeout
:::
#### connect_timeout
:::{versionadded} 1.1.0
:::
The number of seconds to wait for a connection to be established.
Defaults to `9.2`.

:::{vconf} client:read_timeout
:::
#### read_timeout
:::{versionadded} 1.1.0
:::
The number of seconds to wait between packets sent by the server.
Defaults to `30`.

:::{vconf} client:max_retries
:::
#### max_retries
:::{versionadded} 1.1.0
:::
The maximum number of retries (not including the initial request) before
raising an exception. Set this to `0` to disable retry behavior.
Defaults to `5`. Maximum: `10`.

:::{vconf} client:backoff_factor
:::
#### backoff_factor
:::{versionadded} 1.1.0
:::
A backoff factor (in seconds) to use between retry attempts when applying
the backoff strategy (based on the Fibonacci sequence).
Defaults to `0.1`. Maximum: `3.0`

:::{hint}
The effective sleep time before the nth retry is given by:

  > {backoff_factor} * {Fibonacci(n+3)}

The default values thus result in the following sleep times (in seconds),
without accounting for {vconf}`backoff_jitter <client:backoff_jitter>`
and only if the response did not include the `Retry-After` header:

  > [initial request] 0.2 [1st] 0.3 [2nd] 0.5 [3rd] 0.8 [4th] 1.3 [5th]

If we did not receive a response (connection/read error), the first retry
is executed immediately, thus the following sleep times are in effect by default:

  > [initial request] 0 [1st] 0.2 [2nd] 0.3 [3rd] 0.5 [4th] 0.8 [5th]

:::

:::{vconf} client:backoff_max
:::
#### backoff_max
:::{versionadded} 1.1.0
:::
A cap for the effective sleep time between retries.
Defaults to `10.0`. Maximum: `60.0`.

:::{vconf} client:backoff_jitter
:::
#### backoff_jitter
:::{versionadded} 1.1.0
:::
A maximum number of seconds to randomize the effective sleep time
between retries by. Defaults to `0.2`. Maximum: `5.0`

:::{vconf} client:retry_post
:::
#### retry_post
:::{versionadded} 1.1.0
:::
Whether to retry requests that are potentially non-idempotent (`POST`, `PATCH`). Defaults to `False`.

:::{note}
HTTP 429 responses are always retried, regardless of HTTP verb.
:::

:::{vconf} client:retry_status
:::
#### retry_status
:::{versionadded} 1.1.0
:::
A list of HTTP status codes which should be retried.
Defaults to `[412, 500, 502, 503, 504]`.

:::{note}
HTTP 429 is always retried, regardless of HTTP verb and whether it is present
in this list. It is recommended to ensure the `Retry-After` header is sent by Vault to optimize the spent resources.
See {vconf}`respect_retry_after <client:respect_retry_after>` for details.
:::

:::{vconf} client:respect_retry_after
:::
#### respect_retry_after
:::{versionadded} 1.1.0
:::
Whether to respect the `Retry-After` header sent by Vault, usually when a
rate limit has been hit. Defaults to `True`.

:::{hint}
This header is not sent by default and must be enabled explicitly
via [enable_rate_limit_response_headers](https://developer.hashicorp.com/vault/api-docs/system/quotas-config#enable_rate_limit_response_headers).
:::

:::{vconf} client:retry_after_max
:::
#### retry_after_max
:::{versionadded} 1.1.0
:::
When {vconf}`respect_retry_after <client:respect_retry_after>` is True, limit
the maximum amount of seconds the client will sleep before retrying. Set this to `null` (YAML/JSON)/`None` (Python)
to disable this behavior. Defaults to `60`.

:::{vconf} server
:::
### `server`
Configures Vault server details.

:::{vconf} server:url
:::
#### url
URL of your Vault installation. Required.

:::{vconf} server:verify
:::
#### verify
Configures certificate verification behavior when issuing requests to the
Vault server. If unset, requests will use the CA certificates bundled with `certifi`.

For details, please see the `requests` documentation on [certificate verification][].

:::{note}
In addition, this value can be set to a PEM-encoded CA certificate to use as the
sole trust anchor for certificate chain verification.
:::

:::{hint}
This value can be set inside the minion configuration as well, from where it
will take precedence.
:::

:::{vconf} server:namespace
:::
#### namespace
Optional [Vault namespace][]. Used with Vault Enterprise.

## Master-only configuration
:::{vconf} issue
:::
### `issue`
Configures authentication data issued by the master to minions.

:::{vconf} issue:type
:::
#### type
The type of authentication to issue to minions. Can be `token` or `approle`.
Defaults to `token`.

To be able to issue AppRoles to minions, the master needs to be able to
create new AppRoles on the configured auth mount.
It is strongly encouraged to create a separate mount dedicated to minions.

:::{vconf} issue:approle
:::
#### approle
Configuration regarding issued AppRoles.

:::{vconf} issue:approle:mount
:::
mount
    : Specifies the name of the auth mount the master manages. Defaults to
      `salt-minions`. This mount should be exclusively dedicated
      to the Salt master.

:::{vconf} issue:approle:params
:::
params
    : Configures the AppRole the master creates for minions. See the
      [Vault AppRole API docs][] for details. If you update these params, you can
      update the minion AppRoles manually using the runner
      [vault.sync_approles](saltext.vault.runners.vault.sync_approles),
      but they will be updated automatically during a request by a minion as well.

:::{vconf} issue:token
:::
#### token
Configuration regarding issued tokens.

:::{vconf} issue:token:role_name
:::
role_name
    : Specifies the [Token Role][] name to use for creating minion tokens.
      If omitted, minion tokens will be created without any role, thus being able
      to inherit any master token policy (including token creation capabilities).

:::{vconf} issue:token:params
:::
params
    : Configures the tokens the master issues to minions.
      See the [Vault Token API docs][] for details. To make full use of multi-use tokens,
      you should configure a {vconf}`cache <cache:backend>` that survives a single session
      (e.g. `disk`).

      :::{important}
      If unset, the master issues single-use tokens to minions, which can be quite expensive.
      :::


:::{vconf} issue:allow_minion_override_params
:::
#### allow_minion_override_params
Whether to allow minions to request to override parameters for issuing credentials.
See {vconf}`issue_params`.

:::{vconf} issue:wrap
:::
#### wrap
The time a minion has to unwrap a wrapped secret issued by the master.
Set this to false to disable wrapping, otherwise a time string like `30s`
can be used. Defaults to `30s`.

:::{vconf} keys
:::
### `keys`
List of keys to use to unseal the Vault server with the
[vault.unseal](saltext.vault.runners.vault.unseal) runner.

:::{vconf} metadata
:::
### `metadata`
Configures metadata for the issued entities/secrets. Values can be
strings or [string templates](#vault-templating).

:::{note}
Values have to be strings, hence templated variables that resolve to lists
will be concatenated to a lexicographically sorted comma-separated list
(Python `list.sort()`).
:::

:::{vconf} metadata:entity
:::
#### entity
Configures the metadata associated with the minion entity inside Vault.
Entities are only created when issuing AppRoles to minions.

:::{vconf} metadata:secret
:::
#### secret
Configures the metadata associated with issued tokens/SecretIDs. They
are logged in plaintext to the Vault audit log.

:::{vconf} policies
:::
### `policies`

:::{vconf} policies:assign
:::
#### assign
List of policies that are assigned to issued minion authentication data,
either token or AppRole. They can be static strings or [string templates](#vault-templating).

Defaults to `[saltstack/minions, saltstack/{minion}]`.

:::{vconf} policies:cache_time
:::
#### cache_time
Number of seconds compiled templated policies are cached on the master.
This is important when using pillar values in templates, since compiling
the pillar is an expensive operation.

:::{note}
Only effective when issuing tokens to minions. Token policies
need to be compiled every time a token is requested, while AppRole-associated
policies are written to Vault configuration the first time authentication data
is requested (they can be refreshed on demand by running the
[vault.sync_approles](saltext.vault.runners.vault.sync_approles) runner).

They will also be refreshed in case other {vconf}`issuance parameters <issue:approle:params>` are changed, either on the master or the minion
(if {vconf}`allow_minion_override_params` is True).
:::

:::{vconf} policies:refresh_pillar
:::
#### refresh_pillar
Whether to refresh the minion pillar when compiling templated policies
that contain pillar variables.
Only effective when issuing tokens to minions (see note on {vconf}`policies:cache_time`).

Possible values:

`null`
    : (default) Only compile the pillar when no cached pillar is found.

`false`
    : Never compile the pillar. This means templated policies that
      contain pillar values are skipped if no cached pillar is found.

`true`
    : Always compile the pillar. This can cause additional strain
      on the master since the compilation is costly.

:::{note}
Hardcoded to True when issuing AppRoles.

Using cached pillar data only (refresh_pillar=False) might cause the policies
to be out of sync. If there is no cached pillar data available for the minion,
pillar templates will fail to render at all.

If you use pillar values for templating policies and do not disable
refreshing pillar data, make sure the relevant values are not sourced
from Vault (ext_pillar, sdb) or from a pillar sls file that uses the vault
execution/sdb module. Although this will often work when cached pillar data is
available, if the master needs to compile the pillar data during policy rendering,
all Vault modules will be broken to prevent an infinite loop.
:::

## Minion-only configuration

:::{note}
In addition to the following minion-only values, {vconf}`auth:token_lifecycle`, {vconf}`server:verify`
and {vconf}`client` can be set on the minion as well, even if it pulls its configuration from a master.
:::

:::{vconf} config_location
:::
### `config_location`
Override the source of the Vault configuration for the minion.
By default, this extension will try to determine if it needs to request
the connection details from the master or from the local config, depending
on the minion running in local or master-connected mode. This option
will force the extension to use the connection details from the master or the
local config, regardless of circumstances. Allowed values: `master`, `local`.

:::{vconf} issue_params
:::
### `issue_params`
Request overrides for token/AppRole issuance. This needs to be allowed
on the master by setting {vconf}`issue:allow_minion_override_params` to true.
See the master configuration {vconf}`issue:token:params` or {vconf}`issue:approle:params`
for reference.


[Vault AppRole API docs]: https://www.vaultproject.io/api-docs/auth/approle#create-update-approle
[Token Role]: https://developer.hashicorp.com/nomad/docs/integrations/vault/acl#vault-token-role-configuration
[Vault Token API docs]: https://developer.hashicorp.com/vault/api-docs/auth/token#create-token
[certificate verification]: https://requests.readthedocs.io/en/latest/user/advanced.html#ssl-cert-verification
[Vault namespace]: https://developer.hashicorp.com/vault/docs/enterprise/namespaces


## All configuration parameters with defaults

```yaml
vault:
  auth:
    approle_mount: approle
    approle_name: salt-master
    method: token
    role_id: <required if auth:method == approle>
    secret_id: null
    token: <required if auth:method == token>
    token_lifecycle:
      minimum_ttl: 10
      renew_increment: null
  cache:
    backend: session
    config: 3600
    kv_metadata: connection
    secret: ttl
  client:
    max_retries: 5
    connect_timeout: 9.2
    read_timeout: 30
    backoff_factor: 0.1
    backoff_max: 10
    backoff_jitter: 0.2
    retry_post: false
    retry_status:
      - 412
      - 500
      - 502
      - 503
      - 504
    respect_retry_after: true
    retry_after_max: 60
  config_location: <variable, depends on running scope>
  issue:
    allow_minion_override_params: false
    type: token
    approle:
      mount: salt-minions
      params:
        bind_secret_id: true
        secret_id_num_uses: 1
        secret_id_ttl: 60
        token_explicit_max_ttl: 60
        token_num_uses: 10
        secret_id_bound_cidrs: null
        token_ttl: null
        token_max_ttl: null
        token_no_default_policy: false
        token_period: null
        token_bound_cidrs: null
    token:
      role_name: null
      params:
        explicit_max_ttl: null
        num_uses: 1
        ttl: null
        period: null
        no_default_policy: false
        renewable: true
    wrap: 30s
  issue_params: {}
  keys: []
  metadata:
    entity:
      minion-id: '{minion}'
    secret:
      saltstack-jid: '{jid}'
      saltstack-minion: '{minion}'
      saltstack-user: '{user}'
  policies:
    assign:
      - saltstack/minions
      - saltstack/{minion}
    cache_time: 60
    refresh_pillar: null
  server:
    url: <required, e. g. https://vault.example.com:8200>
    namespace: null
    verify: null
```
