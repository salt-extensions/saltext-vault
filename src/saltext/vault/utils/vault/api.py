"""
Class wrappers for several Vault API endpoints
"""

import salt.utils.json

import saltext.vault.utils.vault.leases as vleases
from saltext.vault.utils.vault.exceptions import VaultInvocationError
from saltext.vault.utils.vault.exceptions import VaultNotFoundError


class AppRoleApi:
    """
    Wraps the `Vault AppRole API <https://developer.hashicorp.com/vault/api-docs/auth/approle>`_.

    .. note::

        All durations can be specified either as an integer time in seconds
        or a time string like ``1h``.
    """

    def __init__(self, client):
        self.client = client

    def list_approles(self, mount="approle"):
        """
        List all AppRoles present on the specified mount.

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        endpoint = f"auth/{mount}/role"
        return self.client.list(endpoint)["data"]["keys"]

    def read_approle(self, name, mount="approle"):
        """
        Read the properties of an existing AppRole.
        Raises VaultNotFound if the AppRole does not exist on the mount.

        name
            Name of the AppRole to read the properties of.

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        endpoint = f"auth/{mount}/role/{name}"
        return self.client.get(endpoint)["data"]

    def write_approle(
        self,
        name,
        bind_secret_id=None,
        secret_id_bound_cidrs=None,
        secret_id_num_uses=None,
        secret_id_ttl=None,
        local_secret_ids=None,
        token_ttl=None,
        token_max_ttl=None,
        token_policies=None,
        token_bound_cidrs=None,
        token_explicit_max_ttl=None,
        token_no_default_policy=None,
        token_num_uses=None,
        token_period=None,
        token_type=None,
        mount="approle",
    ):
        """
        Create or update an AppRole.

        name
            Name of the AppRole to read the properties of.

        bind_secret_id
            Require a SecretID when authenticating with this AppRole.
            Defaults to true.

        secret_id_bound_cidrs
            List of blocks of IP addresses in CIDR notation that
            can perform the login operation.

        secret_id_num_uses
            Number of times a generated SecretID can be used to authenticate
            with this AppRole by default. ``0`` means unlimited.

        secret_id_ttl
            Duration after which a generated SecretID for this AppRole expires by default.

        local_secret_ids
            If set, the secret IDs generated using this role will be cluster-local.
            This can only be set during role creation and once set, it can't be reset later.
            Defaults to false.

        token_ttl
            The incremental lifetime for tokens generated by authenticating with this AppRole.
            This value will be referenced at renewal time.

        token_max_ttl
            The maximum lifetime for tokens generated by authenticating with this AppRole.
            This value will be referenced at renewal time.

        token_policies
            List of token policies to encode onto generated tokens.
            This list may be supplemented by user/group/other values.

        token_bound_cidrs
            List of blocks of IP addresses in CIDR notation that
            can perform the login operation. The resulting token will be tied
            to these blocks as well.

        token_explicit_max_ttl
            Place a hard cap on the maximum lifetime of tokens issued by authenticating
            with this AppRole.

        token_no_default_policy
            Do not add the ``default`` policy to tokens generated by authenticating
            with this AppRole. Defaults to false.

        token_num_uses
            Number of times a token generated by authenticating with this AppRole
            may be used to issue requests. ``0`` means unlimited.

        token_period
            The maximum allowed period value when a periodic token is requested from this role.

        token_type
            The type of token that should be generated (``service``, ``batch`` or ``default``).

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        endpoint = f"auth/{mount}/role/{name}"
        payload = _filter_none(
            {
                "bind_secret_id": bind_secret_id,
                "secret_id_bound_cidrs": secret_id_bound_cidrs,
                "secret_id_num_uses": secret_id_num_uses,
                "secret_id_ttl": secret_id_ttl,
                "local_secret_ids": local_secret_ids,
                "token_ttl": token_ttl,
                "token_max_ttl": token_max_ttl,
                "token_policies": token_policies,
                "token_bound_cidrs": token_bound_cidrs,
                "token_explicit_max_ttl": token_explicit_max_ttl,
                "token_no_default_policy": token_no_default_policy,
                "token_num_uses": token_num_uses,
                "token_period": token_period,
                "token_type": token_type,
            }
        )
        return self.client.post(endpoint, payload=payload)

    def delete_approle(self, name, mount="approle"):
        """
        Delete an existing AppRole.
        Raises VaultNotFound if the AppRole does not exist on the mount.

        name
            Name of the AppRole to delete.

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        endpoint = f"auth/{mount}/role/{name}"
        return self.client.delete(endpoint)

    def read_role_id(self, name, wrap=False, mount="approle"):
        """
        Read the associated RoleID of an existing AppRole.
        Raises VaultNotFound if the AppRole does not exist on the mount.

        name
            Name of the AppRole.

        wrap
            If set, specifies the duration the resulting wrapping token should
            be valid for. This token can be used once to access the
            query result. Defaults to false (=> returns the RoleID as a string).

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        endpoint = f"auth/{mount}/role/{name}/role-id"
        role_id = self.client.get(endpoint, wrap=wrap)
        if wrap:
            return role_id
        return role_id["data"]["role_id"]

    def generate_secret_id(
        self,
        name,
        metadata=None,
        cidr_list=None,
        token_bound_cidrs=None,
        num_uses=None,
        ttl=None,
        wrap=False,
        mount="approle",
    ):
        """
        Generate a SecretID for an existing AppRole.
        Raises VaultNotFound if the AppRole does not exist on the mount.

        name
            Name of the AppRole.

        metadata
            Mapping of string keys to string values that specifies metadata
            to be set on the token generated by authenticating with this
            specific SecretID. It will be logged to audit logs in plaintext.

        cidr_list
            List of blocks of IP addresses in CIDR notation that
            can perform the login operation with this specific SecretID.
            If ``secret_id_bound_cidrs`` is set on the AppRole, this list
            must be a subset of the ones specified there.

        token_bound_cidrs
            List of blocks of IP addresses in CIDR notation that
            can perform the login operation. The resulting token will be tied
            to these blocks as well.
            If ``token_bound_cidrs`` is set on the AppRole, this list
            must be a subset of the ones specified there.

        num_uses
            Number of times this specific SecretID can be used to authenticate
            by default. ``0`` means unlimited.
            Must be equal to or lower than ``secret_id_num_uses`` set on the AppRole.

        ttl
            Duration after which this SecretID should expire.
            Must be equal to or lower than ``secret_id_ttl`` set on the AppRole.

        wrap
            If set, specifies the duration the resulting wrapping token should
            be valid for. This token can be used once to access the
            query result. Defaults to false (=> returns the SecretID as a string).

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        endpoint = f"auth/{mount}/role/{name}/secret-id"
        if metadata is not None:
            metadata = salt.utils.json.dumps(metadata)
        payload = _filter_none(
            {
                "metadata": metadata,
                "cidr_list": cidr_list,
                "token_bound_cidrs": token_bound_cidrs,
                "num_uses": num_uses,
                "ttl": ttl,
            }
        )
        response = self.client.post(endpoint, payload=payload, wrap=wrap)
        if wrap:
            return response
        # Sadly, secret_id_num_uses is not part of the information returned, but
        # it can be read with `read_secret_id` using the accessor.
        return vleases.VaultSecretId(**response["data"])

    def read_secret_id(self, name, secret_id=None, accessor=None, mount="approle"):
        """
        Read properties of an existing SecretID.
        Raises VaultNotFound if the AppRole and/or SecretID does not exist on the mount.

        name
            Name of the AppRole the SecretID belongs to.

        secret_id
            The SecretID to look up. Specify either this or ``accessor``.

        accessor
            The accessor of the SecretID to look up. Specify either this
            or ``secret_id``.

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        if not secret_id and not accessor:
            raise VaultInvocationError("Need either secret_id or accessor to read secret ID.")
        if secret_id:
            endpoint = f"auth/{mount}/role/{name}/secret-id/lookup"
            payload = {"secret_id": str(secret_id)}
        else:
            endpoint = f"auth/{mount}/role/{name}/secret-id-accessor/lookup"
            payload = {"secret_id_accessor": accessor}
        try:
            return self.client.post(endpoint, payload=payload)["data"]
        except TypeError as err:
            # lookup does not raise exceptions, only returns True
            raise VaultNotFoundError() from err

    def destroy_secret_id(self, name, secret_id=None, accessor=None, mount="approle"):
        """
        Destroy an existing SecretID.
        Raises VaultNotFound if the AppRole and/or SecretID does not exist on the mount.

        name
            Name of the AppRole the SecretID belongs to.

        secret_id
            The SecretID to destroy. Specify either this or ``accessor``.

        accessor
            The accessor of the SecretID to destroy. Specify either this
            or ``secret_id``.

        mount
            Name of the AppRole auth backend mount.
            Defaults to ``approle``.
        """
        if not secret_id and not accessor:
            raise VaultInvocationError("Need either secret_id or accessor to destroy secret ID.")
        if secret_id:
            endpoint = f"auth/{mount}/role/{name}/secret-id/destroy"
            payload = {"secret_id": str(secret_id)}
        else:
            endpoint = f"auth/{mount}/role/{name}/secret-id-accessor/destroy"
            payload = {"secret_id_accessor": accessor}
        return self.client.post(endpoint, payload=payload)


class IdentityApi:
    """
    Wraps the Vault `Identity secret engine API <https://developer.hashicorp.com/vault/api-docs/secret/identity>`_.
    """

    def __init__(self, client):
        self.client = client

    def list_entities(self):
        """
        Return a list of the names of all entities known by Vault.
        """
        endpoint = "identity/entity/name"
        return self.client.list(endpoint)["data"]["keys"]

    def read_entity(self, name):
        """
        Read the properties of an entity by its name.
        Raises VaultNotFound if the entity does not exist.

        name
            Name of the entity to read the properties of.
        """
        endpoint = f"identity/entity/name/{name}"
        return self.client.get(endpoint)["data"]

    def read_entity_by_alias(self, alias, mount):
        """
        Lookup the properties of an entity by its alias name and mount.
        Raises VaultNotFound if the entity does not exist.

        alias
            The name of the entity's alias on the specified
            ``mount``. For AppRole backends, this is the RoleID.

        mount
            The name of the mount the given alias is associated with.
            For example, if the backend is mounted at ``auth/approle``,
            this should be ``approle``.
        """
        endpoint = "identity/lookup/entity"
        payload = {
            "alias_name": alias,
            "alias_mount_accessor": self._lookup_mount_accessor(mount),
        }
        entity = self.client.post(endpoint, payload=payload)
        if isinstance(entity, dict):
            return entity["data"]
        raise VaultNotFoundError()

    def write_entity(self, name, metadata=None, policies=None, disabled=None):
        """
        Create or update an entity by name.

        name
            The name of the entity.

        metadata
            Mapping of string keys to string values that specifies metadata
            to be set on the entity. This can be used to template policies.

        policies
            List of policies to be tied to the entity. These policies will
            be active in addition to auth method-specific policies.

        disabled
            Whether this entity should be disabled. Disabled entities' associated
            tokens cannot be used, but are not revoked. Defaults to false.
        """
        endpoint = f"identity/entity/name/{name}"
        payload = _filter_none(
            {
                "metadata": metadata,
                "policies": policies,
                "disabled": disabled,
            }
        )
        return self.client.post(endpoint, payload=payload)

    def delete_entity(self, name):
        """
        Delete an entity by name.
        Raises VaultNotFound if the entity does not exist.

        name
            The name of the entity.
        """
        endpoint = f"identity/entity/name/{name}"
        return self.client.delete(endpoint)

    def write_entity_alias(self, name, alias_name, mount, custom_metadata=None):
        """
        Create/update the association between an entity and a specific
        alias of an auth mount.

        name
            Name of the entity to associate with the alias.

        alias_name
            Name of the alias to associate with the entity.
            The specifics are dependent on the type of the auth backend.
            For AppRoles, this is the RoleID.

        mount
            The name of the mount the given alias is associated with.
            For example, if the backend is mounted at ``auth/approle``,
            this should be ``approle``.

        custom_metadata
            A map of arbitrary string to string valued user-provided
            metadata meant to describe the alias.
        """
        entity = self.read_entity(name)
        mount_accessor = self._lookup_mount_accessor(mount)
        payload = {
            "canonical_id": entity["id"],
            "mount_accessor": mount_accessor,
            "name": alias_name,
        }
        if custom_metadata is not None:
            payload["custom_metadata"] = custom_metadata

        for alias in entity["aliases"]:
            # Ensure an existing alias is updated
            if alias["mount_accessor"] == mount_accessor:
                payload["id"] = alias["id"]
                break
        return self.client.post("identity/entity-alias", payload=payload)

    def _lookup_mount_accessor(self, mount):
        endpoint = f"sys/auth/{mount}"
        return self.client.get(endpoint)["data"]["accessor"]


def _filter_none(data):
    return {k: v for k, v in data.items() if v is not None}
